namespace MaintenX.Api.Infrastructure.Persistence;

using System.Reflection;
using System.Security;
using MaintenX.Api.Application.Tenancy.Context;
using MaintenX.Api.Domain.Auth;
using MaintenX.Api.Domain.Tenants;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging;

/// <summary>
/// Entity Framework Core DbContext for MaintenX.
/// Configured for PostgreSQL 16 with domain entity configuration discovery,
/// automatic UTC audit timestamps, optimistic concurrency token management,
/// and automated multi-tenant query filtering and write isolation enforcement.
/// </summary>
public class MaintenXDbContext : DbContext
{
    private readonly ITenantContextAccessor? _tenantContextAccessor;
    private readonly ILogger<MaintenXDbContext>? _logger;
    private bool _isTenantFilterDisabled;

    /// <summary>
    /// Default database schema for foundational platform tables.
    /// </summary>
    public const string DefaultSchema = "platform";

    /// <summary>
    /// Tenants catalog database set.
    /// </summary>
    public DbSet<Tenant> Tenants => Set<Tenant>();

    /// <summary>
    /// Tenant memberships database set.
    /// </summary>
    public DbSet<TenantMembership> TenantMemberships => Set<TenantMembership>();

    /// <summary>
    /// Authentication users identity database set.
    /// </summary>
    public DbSet<User> Users => Set<User>();

    /// <summary>
    /// User sessions database set.
    /// </summary>
    public DbSet<UserSession> UserSessions => Set<UserSession>();

    /// <summary>
    /// Refresh tokens database set.
    /// </summary>
    public DbSet<RefreshToken> RefreshTokens => Set<RefreshToken>();

    /// <summary>
    /// Security audit events database set.
    /// </summary>
    public DbSet<SecurityAuditEvent> SecurityAuditEvents => Set<SecurityAuditEvent>();

    /// <summary>
    /// Currently resolved tenant identifier from the request scope, or null if uncontexted.
    /// </summary>
    public Guid? CurrentTenantId => _tenantContextAccessor?.Current?.TenantId;

    /// <summary>
    /// Indicates whether multi-tenant query filtering and write boundaries are temporarily bypassed
    /// for privileged administrative or infrastructure operations.
    /// </summary>
    public bool IsTenantFilterDisabled => _isTenantFilterDisabled;

    public MaintenXDbContext(
        DbContextOptions<MaintenXDbContext> options,
        ITenantContextAccessor? tenantContextAccessor = null,
        ILogger<MaintenXDbContext>? logger = null)
        : base(options)
    {
        _tenantContextAccessor = tenantContextAccessor;
        _logger = logger;
    }

    /// <summary>
    /// Explicitly activates a privileged scope bypassing tenant query filtering and write ownership checks.
    /// An audit warning is logged when the scope is activated and deactivated.
    /// Disposing the returned object immediately restores standard tenant boundary enforcement.
    /// </summary>
    public IDisposable CreatePrivilegedTenantBypassScope(string reason)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(reason);
        return new TenantBypassScope(this, reason);
    }

    protected override void OnModelCreating(ModelBuilder modelBuilder)
    {
        base.OnModelCreating(modelBuilder);

        // Configure default schema
        modelBuilder.HasDefaultSchema(DefaultSchema);

        // Automatically discover and apply all IEntityTypeConfiguration implementations in this assembly
        modelBuilder.ApplyConfigurationsFromAssembly(typeof(MaintenXDbContext).Assembly);

        // Configure global query filters for all tenant-scoped entities
        ApplyTenantFilters(modelBuilder);
    }

    private void ApplyTenantFilters(ModelBuilder modelBuilder)
    {
        foreach (var entityType in modelBuilder.Model.GetEntityTypes())
        {
            if (entityType.BaseType == null && typeof(ITenantEntity).IsAssignableFrom(entityType.ClrType))
            {
                var method = typeof(MaintenXDbContext)
                    .GetMethod(nameof(ConfigureTenantFilter), BindingFlags.NonPublic | BindingFlags.Instance)!
                    .MakeGenericMethod(entityType.ClrType);

                method.Invoke(this, [modelBuilder]);
            }
        }
    }

    private void ConfigureTenantFilter<TEntity>(ModelBuilder modelBuilder)
        where TEntity : class, ITenantEntity
    {
        modelBuilder.Entity<TEntity>().HasQueryFilter(e =>
            IsTenantFilterDisabled || (CurrentTenantId.HasValue && (Guid?)e.TenantId == CurrentTenantId));
    }

    public override Task<int> SaveChangesAsync(CancellationToken cancellationToken = default)
    {
        UpdateAuditAndConcurrencyTokens();
        EnforceTenantOwnershipOnWrite();
        return base.SaveChangesAsync(cancellationToken);
    }

    public override int SaveChanges()
    {
        UpdateAuditAndConcurrencyTokens();
        EnforceTenantOwnershipOnWrite();
        return base.SaveChanges();
    }

    private void EnforceTenantOwnershipOnWrite()
    {
        var tenantEntries = ChangeTracker.Entries<ITenantEntity>()
            .Where(e => e.State is EntityState.Added or EntityState.Modified or EntityState.Deleted)
            .ToList();

        if (tenantEntries.Count == 0)
        {
            return;
        }

        if (_isTenantFilterDisabled)
        {
            _logger?.LogWarning(
                "Privileged write bypass in effect: {EntryCount} tenant-scoped entities written outside tenant boundary enforcement.",
                tenantEntries.Count);
            return;
        }

        if (!CurrentTenantId.HasValue || CurrentTenantId.Value == Guid.Empty)
        {
            throw new SecurityException(
                "Tenant isolation violation: Cannot perform write operation on tenant-scoped entity without an active, verified tenant context.");
        }

        var activeTenantId = CurrentTenantId.Value;

        foreach (var entry in tenantEntries)
        {
            var entity = entry.Entity;

            switch (entry.State)
            {
                case EntityState.Added:
                    if (entity.TenantId == Guid.Empty)
                    {
                        throw new SecurityException(
                            $"Tenant isolation violation: Entity of type '{entry.Metadata.ClrType.Name}' cannot be added with an empty TenantId.");
                    }

                    if (entity.TenantId != activeTenantId)
                    {
                        throw new SecurityException(
                            $"Tenant isolation violation: Attempted cross-tenant write. Active tenant is '{activeTenantId}', but entity '{entry.Metadata.ClrType.Name}' belongs to tenant '{entity.TenantId}'.");
                    }
                    break;

                case EntityState.Modified:
                    var tenantIdProperty = entry.Property(nameof(ITenantEntity.TenantId));
                    if (tenantIdProperty.IsModified)
                    {
                        throw new SecurityException(
                            $"Tenant isolation violation: TenantId is strictly immutable. Cannot mutate TenantId on entity '{entry.Metadata.ClrType.Name}'.");
                    }

                    var originalTenantId = (Guid)tenantIdProperty.OriginalValue!;
                    if (originalTenantId != activeTenantId || entity.TenantId != activeTenantId)
                    {
                        throw new SecurityException(
                            $"Tenant isolation violation: Attempted cross-tenant modification. Active tenant is '{activeTenantId}', but entity '{entry.Metadata.ClrType.Name}' belongs to tenant '{entity.TenantId}'.");
                    }
                    break;

                case EntityState.Deleted:
                    if (entity.TenantId != activeTenantId)
                    {
                        throw new SecurityException(
                            $"Tenant isolation violation: Attempted cross-tenant deletion. Active tenant is '{activeTenantId}', but entity '{entry.Metadata.ClrType.Name}' belongs to tenant '{entity.TenantId}'.");
                    }
                    break;
            }
        }
    }

    private void UpdateAuditAndConcurrencyTokens()
    {
        var now = DateTime.UtcNow;

        foreach (var entry in ChangeTracker.Entries<Tenant>())
        {
            if (entry.State == EntityState.Added)
            {
                if (entry.Entity.CreatedAtUtc == default)
                {
                    entry.Entity.CreatedAtUtc = now;
                }

                if (entry.Entity.UpdatedAtUtc == default)
                {
                    entry.Entity.UpdatedAtUtc = now;
                }

                if (entry.Entity.Version == 0)
                {
                    entry.Entity.Version = 1;
                }
            }
            else if (entry.State == EntityState.Modified)
            {
                entry.Entity.UpdatedAtUtc = now;
                // Increment version token for optimistic concurrency tracking
                entry.Entity.Version += 1;
            }
        }
    }

    private sealed class TenantBypassScope : IDisposable
    {
        private readonly MaintenXDbContext _context;
        private readonly string _reason;
        private readonly bool _previousState;
        private bool _disposed;

        public TenantBypassScope(MaintenXDbContext context, string reason)
        {
            _context = context;
            _reason = reason;
            _previousState = context._isTenantFilterDisabled;
            context._isTenantFilterDisabled = true;
            _context._logger?.LogWarning("Privileged tenant bypass scope ACTIVATED. Reason: {BypassReason}", _reason);
        }

        public void Dispose()
        {
            if (!_disposed)
            {
                _context._isTenantFilterDisabled = _previousState;
                _context._logger?.LogWarning("Privileged tenant bypass scope DEACTIVATED. Reason: {BypassReason}", _reason);
                _disposed = true;
            }
        }
    }
}

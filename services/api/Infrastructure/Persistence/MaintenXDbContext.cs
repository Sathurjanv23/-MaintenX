namespace MaintenX.Api.Infrastructure.Persistence;

using MaintenX.Api.Domain.Auth;
using MaintenX.Api.Domain.Tenants;
using Microsoft.EntityFrameworkCore;

/// <summary>
/// Entity Framework Core DbContext for MaintenX.
/// Configured for PostgreSQL 16 with domain entity configuration discovery,
/// automatic UTC audit timestamps, and optimistic concurrency token management.
/// </summary>
public class MaintenXDbContext : DbContext
{
    /// <summary>
    /// Default database schema for foundational platform tables.
    /// </summary>
    public const string DefaultSchema = "platform";

    /// <summary>
    /// Tenants catalog database set.
    /// </summary>
    public DbSet<Tenant> Tenants => Set<Tenant>();

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

    public MaintenXDbContext(DbContextOptions<MaintenXDbContext> options)
        : base(options)
    {
    }

    protected override void OnModelCreating(ModelBuilder modelBuilder)
    {
        base.OnModelCreating(modelBuilder);

        // Configure default schema
        modelBuilder.HasDefaultSchema(DefaultSchema);

        // Automatically discover and apply all IEntityTypeConfiguration implementations in this assembly
        modelBuilder.ApplyConfigurationsFromAssembly(typeof(MaintenXDbContext).Assembly);
    }

    public override Task<int> SaveChangesAsync(CancellationToken cancellationToken = default)
    {
        UpdateAuditAndConcurrencyTokens();
        return base.SaveChangesAsync(cancellationToken);
    }

    public override int SaveChanges()
    {
        UpdateAuditAndConcurrencyTokens();
        return base.SaveChanges();
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
}

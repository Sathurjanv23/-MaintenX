namespace MaintenX.Api.Application.Tenancy.Services;

using System.Data;
using MaintenX.Api.Application.Tenancy.Context;
using MaintenX.Api.Application.Tenancy.Contracts;
using MaintenX.Api.Application.Tenancy.Models;
using MaintenX.Api.Application.Tenancy.Validation;
using MaintenX.Api.Domain.Auth;
using MaintenX.Api.Domain.Tenants;
using MaintenX.Api.Infrastructure.Persistence;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging;
using Npgsql;

/// <summary>
/// Application service coordinating tenant creation, onboarding, lifecycle, and configuration.
/// Guarantees atomic transaction durability, slug uniqueness, and initial owner membership.
/// Enforces member-scoped authorization, platform-admin lifecycle boundaries, and optimistic concurrency.
/// </summary>
public sealed class TenantService : ITenantService
{
    private readonly MaintenXDbContext _dbContext;
    private readonly TimeProvider _timeProvider;
    private readonly ILogger<TenantService> _logger;
    private readonly ITenantContextAccessor? _tenantContextAccessor;

    public TenantService(
        MaintenXDbContext dbContext,
        TimeProvider timeProvider,
        ILogger<TenantService> logger,
        ITenantContextAccessor? tenantContextAccessor = null)
    {
        _dbContext = dbContext ?? throw new ArgumentNullException(nameof(dbContext));
        _timeProvider = timeProvider ?? throw new ArgumentNullException(nameof(timeProvider));
        _logger = logger ?? throw new ArgumentNullException(nameof(logger));
        _tenantContextAccessor = tenantContextAccessor;
    }

    /// <inheritdoc />
    public async Task<CreateTenantResult> CreateTenantAsync(
        Guid creatorUserId,
        CreateTenantRequest request,
        CancellationToken cancellationToken = default)
    {
        // 1. Validate Input Invariants
        if (request is null)
        {
            return CreateTenantResult.ValidationFailed("Request payload cannot be null.");
        }

        try
        {
            TenantValidation.ValidateUserId(creatorUserId);
        }
        catch (ArgumentException ex)
        {
            return CreateTenantResult.Unauthorized(ex.Message);
        }

        string normalizedSlug;
        string trimmedDisplayName;
        try
        {
            normalizedSlug = TenantValidation.ValidateAndNormalizeSlug(request.Slug);
            trimmedDisplayName = TenantValidation.ValidateAndTrimDisplayName(request.DisplayName);
        }
        catch (ArgumentException ex)
        {
            return CreateTenantResult.ValidationFailed(ex.Message);
        }

        // 2. Verify Creator User Identity and Status
        var creatorUser = await _dbContext.Users
            .AsNoTracking()
            .FirstOrDefaultAsync(u => u.Id == creatorUserId, cancellationToken);

        if (creatorUser is null)
        {
            _logger.LogWarning("Tenant creation rejected: creator User {UserId} was not found.", creatorUserId);
            return CreateTenantResult.Unauthorized("Authenticated user account was not found.");
        }

        if (creatorUser.Status != UserStatus.Active)
        {
            _logger.LogWarning(
                "Tenant creation rejected: creator User {UserId} has non-active status ({Status}).",
                creatorUserId, creatorUser.Status);
            return CreateTenantResult.Forbidden("Your account status does not permit creating a tenant organization.");
        }

        // 3. Pre-check Slug Uniqueness
        var slugExists = await _dbContext.Tenants
            .AsNoTracking()
            .AnyAsync(t => t.Slug == normalizedSlug, cancellationToken);

        if (slugExists)
        {
            _logger.LogWarning("Tenant creation rejected: slug '{Slug}' is already registered.", normalizedSlug);
            return CreateTenantResult.Conflict($"A tenant organization with the URL identifier '{normalizedSlug}' already exists.");
        }

        var utcNow = _timeProvider.GetUtcNow().UtcDateTime;

        // 4. Atomic Durability using EF Execution Strategy
        var strategy = _dbContext.Database.CreateExecutionStrategy();
        return await strategy.ExecuteAsync(async () =>
        {
            await using var tx = await _dbContext.Database.BeginTransactionAsync(IsolationLevel.ReadCommitted, cancellationToken);

            try
            {
                // Create Tenant entity in PendingOnboarding status (domain default)
                var tenant = Tenant.Create(normalizedSlug, trimmedDisplayName, TenantStatus.PendingOnboarding);
                tenant.CreatedAtUtc = utcNow;
                tenant.UpdatedAtUtc = utcNow;

                // Create initial Owner membership for creator
                var membership = TenantMembership.Create(
                    tenant.Id,
                    creatorUserId,
                    TenantMembershipRole.Owner,
                    TenantMembershipStatus.Active,
                    utcNow);

                // Add to database using privileged bypass scope for onboarding write
                using (_dbContext.CreatePrivilegedTenantBypassScope("tenant-onboarding"))
                {
                    _dbContext.Tenants.Add(tenant);
                    _dbContext.TenantMemberships.Add(membership);
                    await _dbContext.SaveChangesAsync(cancellationToken);
                }

                await tx.CommitAsync(cancellationToken);

                _logger.LogInformation(
                    "Tenant organization created successfully: Tenant {TenantId} ('{Slug}') with Owner User {UserId}.",
                    tenant.Id, tenant.Slug, creatorUserId);

                var response = new CreateTenantResponse(
                    tenant.Id,
                    tenant.Slug,
                    tenant.DisplayName,
                    tenant.Status.ToString(),
                    tenant.CreatedAtUtc);

                return CreateTenantResult.Success(response);
            }
            catch (DbUpdateException ex) when (IsUniqueSlugViolation(ex))
            {
                await tx.RollbackAsync(cancellationToken);
                _logger.LogWarning(ex, "Concurrent duplicate tenant creation caught on slug '{Slug}'.", normalizedSlug);
                return CreateTenantResult.Conflict($"A tenant organization with the URL identifier '{normalizedSlug}' already exists.");
            }
            catch (Exception ex)
            {
                await tx.RollbackAsync(cancellationToken);
                _logger.LogError(ex, "Unexpected error occurred during atomic tenant creation for slug '{Slug}'.", normalizedSlug);
                throw;
            }
        });
    }

    private static bool IsUniqueSlugViolation(DbUpdateException ex)
    {
        if (ex.InnerException is PostgresException pgEx)
        {
            return pgEx.SqlState == PostgresErrorCodes.UniqueViolation &&
                   (pgEx.ConstraintName == "ix_tenants_slug" || pgEx.ConstraintName?.Contains("slug") == true);
        }

        return ex.Message.Contains("ix_tenants_slug", StringComparison.OrdinalIgnoreCase);
    }

    /// <inheritdoc />
    public Task<TenantResult> GetTenantByIdAsync(Guid tenantId, CancellationToken cancellationToken = default)
        => GetTenantByIdAsync(tenantId, actor: null, cancellationToken);

    /// <inheritdoc />
    public async Task<TenantResult> GetTenantByIdAsync(
        Guid tenantId,
        TenantActorContext? actor,
        CancellationToken cancellationToken = default)
    {
        try
        {
            TenantValidation.ValidateTenantId(tenantId);
        }
        catch (ArgumentException ex)
        {
            return TenantResult.ValidationFailed(ex.Message, "INVALID_TENANT_ID");
        }

        var effectiveActor = ResolveEffectiveActor(actor);
        if (effectiveActor is null || effectiveActor.UserId == Guid.Empty)
        {
            _logger.LogWarning("Tenant lookup by ID denied: caller context is unauthenticated. TenantId: {TenantId}", tenantId);
            return TenantResult.NotFound(); // Anti-enumeration: Generic NotFound for unauthenticated caller
        }

        var tenant = await _dbContext.Tenants
            .AsNoTracking()
            .FirstOrDefaultAsync(t => t.Id == tenantId, cancellationToken);

        if (tenant is null)
        {
            return TenantResult.NotFound();
        }

        if (!effectiveActor.IsPlatformAdmin)
        {
            var isMember = await IsActiveTenantMemberAsync(effectiveActor, tenant.Id, cancellationToken);
            if (!isMember)
            {
                _logger.LogWarning(
                    "Tenant lookup by ID denied: User {UserId} is not an active member of Tenant {TenantId}.",
                    effectiveActor.UserId, tenantId);
                return TenantResult.NotFound(); // Anti-enumeration: Non-members receive NotFound
            }
        }
        else
        {
            // Explicit administrative inspection bypass tracking (Task 4.4.2)
            var isMember = await IsActiveTenantMemberAsync(effectiveActor, tenant.Id, cancellationToken);
            if (!isMember)
            {
                var auditEvent = TenantAuditEvent.Create(
                    tenant.Id,
                    effectiveActor.UserId,
                    "PlatformAdminTenantInspectionBypass",
                    tenant.Status.ToString(),
                    tenant.Status.ToString(),
                    $"Administrative inspection bypass for tenant '{tenant.Slug}' ({tenant.Id})",
                    _timeProvider.GetUtcNow().UtcDateTime);

                _dbContext.TenantAuditEvents.Add(auditEvent);
                await _dbContext.SaveChangesAsync(cancellationToken);
            }
        }

        return TenantResult.Success(MapToResponse(tenant));
    }

    /// <inheritdoc />
    public Task<TenantResult> GetTenantBySlugAsync(string slug, CancellationToken cancellationToken = default)
        => GetTenantBySlugAsync(slug, actor: null, cancellationToken);

    /// <inheritdoc />
    public async Task<TenantResult> GetTenantBySlugAsync(
        string slug,
        TenantActorContext? actor,
        CancellationToken cancellationToken = default)
    {
        string normalizedSlug;
        try
        {
            normalizedSlug = TenantValidation.ValidateAndNormalizeSlug(slug);
        }
        catch (ArgumentException ex)
        {
            return TenantResult.ValidationFailed(ex.Message, "INVALID_SLUG");
        }

        var effectiveActor = ResolveEffectiveActor(actor);
        if (effectiveActor is null || effectiveActor.UserId == Guid.Empty)
        {
            _logger.LogWarning("Tenant lookup by slug denied: caller context is unauthenticated. Slug: '{Slug}'", normalizedSlug);
            return TenantResult.NotFound(); // Anti-enumeration
        }

        var tenant = await _dbContext.Tenants
            .AsNoTracking()
            .FirstOrDefaultAsync(t => t.Slug == normalizedSlug, cancellationToken);

        if (tenant is null)
        {
            return TenantResult.NotFound();
        }

        if (!effectiveActor.IsPlatformAdmin)
        {
            var isMember = await IsActiveTenantMemberAsync(effectiveActor, tenant.Id, cancellationToken);
            if (!isMember)
            {
                _logger.LogWarning(
                    "Tenant lookup by slug denied: User {UserId} is not an active member of Tenant {TenantId}.",
                    effectiveActor.UserId, tenant.Id);
                return TenantResult.NotFound(); // Anti-enumeration
            }
        }
        else
        {
            // Explicit administrative inspection bypass tracking (Task 4.4.2)
            var isMember = await IsActiveTenantMemberAsync(effectiveActor, tenant.Id, cancellationToken);
            if (!isMember)
            {
                var auditEvent = TenantAuditEvent.Create(
                    tenant.Id,
                    effectiveActor.UserId,
                    "PlatformAdminTenantInspectionBypass",
                    tenant.Status.ToString(),
                    tenant.Status.ToString(),
                    $"Administrative inspection bypass for tenant '{tenant.Slug}' ({tenant.Id})",
                    _timeProvider.GetUtcNow().UtcDateTime);

                _dbContext.TenantAuditEvents.Add(auditEvent);
                await _dbContext.SaveChangesAsync(cancellationToken);
            }
        }

        return TenantResult.Success(MapToResponse(tenant));
    }

    /// <inheritdoc />
    public Task<TenantResult> UpdateTenantAsync(
        Guid tenantId,
        UpdateTenantRequest request,
        CancellationToken cancellationToken = default)
        => UpdateTenantAsync(tenantId, request, actor: null, cancellationToken);

    /// <inheritdoc />
    public async Task<TenantResult> UpdateTenantAsync(
        Guid tenantId,
        UpdateTenantRequest request,
        TenantActorContext? actor,
        CancellationToken cancellationToken = default)
    {
        try
        {
            TenantValidation.ValidateTenantId(tenantId);
        }
        catch (ArgumentException ex)
        {
            return TenantResult.ValidationFailed(ex.Message, "INVALID_TENANT_ID");
        }

        if (request is null)
        {
            return TenantResult.ValidationFailed("Request payload cannot be null.", "INVALID_REQUEST");
        }

        string trimmedDisplayName;
        try
        {
            trimmedDisplayName = TenantValidation.ValidateAndTrimDisplayName(request.DisplayName);
        }
        catch (ArgumentException ex)
        {
            return TenantResult.ValidationFailed(ex.Message, "INVALID_DISPLAY_NAME");
        }

        var effectiveActor = ResolveEffectiveActor(actor);
        if (effectiveActor is null || effectiveActor.UserId == Guid.Empty)
        {
            _logger.LogWarning("Tenant update denied: unauthenticated caller for Tenant {TenantId}.", tenantId);
            return TenantResult.Forbidden("Authentication and verified membership are required to update tenant settings.");
        }

        // Authorization check: Platform Admin or Tenant Owner/Administrator
        if (!effectiveActor.IsPlatformAdmin)
        {
            if (effectiveActor.TenantId.HasValue && effectiveActor.TenantId.Value != tenantId)
            {
                _logger.LogWarning(
                    "Cross-tenant modification denied: Actor active tenant is {ActiveTenantId}, target is {TargetTenantId}.",
                    effectiveActor.TenantId.Value, tenantId);
                return TenantResult.Forbidden("Cross-tenant modification is denied.");
            }

            TenantMembershipRole? actorRole = null;
            if (effectiveActor.TenantId.HasValue && effectiveActor.TenantId.Value == tenantId && effectiveActor.Role.HasValue)
            {
                actorRole = effectiveActor.Role.Value;
            }
            else
            {
                using (_dbContext.CreatePrivilegedTenantBypassScope("verify-tenant-update-membership"))
                {
                    var membership = await _dbContext.TenantMemberships
                        .AsNoTracking()
                        .FirstOrDefaultAsync(m => m.TenantId == tenantId && m.UserId == effectiveActor.UserId && m.Status == TenantMembershipStatus.Active, cancellationToken);

                    if (membership is not null)
                    {
                        actorRole = membership.Role;
                    }
                }
            }

            if (actorRole is null)
            {
                _logger.LogWarning(
                    "Tenant update denied: User {UserId} has no active membership in Tenant {TenantId}.",
                    effectiveActor.UserId, tenantId);
                return TenantResult.Forbidden("Active membership is required to update tenant settings.");
            }

            if (actorRole != TenantMembershipRole.Owner && actorRole != TenantMembershipRole.Administrator)
            {
                _logger.LogWarning(
                    "Tenant update denied: User {UserId} has role {Role} in Tenant {TenantId}; Owner or Administrator required.",
                    effectiveActor.UserId, actorRole, tenantId);
                return TenantResult.Forbidden("Only tenant Owners and Administrators are authorized to update tenant settings.");
            }
        }

        try
        {
            var strategy = _dbContext.Database.CreateExecutionStrategy();
            return await strategy.ExecuteAsync(async () =>
            {
                var isOuterTx = _dbContext.Database.CurrentTransaction is null;
                var tx = isOuterTx ? await _dbContext.Database.BeginTransactionAsync(IsolationLevel.ReadCommitted, cancellationToken) : null;
                try
                {
                    var tenant = await _dbContext.Tenants
                        .FirstOrDefaultAsync(t => t.Id == tenantId, cancellationToken);

                    if (tenant is null)
                    {
                        return TenantResult.NotFound();
                    }

                    if (tenant.Status == TenantStatus.Deactivated)
                    {
                        _logger.LogWarning("Tenant update rejected: tenant {TenantId} is permanently deactivated.", tenantId);
                        return TenantResult.Conflict("Cannot update display name for deactivated tenant organization.", "DEACTIVATED_TENANT");
                    }

                    // Optimistic Concurrency Pre-check (enforced even if submitted values match current state)
                    if (request.ExpectedVersion.HasValue && request.ExpectedVersion.Value != tenant.Version)
                    {
                        _logger.LogWarning(
                            "Optimistic concurrency conflict for Tenant {TenantId}: Expected version {ExpectedVersion}, but current version is {CurrentVersion}.",
                            tenantId, request.ExpectedVersion.Value, tenant.Version);
                        return TenantResult.Conflict($"Optimistic concurrency conflict: Expected version {request.ExpectedVersion.Value} does not match current version {tenant.Version}.");
                    }

                    // Idempotent no-op: preserve version and avoid false audit records
                    if (tenant.DisplayName == trimmedDisplayName)
                    {
                        return TenantResult.Success(MapToResponse(tenant));
                    }

                    var previousVersion = tenant.Version;
                    var now = _timeProvider.GetUtcNow().UtcDateTime;
                    tenant.UpdateDisplayName(trimmedDisplayName, now);

                    var isBypass = effectiveActor.IsPlatformAdmin && !await IsActiveTenantMemberAsync(effectiveActor, tenant.Id, cancellationToken);
                    var auditReason = isBypass
                        ? $"PlatformAdminBypass: DisplayName updated (version {previousVersion} -> {tenant.Version})"
                        : $"Changed fields: DisplayName (version {previousVersion} -> {tenant.Version})";

                    var auditEvent = TenantAuditEvent.Create(
                        tenant.Id,
                        effectiveActor.UserId,
                        "TenantSettingsUpdated",
                        tenant.Status.ToString(),
                        tenant.Status.ToString(),
                        auditReason,
                        now);

                    _dbContext.TenantAuditEvents.Add(auditEvent);

                    await _dbContext.SaveChangesAsync(cancellationToken);

                    if (tx is not null)
                    {
                        await tx.CommitAsync(cancellationToken);
                    }

                    _logger.LogInformation(
                        "Security Audit: TenantSettingsUpdated [ActorUserId={ActorUserId}, TenantId={TenantId}, Version={Version}, Timestamp={Timestamp:O}]",
                        effectiveActor.UserId, tenant.Id, tenant.Version, now);

                    return TenantResult.Success(MapToResponse(tenant));
                }
                catch
                {
                    if (isOuterTx)
                    {
                        _dbContext.ChangeTracker.Clear();
                    }
                    throw;
                }
                finally
                {
                    if (tx is not null)
                    {
                        await tx.DisposeAsync();
                    }
                }
            });
        }
        catch (DbUpdateConcurrencyException ex)
        {
            _logger.LogWarning(ex, "Optimistic concurrency conflict while saving tenant {TenantId} settings.", tenantId);
            return TenantResult.Conflict("Optimistic concurrency conflict: the tenant organization was modified by another operation.");
        }
    }

    /// <inheritdoc />
    public Task<TenantLifecycleResult> ActivateTenantAsync(Guid tenantId, CancellationToken cancellationToken = default)
        => ActivateTenantAsync(tenantId, actor: null, cancellationToken);

    /// <inheritdoc />
    public async Task<TenantLifecycleResult> ActivateTenantAsync(
        Guid tenantId,
        TenantActorContext? actor,
        CancellationToken cancellationToken = default)
    {
        try
        {
            TenantValidation.ValidateTenantId(tenantId);
        }
        catch (ArgumentException ex)
        {
            return TenantLifecycleResult.InvalidState(ex.Message, "INVALID_TENANT_ID");
        }

        var effectiveActor = ResolveEffectiveActor(actor);
        if (effectiveActor is null || !effectiveActor.IsPlatformAdmin)
        {
            _logger.LogWarning("Tenant activation denied: caller is not a verified platform administrator. TenantId: {TenantId}", tenantId);
            return TenantLifecycleResult.Forbidden("Platform administrator privileges are required to perform tenant lifecycle operations.");
        }

        try
        {
            var strategy = _dbContext.Database.CreateExecutionStrategy();
            return await strategy.ExecuteAsync(async () =>
            {
                var isOuterTx = _dbContext.Database.CurrentTransaction is null;
                var tx = isOuterTx ? await _dbContext.Database.BeginTransactionAsync(IsolationLevel.ReadCommitted, cancellationToken) : null;
                try
                {
                    var tenant = await _dbContext.Tenants
                        .FirstOrDefaultAsync(t => t.Id == tenantId, cancellationToken);

                    if (tenant is null)
                    {
                        return TenantLifecycleResult.NotFound();
                    }

                    if (tenant.Status == TenantStatus.Deactivated)
                    {
                        _logger.LogWarning("Tenant activation rejected: tenant {TenantId} is permanently deactivated.", tenantId);
                        return TenantLifecycleResult.InvalidState($"Cannot activate tenant '{tenantId}' because it is permanently deactivated.");
                    }

                    if (tenant.Status == TenantStatus.Active)
                    {
                        _logger.LogInformation("Tenant activation idempotent: tenant {TenantId} is already active.", tenantId);
                        return TenantLifecycleResult.Success(new TenantLifecycleResponse(tenant.Id, tenant.Status.ToString(), tenant.UpdatedAtUtc));
                    }

                    var previousStatus = tenant.Status;
                    var now = _timeProvider.GetUtcNow().UtcDateTime;

                    tenant.Activate(now);

                    var auditEvent = TenantAuditEvent.Create(
                        tenant.Id,
                        effectiveActor.UserId,
                        "TenantActivated",
                        previousStatus.ToString(),
                        tenant.Status.ToString(),
                        null,
                        now);

                    _dbContext.TenantAuditEvents.Add(auditEvent);

                    await _dbContext.SaveChangesAsync(cancellationToken);

                    if (tx is not null)
                    {
                        await tx.CommitAsync(cancellationToken);
                    }

                    _logger.LogInformation(
                        "Security Audit: TenantActivated [ActorUserId={ActorUserId}, TenantId={TenantId}, PreviousStatus={PreviousStatus}, NewStatus={NewStatus}, Timestamp={Timestamp:O}]",
                        effectiveActor.UserId, tenant.Id, previousStatus, tenant.Status, now);

                    return TenantLifecycleResult.Success(new TenantLifecycleResponse(tenant.Id, tenant.Status.ToString(), tenant.UpdatedAtUtc));
                }
                catch
                {
                    if (isOuterTx)
                    {
                        _dbContext.ChangeTracker.Clear();
                    }
                    throw;
                }
                finally
                {
                    if (tx is not null)
                    {
                        await tx.DisposeAsync();
                    }
                }
            });
        }
        catch (DbUpdateConcurrencyException ex)
        {
            _logger.LogWarning(ex, "Optimistic concurrency conflict while activating tenant {TenantId}.", tenantId);
            return TenantLifecycleResult.Conflict("Optimistic concurrency conflict: the tenant organization was modified by another operation.");
        }
    }

    /// <inheritdoc />
    public Task<TenantLifecycleResult> SuspendTenantAsync(
        Guid tenantId,
        string reason,
        CancellationToken cancellationToken = default)
        => SuspendTenantAsync(tenantId, reason, actor: null, cancellationToken);

    /// <inheritdoc />
    public async Task<TenantLifecycleResult> SuspendTenantAsync(
        Guid tenantId,
        string reason,
        TenantActorContext? actor,
        CancellationToken cancellationToken = default)
    {
        try
        {
            TenantValidation.ValidateTenantId(tenantId);
        }
        catch (ArgumentException ex)
        {
            return TenantLifecycleResult.InvalidState(ex.Message, "INVALID_TENANT_ID");
        }

        string trimmedReason;
        try
        {
            trimmedReason = TenantValidation.ValidateReason(reason);
        }
        catch (ArgumentException ex)
        {
            return TenantLifecycleResult.InvalidState(ex.Message, "INVALID_REASON");
        }

        var effectiveActor = ResolveEffectiveActor(actor);
        if (effectiveActor is null || !effectiveActor.IsPlatformAdmin)
        {
            _logger.LogWarning("Tenant suspension denied: caller is not a verified platform administrator. TenantId: {TenantId}", tenantId);
            return TenantLifecycleResult.Forbidden("Platform administrator privileges are required to perform tenant lifecycle operations.");
        }

        try
        {
            var strategy = _dbContext.Database.CreateExecutionStrategy();
            return await strategy.ExecuteAsync(async () =>
            {
                var isOuterTx = _dbContext.Database.CurrentTransaction is null;
                var tx = isOuterTx ? await _dbContext.Database.BeginTransactionAsync(IsolationLevel.ReadCommitted, cancellationToken) : null;
                try
                {
                    var tenant = await _dbContext.Tenants
                        .FirstOrDefaultAsync(t => t.Id == tenantId, cancellationToken);

                    if (tenant is null)
                    {
                        return TenantLifecycleResult.NotFound();
                    }

                    if (tenant.Status == TenantStatus.Deactivated)
                    {
                        _logger.LogWarning("Tenant suspension rejected: tenant {TenantId} is permanently deactivated.", tenantId);
                        return TenantLifecycleResult.InvalidState($"Cannot suspend tenant '{tenantId}' because it is permanently deactivated.");
                    }

                    if (tenant.Status == TenantStatus.PendingOnboarding)
                    {
                        _logger.LogWarning("Tenant suspension rejected: tenant {TenantId} has not completed onboarding.", tenantId);
                        return TenantLifecycleResult.InvalidState($"Cannot suspend tenant '{tenantId}' because it is in PendingOnboarding status and has not completed initial onboarding.");
                    }

                    if (tenant.Status == TenantStatus.Suspended)
                    {
                        _logger.LogInformation("Tenant suspension idempotent: tenant {TenantId} is already suspended.", tenantId);
                        return TenantLifecycleResult.Success(new TenantLifecycleResponse(tenant.Id, tenant.Status.ToString(), tenant.UpdatedAtUtc));
                    }

                    var previousStatus = tenant.Status;
                    var now = _timeProvider.GetUtcNow().UtcDateTime;

                    tenant.Suspend(now);

                    var auditEvent = TenantAuditEvent.Create(
                        tenant.Id,
                        effectiveActor.UserId,
                        "TenantSuspended",
                        previousStatus.ToString(),
                        tenant.Status.ToString(),
                        trimmedReason,
                        now);

                    _dbContext.TenantAuditEvents.Add(auditEvent);

                    await _dbContext.SaveChangesAsync(cancellationToken);

                    if (tx is not null)
                    {
                        await tx.CommitAsync(cancellationToken);
                    }

                    _logger.LogInformation(
                        "Security Audit: TenantSuspended [ActorUserId={ActorUserId}, TenantId={TenantId}, Reason='{Reason}', PreviousStatus={PreviousStatus}, NewStatus={NewStatus}, Timestamp={Timestamp:O}]",
                        effectiveActor.UserId, tenant.Id, trimmedReason, previousStatus, tenant.Status, now);

                    return TenantLifecycleResult.Success(new TenantLifecycleResponse(tenant.Id, tenant.Status.ToString(), tenant.UpdatedAtUtc));
                }
                catch
                {
                    if (isOuterTx)
                    {
                        _dbContext.ChangeTracker.Clear();
                    }
                    throw;
                }
                finally
                {
                    if (tx is not null)
                    {
                        await tx.DisposeAsync();
                    }
                }
            });
        }
        catch (DbUpdateConcurrencyException ex)
        {
            _logger.LogWarning(ex, "Optimistic concurrency conflict while suspending tenant {TenantId}.", tenantId);
            return TenantLifecycleResult.Conflict("Optimistic concurrency conflict: the tenant organization was modified by another operation.");
        }
    }

    /// <inheritdoc />
    public Task<TenantLifecycleResult> DeactivateTenantAsync(
        Guid tenantId,
        string reason,
        CancellationToken cancellationToken = default)
        => DeactivateTenantAsync(tenantId, reason, actor: null, cancellationToken);

    /// <inheritdoc />
    public async Task<TenantLifecycleResult> DeactivateTenantAsync(
        Guid tenantId,
        string reason,
        TenantActorContext? actor,
        CancellationToken cancellationToken = default)
    {
        try
        {
            TenantValidation.ValidateTenantId(tenantId);
        }
        catch (ArgumentException ex)
        {
            return TenantLifecycleResult.InvalidState(ex.Message, "INVALID_TENANT_ID");
        }

        string trimmedReason;
        try
        {
            trimmedReason = TenantValidation.ValidateReason(reason);
        }
        catch (ArgumentException ex)
        {
            return TenantLifecycleResult.InvalidState(ex.Message, "INVALID_REASON");
        }

        var effectiveActor = ResolveEffectiveActor(actor);
        if (effectiveActor is null || !effectiveActor.IsPlatformAdmin)
        {
            _logger.LogWarning("Tenant deactivation denied: caller is not a verified platform administrator. TenantId: {TenantId}", tenantId);
            return TenantLifecycleResult.Forbidden("Platform administrator privileges are required to perform tenant lifecycle operations.");
        }

        try
        {
            var strategy = _dbContext.Database.CreateExecutionStrategy();
            return await strategy.ExecuteAsync(async () =>
            {
                var isOuterTx = _dbContext.Database.CurrentTransaction is null;
                var tx = isOuterTx ? await _dbContext.Database.BeginTransactionAsync(IsolationLevel.ReadCommitted, cancellationToken) : null;
                try
                {
                    var tenant = await _dbContext.Tenants
                        .FirstOrDefaultAsync(t => t.Id == tenantId, cancellationToken);

                    if (tenant is null)
                    {
                        return TenantLifecycleResult.NotFound();
                    }

                    if (tenant.Status == TenantStatus.Deactivated)
                    {
                        _logger.LogInformation("Tenant deactivation idempotent: tenant {TenantId} is already deactivated.", tenantId);
                        return TenantLifecycleResult.Success(new TenantLifecycleResponse(tenant.Id, tenant.Status.ToString(), tenant.UpdatedAtUtc));
                    }

                    var previousStatus = tenant.Status;
                    var now = _timeProvider.GetUtcNow().UtcDateTime;

                    tenant.Deactivate(now);

                    var auditEvent = TenantAuditEvent.Create(
                        tenant.Id,
                        effectiveActor.UserId,
                        "TenantDeactivated",
                        previousStatus.ToString(),
                        tenant.Status.ToString(),
                        trimmedReason,
                        now);

                    _dbContext.TenantAuditEvents.Add(auditEvent);

                    await _dbContext.SaveChangesAsync(cancellationToken);

                    if (tx is not null)
                    {
                        await tx.CommitAsync(cancellationToken);
                    }

                    _logger.LogInformation(
                        "Security Audit: TenantDeactivated [ActorUserId={ActorUserId}, TenantId={TenantId}, Reason='{Reason}', PreviousStatus={PreviousStatus}, NewStatus={NewStatus}, Timestamp={Timestamp:O}]",
                        effectiveActor.UserId, tenant.Id, trimmedReason, previousStatus, tenant.Status, now);

                    return TenantLifecycleResult.Success(new TenantLifecycleResponse(tenant.Id, tenant.Status.ToString(), tenant.UpdatedAtUtc));
                }
                catch
                {
                    if (isOuterTx)
                    {
                        _dbContext.ChangeTracker.Clear();
                    }
                    throw;
                }
                finally
                {
                    if (tx is not null)
                    {
                        await tx.DisposeAsync();
                    }
                }
            });
        }
        catch (DbUpdateConcurrencyException ex)
        {
            _logger.LogWarning(ex, "Optimistic concurrency conflict while deactivating tenant {TenantId}.", tenantId);
            return TenantLifecycleResult.Conflict("Optimistic concurrency conflict: the tenant organization was modified by another operation.");
        }
    }

    private TenantActorContext? ResolveEffectiveActor(TenantActorContext? actor)
    {
        if (actor is not null)
        {
            return actor;
        }

        return TenantActorContext.FromTenantContext(_tenantContextAccessor?.Current);
    }

    private async Task<bool> IsActiveTenantMemberAsync(
        TenantActorContext actor,
        Guid tenantId,
        CancellationToken cancellationToken)
    {
        if (!actor.IsPlatformAdmin && actor.TenantId.HasValue && actor.TenantId.Value == tenantId && actor.Role.HasValue)
        {
            return true;
        }

        using (_dbContext.CreatePrivilegedTenantBypassScope("verify-tenant-membership"))
        {
            return await _dbContext.TenantMemberships
                .AsNoTracking()
                .AnyAsync(m => m.TenantId == tenantId && m.UserId == actor.UserId && m.Status == TenantMembershipStatus.Active, cancellationToken);
        }
    }

    private static TenantResponse MapToResponse(Tenant tenant) =>
        new(
            tenant.Id,
            tenant.Slug,
            tenant.DisplayName,
            tenant.Status.ToString(),
            tenant.CreatedAtUtc,
            tenant.UpdatedAtUtc,
            tenant.Version);
}

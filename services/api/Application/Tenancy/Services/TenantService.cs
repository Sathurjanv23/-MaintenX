namespace MaintenX.Api.Application.Tenancy.Services;

using System.Data;
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
/// </summary>
public sealed class TenantService : ITenantService
{
    private readonly MaintenXDbContext _dbContext;
    private readonly TimeProvider _timeProvider;
    private readonly ILogger<TenantService> _logger;

    public TenantService(
        MaintenXDbContext dbContext,
        TimeProvider timeProvider,
        ILogger<TenantService> logger)
    {
        _dbContext = dbContext ?? throw new ArgumentNullException(nameof(dbContext));
        _timeProvider = timeProvider ?? throw new ArgumentNullException(nameof(timeProvider));
        _logger = logger ?? throw new ArgumentNullException(nameof(logger));
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
        => throw new NotImplementedException("Tenant retrieval will be implemented in Task 3.5.3.");

    /// <inheritdoc />
    public Task<TenantResult> GetTenantBySlugAsync(string slug, CancellationToken cancellationToken = default)
        => throw new NotImplementedException("Tenant retrieval will be implemented in Task 3.5.3.");

    /// <inheritdoc />
    public Task<TenantResult> UpdateTenantAsync(Guid tenantId, UpdateTenantRequest request, CancellationToken cancellationToken = default)
        => throw new NotImplementedException("Tenant update will be implemented in Task 3.5.3.");

    /// <inheritdoc />
    public Task<TenantLifecycleResult> ActivateTenantAsync(Guid tenantId, CancellationToken cancellationToken = default)
        => throw new NotImplementedException("Tenant lifecycle operations will be implemented in Task 3.5.3.");

    /// <inheritdoc />
    public Task<TenantLifecycleResult> SuspendTenantAsync(Guid tenantId, string reason, CancellationToken cancellationToken = default)
        => throw new NotImplementedException("Tenant lifecycle operations will be implemented in Task 3.5.3.");

    /// <inheritdoc />
    public Task<TenantLifecycleResult> DeactivateTenantAsync(Guid tenantId, string reason, CancellationToken cancellationToken = default)
        => throw new NotImplementedException("Tenant lifecycle operations will be implemented in Task 3.5.3.");
}

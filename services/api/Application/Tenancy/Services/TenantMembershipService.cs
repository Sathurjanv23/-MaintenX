namespace MaintenX.Api.Application.Tenancy.Services;

using MaintenX.Api.Application.Tenancy.Context;
using MaintenX.Api.Application.Tenancy.Contracts;
using MaintenX.Api.Application.Tenancy.Models;
using MaintenX.Api.Application.Tenancy.Validation;
using MaintenX.Api.Domain.Tenants;
using MaintenX.Api.Infrastructure.Persistence;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;

/// <summary>
/// Application service providing secure tenant membership discovery and query capabilities.
/// Enforces authenticated caller verification, strict cross-tenant boundary isolation,
/// non-disclosing anti-enumeration error handling, and safe non-tracking queries.
/// </summary>
public sealed class TenantMembershipService : ITenantMembershipService
{
    private readonly MaintenXDbContext _dbContext;
    private readonly ITenantContextAccessor? _tenantContextAccessor;
    private readonly ILogger<TenantMembershipService> _logger;

    public TenantMembershipService(
        MaintenXDbContext dbContext,
        ITenantContextAccessor? tenantContextAccessor = null,
        ILogger<TenantMembershipService>? logger = null)
    {
        _dbContext = dbContext ?? throw new ArgumentNullException(nameof(dbContext));
        _tenantContextAccessor = tenantContextAccessor;
        _logger = logger ?? NullLogger<TenantMembershipService>.Instance;
    }

    /// <inheritdoc />
    public Task<IReadOnlyList<UserTenantMembershipResponse>> GetUserMembershipsAsync(
        Guid userId,
        CancellationToken cancellationToken = default)
        => GetUserMembershipsAsync(userId, actor: null, cancellationToken);

    /// <inheritdoc />
    public async Task<IReadOnlyList<UserTenantMembershipResponse>> GetUserMembershipsAsync(
        Guid userId,
        TenantActorContext? actor,
        CancellationToken cancellationToken = default)
    {
        try
        {
            TenantValidation.ValidateUserId(userId);
        }
        catch (ArgumentException ex)
        {
            _logger.LogWarning(ex, "GetUserMemberships rejected: invalid user identifier {UserId}.", userId);
            return Array.Empty<UserTenantMembershipResponse>();
        }

        var effectiveActor = ResolveEffectiveActor(actor);
        if (effectiveActor is null || effectiveActor.UserId == Guid.Empty)
        {
            _logger.LogWarning("GetUserMemberships denied: caller context is unauthenticated. Target UserId: {UserId}", userId);
            return Array.Empty<UserTenantMembershipResponse>(); // Anti-enumeration: empty result for unauthenticated caller
        }

        // An ordinary authenticated user may only discover their own memberships
        if (!effectiveActor.IsPlatformAdmin && effectiveActor.UserId != userId)
        {
            _logger.LogWarning(
                "GetUserMemberships denied: User {ActorUserId} attempted to discover memberships for User {TargetUserId}.",
                effectiveActor.UserId, userId);
            return Array.Empty<UserTenantMembershipResponse>(); // Anti-enumeration: empty result prevents foreign membership reconnaissance
        }

        // Tenant-neutral discovery query under narrow privileged bypass scope
        using (_dbContext.CreatePrivilegedTenantBypassScope("query-user-memberships"))
        {
            var query = from m in _dbContext.TenantMemberships.AsNoTracking()
                        join t in _dbContext.Tenants.AsNoTracking() on m.TenantId equals t.Id
                        where m.UserId == userId
                              && m.Status != TenantMembershipStatus.Revoked
                        orderby t.DisplayName, t.Id
                        select new UserTenantMembershipResponse(
                            m.Id,
                            t.Id,
                            t.Slug,
                            t.DisplayName,
                            m.Role.ToString(),
                            m.Status.ToString(),
                            t.Status.ToString(),
                            m.Status == TenantMembershipStatus.Active && t.Status == TenantStatus.Active,
                            m.CreatedAtUtc);

            return await query.ToListAsync(cancellationToken);
        }
    }

    /// <inheritdoc />
    public Task<TenantMembershipResult> GetMembershipAsync(
        Guid tenantId,
        Guid userId,
        CancellationToken cancellationToken = default)
        => GetMembershipAsync(tenantId, userId, actor: null, cancellationToken);

    /// <inheritdoc />
    public async Task<TenantMembershipResult> GetMembershipAsync(
        Guid tenantId,
        Guid userId,
        TenantActorContext? actor,
        CancellationToken cancellationToken = default)
    {
        try
        {
            TenantValidation.ValidateTenantId(tenantId);
            TenantValidation.ValidateUserId(userId);
        }
        catch (ArgumentException ex)
        {
            return TenantMembershipResult.ValidationFailed(ex.Message);
        }

        var effectiveActor = ResolveEffectiveActor(actor);
        if (effectiveActor is null || effectiveActor.UserId == Guid.Empty)
        {
            _logger.LogWarning("GetMembership denied: caller context is unauthenticated. TenantId: {TenantId}, UserId: {UserId}", tenantId, userId);
            return TenantMembershipResult.NotFound(); // Anti-enumeration: unauthenticated callers receive generic NotFound
        }

        using (_dbContext.CreatePrivilegedTenantBypassScope("query-membership"))
        {
            // Case 1: Caller is querying their own membership in this tenant
            if (effectiveActor.UserId == userId)
            {
                var membership = await _dbContext.TenantMemberships
                    .AsNoTracking()
                    .Where(m => m.TenantId == tenantId && m.UserId == userId && m.Status != TenantMembershipStatus.Revoked)
                    .FirstOrDefaultAsync(cancellationToken);

                if (membership is null)
                {
                    return TenantMembershipResult.NotFound();
                }

                return TenantMembershipResult.Success(new TenantMembershipResponse(
                    membership.Id,
                    membership.TenantId,
                    membership.UserId,
                    membership.Role.ToString(),
                    membership.Status.ToString(),
                    membership.CreatedAtUtc,
                    membership.UpdatedAtUtc));
            }

            // Case 2: Caller is querying another user's membership in this tenant
            // Permitted ONLY if caller is a verified Platform Admin OR an active Owner/Administrator of that exact tenant
            if (!effectiveActor.IsPlatformAdmin)
            {
                var isCallerAuthorizedAdmin = await _dbContext.TenantMemberships
                    .AsNoTracking()
                    .AnyAsync(m => m.TenantId == tenantId
                                && m.UserId == effectiveActor.UserId
                                && m.Status == TenantMembershipStatus.Active
                                && (m.Role == TenantMembershipRole.Owner || m.Role == TenantMembershipRole.Administrator),
                        cancellationToken);

                if (!isCallerAuthorizedAdmin)
                {
                    _logger.LogWarning(
                        "GetMembership denied: User {ActorUserId} is not an active Owner or Administrator of Tenant {TenantId}.",
                        effectiveActor.UserId, tenantId);
                    return TenantMembershipResult.NotFound(); // Anti-enumeration: foreign or unprivileged callers receive generic NotFound
                }
            }

            var targetMembership = await _dbContext.TenantMemberships
                .AsNoTracking()
                .Where(m => m.TenantId == tenantId && m.UserId == userId && m.Status != TenantMembershipStatus.Revoked)
                .FirstOrDefaultAsync(cancellationToken);

            if (targetMembership is null)
            {
                return TenantMembershipResult.NotFound();
            }

            return TenantMembershipResult.Success(new TenantMembershipResponse(
                targetMembership.Id,
                targetMembership.TenantId,
                targetMembership.UserId,
                targetMembership.Role.ToString(),
                targetMembership.Status.ToString(),
                targetMembership.CreatedAtUtc,
                targetMembership.UpdatedAtUtc));
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
}

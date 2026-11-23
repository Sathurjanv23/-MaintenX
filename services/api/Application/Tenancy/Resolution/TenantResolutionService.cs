namespace MaintenX.Api.Application.Tenancy.Resolution;

using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using MaintenX.Api.Application.Tenancy.Context;
using MaintenX.Api.Common.Security;
using MaintenX.Api.Domain.Tenants;
using MaintenX.Api.Infrastructure.Persistence;
using Microsoft.AspNetCore.Http;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging;

/// <summary>
/// Server-verified tenant resolution implementation.
/// Treats any client-supplied tenant identifier as an unverified request, strictly validating:
/// 1. User authentication and claim validity (sub, sid, sst)
/// 2. Security stamp validity via in-memory cache and DB fallback
/// 3. Active, unexpired, unrevoked user session in PostgreSQL
/// 4. Explicit tenant selection (no implicit first-tenant defaulting)
/// 5. Tenant existence and Active operational status (rejecting suspended/deactivated/pending onboarding)
/// 6. Active membership for that exact user and tenant (rejecting pending/suspended/revoked memberships)
/// </summary>
public sealed class TenantResolutionService : ITenantResolutionService
{
    private readonly MaintenXDbContext _dbContext;
    private readonly ISecurityStampValidator _securityStampValidator;
    private readonly TimeProvider _timeProvider;
    private readonly ILogger<TenantResolutionService> _logger;

    public TenantResolutionService(
        MaintenXDbContext dbContext,
        ISecurityStampValidator securityStampValidator,
        TimeProvider timeProvider,
        ILogger<TenantResolutionService> logger)
    {
        _dbContext = dbContext ?? throw new ArgumentNullException(nameof(dbContext));
        _securityStampValidator = securityStampValidator ?? throw new ArgumentNullException(nameof(securityStampValidator));
        _timeProvider = timeProvider ?? throw new ArgumentNullException(nameof(timeProvider));
        _logger = logger ?? throw new ArgumentNullException(nameof(logger));
    }

    /// <inheritdoc />
    public async Task<TenantResolutionResult> ResolveAsync(
        ClaimsPrincipal? user,
        string? requestedTenantIdentifier,
        CancellationToken cancellationToken = default)
    {
        // 1. Verify Authentication
        if (user?.Identity?.IsAuthenticated != true)
        {
            return TenantResolutionResult.Failure(
                StatusCodes.Status401Unauthorized,
                "Unauthorized",
                "Authentication is required to access tenant resources.");
        }

        // 2. Extract and Validate User ID
        if (!TryGetUserId(user, out var userId))
        {
            return TenantResolutionResult.Failure(
                StatusCodes.Status401Unauthorized,
                "Unauthorized",
                "Invalid or missing user identity claim.");
        }

        // 3. Extract and Validate Session ID
        if (!TryGetSessionId(user, out var sessionId))
        {
            return TenantResolutionResult.Failure(
                StatusCodes.Status401Unauthorized,
                "Unauthorized",
                "Invalid or missing session identifier claim.");
        }

        // 4. Extract and Validate Security Stamp Claim
        var securityStamp = user.FindFirstValue("sst");
        if (string.IsNullOrWhiteSpace(securityStamp))
        {
            return TenantResolutionResult.Failure(
                StatusCodes.Status401Unauthorized,
                "Unauthorized",
                "Missing required security stamp claim.");
        }

        var isStampValid = await _securityStampValidator.ValidateAsync(userId, securityStamp, cancellationToken);
        if (!isStampValid)
        {
            _logger.LogWarning("Tenant resolution rejected: security stamp invalid or user inactive for User {UserId}.", userId);
            return TenantResolutionResult.Failure(
                StatusCodes.Status401Unauthorized,
                "Unauthorized",
                "Security credentials or user account status are no longer valid.");
        }

        // 5. Verify User Session in Database
        var session = await _dbContext.UserSessions
            .AsNoTracking()
            .FirstOrDefaultAsync(s => s.Id == sessionId, cancellationToken);

        var utcNow = _timeProvider.GetUtcNow().UtcDateTime;

        if (session is null || session.UserId != userId || session.IsRevoked || session.ExpiresAtUtc <= utcNow)
        {
            _logger.LogWarning("Tenant resolution rejected: session {SessionId} for User {UserId} is null, revoked, or expired.", sessionId, userId);
            return TenantResolutionResult.Failure(
                StatusCodes.Status401Unauthorized,
                "Unauthorized",
                "The authentication session is expired, revoked, or invalid.");
        }

        // 6. Validate Explicit Tenant Selection (No Implicit Defaulting)
        if (string.IsNullOrWhiteSpace(requestedTenantIdentifier))
        {
            return TenantResolutionResult.Failure(
                StatusCodes.Status400BadRequest,
                "Bad Request",
                "A tenant must be explicitly selected via the X-Tenant-ID header.");
        }

        var rawIdentifier = requestedTenantIdentifier.Trim();

        // 7. Locate Tenant by ID or Slug
        Tenant? tenant;
        if (Guid.TryParse(rawIdentifier, out var tenantId))
        {
            tenant = await _dbContext.Tenants
                .AsNoTracking()
                .FirstOrDefaultAsync(t => t.Id == tenantId, cancellationToken);
        }
        else
        {
            var normalizedSlug = rawIdentifier.ToLowerInvariant();
            tenant = await _dbContext.Tenants
                .AsNoTracking()
                .FirstOrDefaultAsync(t => t.Slug == normalizedSlug, cancellationToken);
        }

        if (tenant is null)
        {
            // Avoid tenant enumeration: safe 404 response
            _logger.LogInformation("Tenant resolution: requested tenant '{Identifier}' was not found.", rawIdentifier);
            return TenantResolutionResult.Failure(
                StatusCodes.Status404NotFound,
                "Not Found",
                "The requested tenant organization was not found.");
        }

        // 8. Enforce Tenant Operational Status
        if (tenant.Status == TenantStatus.Suspended)
        {
            _logger.LogWarning("Tenant resolution denied: tenant {TenantId} is suspended.", tenant.Id);
            return TenantResolutionResult.Failure(
                StatusCodes.Status403Forbidden,
                "Forbidden",
                "The requested tenant organization is currently suspended.");
        }

        if (tenant.Status == TenantStatus.Deactivated)
        {
            _logger.LogWarning("Tenant resolution denied: tenant {TenantId} is deactivated.", tenant.Id);
            return TenantResolutionResult.Failure(
                StatusCodes.Status403Forbidden,
                "Forbidden",
                "The requested tenant organization has been deactivated.");
        }

        if (tenant.Status != TenantStatus.Active)
        {
            _logger.LogWarning("Tenant resolution denied: tenant {TenantId} has not completed onboarding (Status: {Status}).", tenant.Id, tenant.Status);
            return TenantResolutionResult.Failure(
                StatusCodes.Status403Forbidden,
                "Forbidden",
                "The requested tenant organization has not completed initial onboarding.");
        }

        // 9. Query and Validate User Membership for this exact Tenant
        var memberships = await _dbContext.TenantMemberships
            .AsNoTracking()
            .Where(m => m.TenantId == tenant.Id && m.UserId == userId)
            .ToListAsync(cancellationToken);

        // Find the non-revoked membership (guaranteed at most one by unique partial index)
        var currentMembership = memberships.FirstOrDefault(m => m.Status != TenantMembershipStatus.Revoked);

        if (currentMembership is null)
        {
            // If historical memberships exist and all are revoked
            if (memberships.Count > 0)
            {
                _logger.LogWarning("Tenant resolution denied: user {UserId} membership in tenant {TenantId} is revoked.", userId, tenant.Id);
                return TenantResolutionResult.Failure(
                    StatusCodes.Status403Forbidden,
                    "Forbidden",
                    "User membership in the requested tenant organization has been revoked.");
            }

            // User has no membership record for this tenant at all
            _logger.LogWarning("Tenant resolution denied: user {UserId} is not a member of tenant {TenantId}.", userId, tenant.Id);
            return TenantResolutionResult.Failure(
                StatusCodes.Status403Forbidden,
                "Forbidden",
                "Access to the requested tenant organization is denied.");
        }

        // Validate membership lifecycle status
        if (currentMembership.Status == TenantMembershipStatus.Pending)
        {
            _logger.LogWarning("Tenant resolution denied: user {UserId} membership in tenant {TenantId} is pending.", userId, tenant.Id);
            return TenantResolutionResult.Failure(
                StatusCodes.Status403Forbidden,
                "Forbidden",
                "User membership in the requested tenant organization is pending activation.");
        }

        if (currentMembership.Status == TenantMembershipStatus.Suspended)
        {
            _logger.LogWarning("Tenant resolution denied: user {UserId} membership in tenant {TenantId} is suspended.", userId, tenant.Id);
            return TenantResolutionResult.Failure(
                StatusCodes.Status403Forbidden,
                "Forbidden",
                "User membership in the requested tenant organization is currently suspended.");
        }

        if (currentMembership.Status != TenantMembershipStatus.Active)
        {
            _logger.LogWarning("Tenant resolution denied: user {UserId} membership status is {Status}.", userId, currentMembership.Status);
            return TenantResolutionResult.Failure(
                StatusCodes.Status403Forbidden,
                "Forbidden",
                "User membership in the requested tenant organization is not active.");
        }

        // 10. Success: Construct Immutable, Verified Tenant Context
        var context = new TenantContext(
            tenant.Id,
            tenant.Slug,
            tenant.DisplayName,
            userId,
            currentMembership.Id,
            currentMembership.Role,
            currentMembership.Status,
            utcNow);

        _logger.LogInformation(
            "Tenant resolution successful: User {UserId} resolved into Tenant {TenantId} ('{TenantSlug}') with Role {Role}.",
            userId, tenant.Id, tenant.Slug, currentMembership.Role);

        return TenantResolutionResult.Success(context);
    }

    private static bool TryGetUserId(ClaimsPrincipal user, out Guid userId)
    {
        userId = Guid.Empty;
        var sub = user.FindFirstValue(ClaimTypes.NameIdentifier)
                  ?? user.FindFirstValue(JwtRegisteredClaimNames.Sub)
                  ?? user.FindFirstValue("sub");

        return Guid.TryParse(sub, out userId) && userId != Guid.Empty;
    }

    private static bool TryGetSessionId(ClaimsPrincipal user, out Guid sessionId)
    {
        sessionId = Guid.Empty;
        var sid = user.FindFirstValue("sid");

        return Guid.TryParse(sid, out sessionId) && sessionId != Guid.Empty;
    }
}

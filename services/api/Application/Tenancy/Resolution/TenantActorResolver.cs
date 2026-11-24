namespace MaintenX.Api.Application.Tenancy.Resolution;

using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using MaintenX.Api.Application.Tenancy.Context;
using MaintenX.Api.Application.Tenancy.Models;
using MaintenX.Api.Common.Security;
using MaintenX.Api.Infrastructure.Persistence;
using Microsoft.AspNetCore.Http;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging;

/// <summary>
/// Default server-side implementation of <see cref="ITenantActorResolver"/>.
/// Validates caller identity against database session validity and security stamp caches.
/// Strictly enforces that ordinary HTTP callers cannot establish platform-admin actor contexts (IsPlatformAdmin = false).
/// </summary>
public sealed class TenantActorResolver : ITenantActorResolver
{
    private readonly MaintenXDbContext _dbContext;
    private readonly ISecurityStampValidator _securityStampValidator;
    private readonly ITenantContextAccessor _tenantContextAccessor;
    private readonly TimeProvider _timeProvider;
    private readonly ILogger<TenantActorResolver> _logger;

    public TenantActorResolver(
        MaintenXDbContext dbContext,
        ISecurityStampValidator securityStampValidator,
        ITenantContextAccessor tenantContextAccessor,
        TimeProvider timeProvider,
        ILogger<TenantActorResolver> logger)
    {
        _dbContext = dbContext ?? throw new ArgumentNullException(nameof(dbContext));
        _securityStampValidator = securityStampValidator ?? throw new ArgumentNullException(nameof(securityStampValidator));
        _tenantContextAccessor = tenantContextAccessor ?? throw new ArgumentNullException(nameof(tenantContextAccessor));
        _timeProvider = timeProvider ?? throw new ArgumentNullException(nameof(timeProvider));
        _logger = logger ?? throw new ArgumentNullException(nameof(logger));
    }

    /// <inheritdoc />
    public async Task<TenantActorResolutionResult> ResolveActorAsync(
        ClaimsPrincipal? user,
        bool requireActiveTenantContext = false,
        CancellationToken cancellationToken = default)
    {
        // 1. Verify Authentication
        if (user?.Identity?.IsAuthenticated != true)
        {
            return TenantActorResolutionResult.Failure(
                StatusCodes.Status401Unauthorized,
                "Unauthorized",
                "Authentication is required to perform tenant operations.");
        }

        // 2. Extract and Validate User ID claim
        if (!TryGetUserId(user, out var userId))
        {
            return TenantActorResolutionResult.Failure(
                StatusCodes.Status401Unauthorized,
                "Unauthorized",
                "Invalid or missing user identity claim.");
        }

        // 3. Extract and Validate Session ID claim
        if (!TryGetSessionId(user, out var sessionId))
        {
            return TenantActorResolutionResult.Failure(
                StatusCodes.Status401Unauthorized,
                "Unauthorized",
                "Invalid or missing session identifier claim.");
        }

        // 4. Validate Security Stamp Claim
        var securityStamp = user.FindFirstValue("sst");
        if (string.IsNullOrWhiteSpace(securityStamp))
        {
            return TenantActorResolutionResult.Failure(
                StatusCodes.Status401Unauthorized,
                "Unauthorized",
                "Missing required security stamp claim.");
        }

        var isStampValid = await _securityStampValidator.ValidateAsync(userId, securityStamp, cancellationToken);
        if (!isStampValid)
        {
            _logger.LogWarning("Actor resolution rejected: security stamp invalid or user inactive for User {UserId}.", userId);
            return TenantActorResolutionResult.Failure(
                StatusCodes.Status401Unauthorized,
                "Unauthorized",
                "Security credentials or user account status are no longer valid.");
        }

        // 5. Verify User Session in Database (Non-Revoked, Active, Not Expired)
        var session = await _dbContext.UserSessions
            .AsNoTracking()
            .FirstOrDefaultAsync(s => s.Id == sessionId, cancellationToken);

        var utcNow = _timeProvider.GetUtcNow().UtcDateTime;

        if (session is null || session.UserId != userId || session.IsRevoked || session.ExpiresAtUtc <= utcNow)
        {
            _logger.LogWarning("Actor resolution rejected: session {SessionId} for User {UserId} is null, revoked, or expired.", sessionId, userId);
            return TenantActorResolutionResult.Failure(
                StatusCodes.Status401Unauthorized,
                "Unauthorized",
                "The authentication session is expired, revoked, or invalid.");
        }

        // 6. Handle Tenant Context Requirements
        var currentTenantContext = _tenantContextAccessor.Current;

        if (requireActiveTenantContext)
        {
            if (currentTenantContext is null)
            {
                _logger.LogWarning("Actor resolution rejected: endpoint requires active tenant context, but none was established. User: {UserId}", userId);
                return TenantActorResolutionResult.Failure(
                    StatusCodes.Status400BadRequest,
                    "Bad Request",
                    "A valid tenant organization must be selected via the X-Tenant-ID header.");
            }

            if (currentTenantContext.UserId != userId)
            {
                _logger.LogError("Actor resolution anomaly: verified tenant context user {ContextUser} does not match caller {UserId}.",
                    currentTenantContext.UserId, userId);
                return TenantActorResolutionResult.Failure(
                    StatusCodes.Status403Forbidden,
                    "Forbidden",
                    "Access to the requested tenant context is denied.");
            }

            // Tenant-scoped trusted actor: Never platform admin, derived exclusively from verified context
            var tenantActor = new TenantActorContext(
                UserId: userId,
                IsPlatformAdmin: false,
                TenantId: currentTenantContext.TenantId,
                Role: currentTenantContext.Role);

            return TenantActorResolutionResult.Success(tenantActor);
        }

        // 7. Tenant-Neutral Authenticated Actor (for Onboarding, Global Membership Discovery)
        // If an active verified tenant context is optionally present, bind it; otherwise return tenant-neutral context.
        var effectiveTenantId = currentTenantContext?.TenantId;
        var effectiveRole = currentTenantContext?.Role;

        var neutralActor = new TenantActorContext(
            UserId: userId,
            IsPlatformAdmin: false,
            TenantId: effectiveTenantId,
            Role: effectiveRole);

        return TenantActorResolutionResult.Success(neutralActor);
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

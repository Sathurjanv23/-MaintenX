namespace MaintenX.Api.Application.Authorization.Services;

using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using MaintenX.Api.Application.Authorization.Contracts;
using MaintenX.Api.Domain.Auth;
using MaintenX.Api.Domain.Authorization;
using MaintenX.Api.Infrastructure.Persistence;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Http;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging;

/// <summary>
/// Fail-closed, non-caching authoritative resolver for platform-scoped permissions.
/// Obtains identity exclusively from <see cref="IAuthenticationService.AuthenticateAsync"/>
/// using <see cref="JwtBearerDefaults.AuthenticationScheme"/> on the current server-controlled
/// <see cref="HttpContext"/>, then verifies current <see cref="User"/>, <see cref="UserSession"/>,
/// and <see cref="PlatformRoleGrant"/> database state on every evaluation.
/// </summary>
public sealed class PlatformGrantResolver : IPlatformGrantResolver
{
    private readonly IHttpContextAccessor _httpContextAccessor;
    private readonly IAuthenticationService _authenticationService;
    private readonly MaintenXDbContext _dbContext;
    private readonly TimeProvider _timeProvider;
    private readonly ILogger<PlatformGrantResolver> _logger;

    public PlatformGrantResolver(
        IHttpContextAccessor httpContextAccessor,
        IAuthenticationService authenticationService,
        MaintenXDbContext dbContext,
        TimeProvider timeProvider,
        ILogger<PlatformGrantResolver> logger)
    {
        _httpContextAccessor = httpContextAccessor ?? throw new ArgumentNullException(nameof(httpContextAccessor));
        _authenticationService = authenticationService ?? throw new ArgumentNullException(nameof(authenticationService));
        _dbContext = dbContext ?? throw new ArgumentNullException(nameof(dbContext));
        _timeProvider = timeProvider ?? throw new ArgumentNullException(nameof(timeProvider));
        _logger = logger ?? throw new ArgumentNullException(nameof(logger));
    }

    /// <inheritdoc />
    public async Task<PlatformGrantResolutionResult> ResolveAsync(
        PermissionKey? permission,
        CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();

        // 1. Validate requested permission is registered and strictly Platform-scoped
        if (permission is null ||
            permission.Scope != AuthorizationScopeKind.Platform ||
            !PermissionCatalog.IsRegistered(permission))
        {
            return PlatformGrantResolutionResult.Deny("InvalidOrUnregisteredPlatformPermission", permission);
        }

        // 2. Require an active server-controlled HttpContext
        var httpContext = _httpContextAccessor.HttpContext;
        if (httpContext is null)
        {
            return PlatformGrantResolutionResult.Deny("MissingHttpContext", permission);
        }

        Guid userId = Guid.Empty;

        try
        {
            // 3. Obtain authentication provenance exclusively from the configured Bearer scheme
            var authResult = await _authenticationService.AuthenticateAsync(
                httpContext,
                JwtBearerDefaults.AuthenticationScheme);

            cancellationToken.ThrowIfCancellationRequested();

            if (!authResult.Succeeded ||
                authResult.Ticket is null ||
                !string.Equals(authResult.Ticket.AuthenticationScheme, JwtBearerDefaults.AuthenticationScheme, StringComparison.Ordinal) ||
                authResult.Principal is null)
            {
                return PlatformGrantResolutionResult.Deny("UnauthenticatedBearerContext", permission);
            }

            // 4. Require exactly one authenticated ClaimsIdentity (reject ambiguous/multi-identity principals)
            var authenticatedIdentities = authResult.Principal.Identities
                .Where(i => i.IsAuthenticated)
                .ToList();

            if (authenticatedIdentities.Count != 1)
            {
                return PlatformGrantResolutionResult.Deny("AmbiguousAuthenticatedIdentities", permission);
            }

            var identity = authenticatedIdentities[0];
            if (string.IsNullOrWhiteSpace(identity.AuthenticationType))
            {
                return PlatformGrantResolutionResult.Deny("UnauthenticatedBearerContext", permission);
            }

            // 5. Extract and validate non-ambiguous identity claims from that single identity only
            if (!TryGetSingleGuidClaim(identity, out userId, ClaimTypes.NameIdentifier, JwtRegisteredClaimNames.Sub, "sub"))
            {
                return PlatformGrantResolutionResult.Deny("InvalidOrAmbiguousUserClaim", permission);
            }

            if (!TryGetSingleGuidClaim(identity, out var sessionId, JwtRegisteredClaimNames.Sid, "sid"))
            {
                return PlatformGrantResolutionResult.Deny("InvalidOrAmbiguousSessionClaim", permission);
            }

            if (!TryGetSingleStringClaim(identity, "sst", out var securityStamp))
            {
                return PlatformGrantResolutionResult.Deny("InvalidOrAmbiguousSecurityStampClaim", permission);
            }

            // 6. Verify current authoritative User eligibility and SecurityStamp (no stale cache)
            var user = await _dbContext.Users
                .AsNoTracking()
                .Where(u => u.Id == userId)
                .Select(u => new { u.Id, u.Status, u.SecurityStamp })
                .FirstOrDefaultAsync(cancellationToken);

            if (user is null || user.Status != UserStatus.Active || !FixedTimeEquals(user.SecurityStamp, securityStamp))
            {
                _logger.LogWarning("Platform grant resolution denied: ineligible user or security stamp mismatch for User {UserId}.", userId);
                return PlatformGrantResolutionResult.Deny("IneligibleAccountOrSecurityStampMismatch", permission);
            }

            // 7. Verify current authoritative UserSession validity (belongs to user, not revoked, not expired)
            var utcNow = _timeProvider.GetUtcNow().UtcDateTime;
            var session = await _dbContext.UserSessions
                .AsNoTracking()
                .Where(s => s.Id == sessionId)
                .Select(s => new { s.Id, s.UserId, s.RevokedAtUtc, s.ExpiresAtUtc })
                .FirstOrDefaultAsync(cancellationToken);

            if (session is null ||
                session.UserId != userId ||
                session.RevokedAtUtc is not null ||
                session.ExpiresAtUtc <= utcNow)
            {
                _logger.LogWarning("Platform grant resolution denied: invalid, revoked, or expired session {SessionId} for User {UserId}.", sessionId, userId);
                return PlatformGrantResolutionResult.Deny("InvalidOrExpiredSession", permission);
            }

            // 8. Query current authoritative Active PlatformRoleGrants for this User (global scope)
            var activeGrants = await _dbContext.PlatformRoleGrants
                .AsNoTracking()
                .Where(g => g.UserId == userId && g.Status == PlatformRoleGrantStatus.Active)
                .Take(2)
                .ToListAsync(cancellationToken);

            if (activeGrants.Count == 0)
            {
                return PlatformGrantResolutionResult.Deny("NoActivePlatformGrant", permission);
            }

            if (activeGrants.Count > 1)
            {
                _logger.LogError("Platform grant resolution integrity anomaly: multiple active platform grants found for User {UserId}.", userId);
                return PlatformGrantResolutionResult.Deny("AmbiguousActivePlatformGrants", permission);
            }

            var grant = activeGrants[0];
            if (!Enum.IsDefined(grant.Role) || !PlatformRolePermissionMap.CanAuthorize(grant, permission))
            {
                return PlatformGrantResolutionResult.Deny("PermissionNotGranted", permission);
            }

            return PlatformGrantResolutionResult.Allow(userId, grant.Id, grant.Role, permission);
        }
        catch (OperationCanceledException)
        {
            throw;
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Platform grant resolution failed closed due to infrastructure error for User {UserId}.", userId);
            return PlatformGrantResolutionResult.Deny("InfrastructureFailure", permission);
        }
    }

    private static bool TryGetSingleGuidClaim(ClaimsIdentity identity, out Guid value, params string[] claimTypes)
    {
        value = Guid.Empty;
        var matchedClaims = identity.Claims
            .Where(c => claimTypes.Contains(c.Type, StringComparer.Ordinal))
            .Select(c => c.Value)
            .ToList();

        if (matchedClaims.Count == 0)
        {
            return false;
        }

        foreach (var type in claimTypes)
        {
            if (identity.Claims.Count(c => string.Equals(c.Type, type, StringComparison.Ordinal)) > 1)
            {
                return false;
            }
        }

        var distinctValues = matchedClaims.Distinct(StringComparer.Ordinal).ToList();
        if (distinctValues.Count != 1)
        {
            return false;
        }

        return Guid.TryParse(distinctValues[0], out value) && value != Guid.Empty;
    }

    private static bool TryGetSingleStringClaim(ClaimsIdentity identity, string claimType, out string value)
    {
        value = string.Empty;
        var matched = identity.Claims
            .Where(c => string.Equals(c.Type, claimType, StringComparison.Ordinal))
            .ToList();

        if (matched.Count != 1 || string.IsNullOrWhiteSpace(matched[0].Value))
        {
            return false;
        }

        value = matched[0].Value.Trim();
        return true;
    }

    private static bool FixedTimeEquals(string a, string b)
    {
        var bytesA = Encoding.UTF8.GetBytes(a);
        var bytesB = Encoding.UTF8.GetBytes(b);
        return CryptographicOperations.FixedTimeEquals(bytesA, bytesB);
    }
}

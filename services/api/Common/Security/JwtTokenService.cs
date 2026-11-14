namespace MaintenX.Api.Common.Security;

using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using MaintenX.Api.Configuration;
using MaintenX.Api.Domain.Auth;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;

/// <summary>
/// Thread-safe service for issuing JWT access tokens strictly configured with active key ring credentials,
/// 15-minute token lifetime, and mandatory identity claims (sub, sid, sst, jti).
/// </summary>
public sealed class JwtTokenService : IJwtTokenService
{
    private readonly IJwtKeyRing _keyRing;
    private readonly IOptions<JwtOptions> _options;
    private readonly TimeProvider _timeProvider;
    private readonly JwtSecurityTokenHandler _tokenHandler;

    public JwtTokenService(
        IJwtKeyRing keyRing,
        IOptions<JwtOptions> options,
        TimeProvider? timeProvider = null)
    {
        _keyRing = keyRing ?? throw new ArgumentNullException(nameof(keyRing));
        _options = options ?? throw new ArgumentNullException(nameof(options));
        _timeProvider = timeProvider ?? TimeProvider.System;
        _tokenHandler = new JwtSecurityTokenHandler
        {
            SetDefaultTimesOnTokenCreation = false
        };
    }

    /// <inheritdoc />
    public AccessTokenResult GenerateAccessToken(User user, UserSession session)
    {
        ArgumentNullException.ThrowIfNull(user);
        ArgumentNullException.ThrowIfNull(session);

        if (string.IsNullOrWhiteSpace(user.SecurityStamp))
        {
            throw new InvalidOperationException($"User '{user.Id}' does not have a valid security stamp configured.");
        }

        return GenerateAccessToken(user.Id, session.Id, user.SecurityStamp);
    }

    /// <inheritdoc />
    public AccessTokenResult GenerateAccessToken(Guid userId, Guid sessionId, string securityStamp)
    {
        if (userId == Guid.Empty)
        {
            throw new ArgumentException("User ID cannot be empty.", nameof(userId));
        }

        if (sessionId == Guid.Empty)
        {
            throw new ArgumentException("Session ID cannot be empty.", nameof(sessionId));
        }

        ArgumentException.ThrowIfNullOrWhiteSpace(securityStamp);

        var jwtOptions = _options.Value;
        if (string.IsNullOrWhiteSpace(jwtOptions.Issuer))
        {
            throw new InvalidOperationException("JWT Issuer is not configured.");
        }

        if (string.IsNullOrWhiteSpace(jwtOptions.Audience))
        {
            throw new InvalidOperationException("JWT Audience is not configured.");
        }

        var lifetimeMinutes = jwtOptions.AccessTokenLifetimeMinutes > 0
            ? jwtOptions.AccessTokenLifetimeMinutes
            : 15;

        var issuedAt = _timeProvider.GetUtcNow();
        var expiresAt = issuedAt.AddMinutes(lifetimeMinutes);
        var jti = Guid.NewGuid().ToString("D");

        var claims = new[]
        {
            new Claim(JwtRegisteredClaimNames.Sub, userId.ToString("D")),
            new Claim("sid", sessionId.ToString("D")),
            new Claim("sst", securityStamp.Trim()),
            new Claim(JwtRegisteredClaimNames.Jti, jti)
        };

        var tokenDescriptor = new SecurityTokenDescriptor
        {
            Issuer = jwtOptions.Issuer,
            Audience = jwtOptions.Audience,
            Subject = new ClaimsIdentity(claims),
            NotBefore = issuedAt.UtcDateTime,
            IssuedAt = issuedAt.UtcDateTime,
            Expires = expiresAt.UtcDateTime,
            SigningCredentials = _keyRing.CreateSigningCredentials()
        };

        var securityToken = _tokenHandler.CreateJwtSecurityToken(tokenDescriptor);
        var tokenString = _tokenHandler.WriteToken(securityToken);

        return new AccessTokenResult(tokenString, expiresAt.UtcDateTime, jti);
    }

    /// <summary>
    /// Strictly redacts key material from diagnostic representations.
    /// </summary>
    public override string ToString() => $"JwtTokenService [ActiveKid='{_keyRing.ActiveKeyId}']";
}

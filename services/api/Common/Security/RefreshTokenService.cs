namespace MaintenX.Api.Common.Security;

using System.Buffers.Text;
using System.Security.Cryptography;
using System.Text;
using MaintenX.Api.Domain.Auth;

/// <summary>
/// Thread-safe service implementing cryptographic refresh token generation, SHA-256 lowercase hex hashing,
/// and entity instantiation honoring the 7-day nominal and session-capped expiration boundaries.
/// </summary>
public sealed class RefreshTokenService : IRefreshTokenService
{
    private readonly TimeProvider _timeProvider;
    private static readonly TimeSpan NominalLifetime = TimeSpan.FromDays(7);

    /// <inheritdoc />
    public TimeSpan DefaultLifetime => NominalLifetime;

    public RefreshTokenService(TimeProvider? timeProvider = null)
    {
        _timeProvider = timeProvider ?? TimeProvider.System;
    }

    /// <inheritdoc />
    public GeneratedRefreshToken GenerateToken()
    {
        // Generate 64 cryptographically secure random bytes
        var bytes = new byte[64];
        RandomNumberGenerator.Fill(bytes);

        // Encode using URL-safe Base64 without padding for client delivery
        var rawToken = Base64Url.EncodeToString(bytes);
        var tokenHash = HashToken(rawToken);

        return new GeneratedRefreshToken(rawToken, tokenHash);
    }

    /// <inheritdoc />
    public string HashToken(string rawToken)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(rawToken);

        var utf8Bytes = Encoding.UTF8.GetBytes(rawToken.Trim());
        var hashBytes = SHA256.HashData(utf8Bytes);
        return Convert.ToHexString(hashBytes).ToLowerInvariant();
    }

    /// <inheritdoc />
    public RefreshToken CreateRefreshTokenEntity(UserSession session, string tokenHash, DateTime? utcNow = null)
    {
        ArgumentNullException.ThrowIfNull(session);
        var now = utcNow ?? _timeProvider.GetUtcNow().UtcDateTime;

        return RefreshToken.Create(session, tokenHash, now, DefaultLifetime);
    }

    /// <inheritdoc />
    public RefreshToken CreateRefreshTokenEntity(
        Guid sessionId,
        string tokenHash,
        DateTime sessionExpiresAtUtc,
        TimeSpan? lifetime = null,
        DateTime? utcNow = null)
    {
        var now = utcNow ?? _timeProvider.GetUtcNow().UtcDateTime;
        var effectiveLifetime = lifetime ?? DefaultLifetime;

        return RefreshToken.Create(sessionId, tokenHash, now, effectiveLifetime, sessionExpiresAtUtc);
    }

    /// <summary>
    /// Redacts all sensitive details from string representation.
    /// </summary>
    public override string ToString() => "RefreshTokenService [64-byte CSPRNG, SHA-256 Digest]";
}

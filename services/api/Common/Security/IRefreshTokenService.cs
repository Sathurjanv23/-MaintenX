namespace MaintenX.Api.Common.Security;

using MaintenX.Api.Domain.Auth;

/// <summary>
/// Provides cryptographically secure refresh token generation, SHA-256 hashing,
/// and entity instantiation complying with approved 7-day and session-capped expiration policies.
/// </summary>
public interface IRefreshTokenService
{
    /// <summary>
    /// Nominal refresh token duration (7 days).
    /// </summary>
    TimeSpan DefaultLifetime { get; }

    /// <summary>
    /// Generates 64 cryptographically secure random bytes, returning the raw URL-safe token
    /// and its SHA-256 lowercase hexadecimal digest.
    /// </summary>
    /// <returns>A <see cref="GeneratedRefreshToken"/> containing raw and hashed values.</returns>
    GeneratedRefreshToken GenerateToken();

    /// <summary>
    /// Computes the deterministic SHA-256 lowercase hexadecimal digest of a raw refresh token string.
    /// </summary>
    /// <param name="rawToken">The raw refresh token provided by the client.</param>
    /// <returns>A 64-character lowercase hex string matching SHA-256 digest format.</returns>
    string HashToken(string rawToken);

    /// <summary>
    /// Creates a validated <see cref="RefreshToken"/> domain entity for a session,
    /// enforcing that token expiration is capped at the parent session's absolute expiry.
    /// </summary>
    /// <param name="session">The parent user session entity.</param>
    /// <param name="tokenHash">The SHA-256 lowercase hex digest of the refresh token.</param>
    /// <param name="utcNow">Optional creation timestamp; defaults to current UTC time.</param>
    /// <returns>A validated <see cref="RefreshToken"/> entity.</returns>
    RefreshToken CreateRefreshTokenEntity(UserSession session, string tokenHash, DateTime? utcNow = null);

    /// <summary>
    /// Creates a validated <see cref="RefreshToken"/> domain entity with explicit lifetime,
    /// enforcing that token expiration is capped at the parent session's absolute expiry.
    /// </summary>
    /// <param name="sessionId">Parent session identifier.</param>
    /// <param name="tokenHash">The SHA-256 lowercase hex digest of the refresh token.</param>
    /// <param name="sessionExpiresAtUtc">The absolute expiration timestamp of the parent session.</param>
    /// <param name="lifetime">Optional custom token lifetime; defaults to 7 days if null.</param>
    /// <param name="utcNow">Optional creation timestamp; defaults to current UTC time.</param>
    /// <returns>A validated <see cref="RefreshToken"/> entity.</returns>
    RefreshToken CreateRefreshTokenEntity(
        Guid sessionId,
        string tokenHash,
        DateTime sessionExpiresAtUtc,
        TimeSpan? lifetime = null,
        DateTime? utcNow = null);
}

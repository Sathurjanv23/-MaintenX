namespace MaintenX.Api.Common.Security;

using Microsoft.IdentityModel.Tokens;

/// <summary>
/// Manages the active cryptographic signing key and verification key ring for JWT issuance and signature validation.
/// </summary>
public interface IJwtKeyRing
{
    /// <summary>
    /// Active Key ID (kid) identifying the primary key used to sign new access tokens.
    /// </summary>
    string ActiveKeyId { get; }

    /// <summary>
    /// Active symmetric key used to sign new access tokens.
    /// </summary>
    SecurityKey ActiveSigningKey { get; }

    /// <summary>
    /// Creates signing credentials for token issuance using HMAC-SHA256 and the active Key ID.
    /// </summary>
    SigningCredentials CreateSigningCredentials();

    /// <summary>
    /// Attempts to resolve a security key matching the given Key ID (kid) from the primary key or verification ring.
    /// </summary>
    /// <param name="kid">Key ID from the JWT header.</param>
    /// <param name="key">Resolved SecurityKey, or null if unknown.</param>
    /// <returns>True if the key ID is recognized; otherwise false.</returns>
    bool TryGetKey(string? kid, out SecurityKey? key);

    /// <summary>
    /// Retrieves all valid keys currently in the verification ring (active key plus unexpired retired keys).
    /// </summary>
    IEnumerable<SecurityKey> GetAllKeys();

    /// <summary>
    /// Retires an existing key by moving it into the retired verification ring with an explicit retirement timestamp.
    /// </summary>
    /// <param name="kid">Key ID of the key to retire.</param>
    /// <param name="keyMaterialBase64">Base64-encoded key material.</param>
    /// <param name="retiredAtUtc">Optional UTC timestamp of retirement; defaults to current time if null.</param>
    void RetireKey(string kid, string keyMaterialBase64, DateTimeOffset? retiredAtUtc = null);

    /// <summary>
    /// Checks whether a retired key has completed its mandatory retention period and can safely be purged.
    /// </summary>
    /// <param name="kid">Key ID to check.</param>
    /// <param name="remainingRetention">Remaining retention time if not yet eligible.</param>
    /// <returns>True if the key has exceeded the retention period and can be purged; otherwise false.</returns>
    bool CanPurgeKey(string kid, out TimeSpan remainingRetention);

    /// <summary>
    /// Attempts to purge a retired key from the key ring.
    /// Fails if the key is active, unknown, or if the 24-hour retention period has not elapsed.
    /// </summary>
    /// <param name="kid">Key ID of the retired key to purge.</param>
    /// <param name="failureReason">Description of why purge failed, or null on success.</param>
    /// <returns>True if the key was purged; otherwise false.</returns>
    bool TryPurgeRetiredKey(string kid, out string? failureReason);

    /// <summary>
    /// Gets metadata on all currently tracked retired keys.
    /// </summary>
    IReadOnlyCollection<RetiredKeyInfo> GetRetiredKeys();
}

/// <summary>
/// Information regarding a retired verification key and its retention lifecycle.
/// </summary>
public sealed record RetiredKeyInfo(
    string KeyId,
    DateTimeOffset RetiredAtUtc,
    DateTimeOffset ExpiresAtUtc,
    bool IsExpired);


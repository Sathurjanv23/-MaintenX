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
    /// Retrieves all valid keys currently in the verification ring (active key plus retired keys).
    /// </summary>
    IEnumerable<SecurityKey> GetAllKeys();
}


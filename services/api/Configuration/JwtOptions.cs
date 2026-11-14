namespace MaintenX.Api.Configuration;

/// <summary>
/// Strongly typed configuration options for JSON Web Token (JWT) authentication and signing key ring.
/// </summary>
public sealed class JwtOptions
{
    public const string SectionName = "Jwt";

    /// <summary>
    /// Expected issuer claim (iss) of the JWT.
    /// </summary>
    public string Issuer { get; set; } = string.Empty;

    /// <summary>
    /// Expected audience claim (aud) of the JWT.
    /// </summary>
    public string Audience { get; set; } = string.Empty;

    /// <summary>
    /// Active Key ID (kid) header identifying the primary signing key in the key ring.
    /// </summary>
    public string KeyId { get; set; } = string.Empty;

    /// <summary>
    /// Base64-encoded primary symmetric signing key containing at least 256 bits (32 decoded bytes).
    /// </summary>
    public string SigningKey { get; set; } = string.Empty;

    /// <summary>
    /// Access token lifetime in minutes. Strictly configured to 15 minutes by default.
    /// </summary>
    public int AccessTokenLifetimeMinutes { get; set; } = 15;

    /// <summary>
    /// Additional verification keys for zero-downtime key rotation.
    /// Key ID (kid) to Base64-encoded symmetric key material.
    /// Tokens signed by these keys remain valid for signature verification during the rotation window.
    /// </summary>
    public Dictionary<string, string> VerificationKeys { get; set; } = new(StringComparer.Ordinal);

    /// <summary>
    /// Override ToString to guarantee signing keys and secret material are never printed in logs or diagnostic dumps.
    /// </summary>
    public override string ToString() =>
        $"JwtOptions {{ Issuer: '{Issuer}', Audience: '{Audience}', KeyId: '{KeyId}', Lifetime: {AccessTokenLifetimeMinutes}m, VerificationKeyCount: {VerificationKeys.Count} }}";
}


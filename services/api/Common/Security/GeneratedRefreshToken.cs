namespace MaintenX.Api.Common.Security;

/// <summary>
/// Represents the result of generating a new cryptographically secure refresh token.
/// Contains the raw token string intended exclusively for transmission to the client,
/// and the SHA-256 lowercase hex digest for database persistence and lookup.
/// </summary>
public sealed record GeneratedRefreshToken(
    string RawToken,
    string TokenHash)
{
    /// <summary>
    /// Strictly redacts raw token and token hash from string representation to prevent leakage in diagnostic logs.
    /// </summary>
    public override string ToString() => "GeneratedRefreshToken [REDACTED]";
}

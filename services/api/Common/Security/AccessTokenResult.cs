namespace MaintenX.Api.Common.Security;

/// <summary>
/// Encapsulates the result of issuing a JSON Web Token (JWT) access token,
/// including the signed compact token string, expiration timestamp, and unique JWT identifier (jti).
/// </summary>
public sealed record AccessTokenResult(
    string Token,
    DateTime ExpiresAtUtc,
    string Jti)
{
    /// <summary>
    /// Strictly redacts raw token from string representation to prevent token leakage in diagnostic logs.
    /// </summary>
    public override string ToString() => $"AccessTokenResult [ExpiresAtUtc={ExpiresAtUtc:O}, Jti={Jti}, Token=[REDACTED]]";
}

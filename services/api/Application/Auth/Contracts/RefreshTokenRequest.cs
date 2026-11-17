namespace MaintenX.Api.Application.Auth.Contracts;

/// <summary>
/// Request payload for token rotation.
/// </summary>
/// <param name="RefreshToken">The current opaque single-use refresh token string.</param>
public sealed record RefreshTokenRequest(string RefreshToken)
{
    /// <summary>
    /// Redacts refresh token in string representations and logs.
    /// </summary>
    public override string ToString() =>
        "RefreshTokenRequest [RefreshToken=[REDACTED]]";
}

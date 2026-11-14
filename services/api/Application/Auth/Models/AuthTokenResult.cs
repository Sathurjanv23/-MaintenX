namespace MaintenX.Api.Application.Auth.Models;

/// <summary>
/// Encapsulates authentication tokens issued to a client upon successful login or refresh token rotation.
/// </summary>
public sealed record AuthTokenResult(
    string AccessToken,
    string RefreshToken,
    DateTime AccessTokenExpiresAtUtc,
    DateTime RefreshTokenExpiresAtUtc,
    Guid SessionId)
{
    /// <summary>
    /// Strictly redacts sensitive tokens from diagnostic string representations.
    /// </summary>
    public override string ToString() =>
        $"AuthTokenResult [SessionId={SessionId}, AccessTokenExpiresAtUtc={AccessTokenExpiresAtUtc:O}, RefreshTokenExpiresAtUtc={RefreshTokenExpiresAtUtc:O}, AccessToken=[REDACTED], RefreshToken=[REDACTED]]";
}

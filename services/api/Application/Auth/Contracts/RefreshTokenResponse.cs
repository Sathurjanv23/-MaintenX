namespace MaintenX.Api.Application.Auth.Contracts;

/// <summary>
/// Response payload for successful refresh token rotation containing rotated access and refresh tokens.
/// </summary>
/// <param name="AccessToken">Newly issued cryptographically signed JWT Bearer access token.</param>
/// <param name="RefreshToken">Newly issued opaque single-use refresh token string.</param>
/// <param name="ExpiresInSeconds">Lifetime of the access token in seconds.</param>
/// <param name="TokenType">Token scheme type (defaults to 'Bearer').</param>
/// <param name="SessionId">Unique persistent session identifier associated with this token pair.</param>
public sealed record RefreshTokenResponse(
    string AccessToken,
    string RefreshToken,
    int ExpiresInSeconds,
    string TokenType,
    Guid SessionId)
{
    /// <summary>
    /// Redacts access and refresh tokens in string representations and logs.
    /// </summary>
    public override string ToString() =>
        $"RefreshTokenResponse [TokenType={TokenType}, ExpiresInSeconds={ExpiresInSeconds}, SessionId={SessionId}, AccessToken=[REDACTED], RefreshToken=[REDACTED]]";
}

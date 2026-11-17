namespace MaintenX.Api.Application.Auth.Contracts;

/// <summary>
/// Response payload for successful user authentication containing access and refresh tokens.
/// </summary>
/// <param name="AccessToken">Cryptographically signed JWT Bearer access token.</param>
/// <param name="RefreshToken">Opaque, single-use cryptographically strong refresh token string.</param>
/// <param name="ExpiresInSeconds">Lifetime of the access token in seconds.</param>
/// <param name="TokenType">Token scheme type (defaults to 'Bearer').</param>
/// <param name="SessionId">Unique persistent session identifier associated with this token pair.</param>
public sealed record LoginResponse(
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
        $"LoginResponse [TokenType={TokenType}, ExpiresInSeconds={ExpiresInSeconds}, SessionId={SessionId}, AccessToken=[REDACTED], RefreshToken=[REDACTED]]";
}

namespace MaintenX.Api.Common.Security;

using MaintenX.Api.Domain.Auth;

/// <summary>
/// Issues cryptographically signed JSON Web Token (JWT) access tokens using the active key ring
/// and authoritative security options.
/// </summary>
public interface IJwtTokenService
{
    /// <summary>
    /// Generates a signed 15-minute JWT access token for an authenticated user session.
    /// </summary>
    /// <param name="user">The authenticated user entity.</param>
    /// <param name="session">The active user session.</param>
    /// <returns>An <see cref="AccessTokenResult"/> containing the signed compact JWT string and metadata.</returns>
    AccessTokenResult GenerateAccessToken(User user, UserSession session);

    /// <summary>
    /// Generates a signed 15-minute JWT access token from discrete identity claims.
    /// </summary>
    /// <param name="userId">Unique identifier of the user.</param>
    /// <param name="sessionId">Unique identifier of the user session.</param>
    /// <param name="securityStamp">Current security stamp of the user.</param>
    /// <returns>An <see cref="AccessTokenResult"/> containing the signed compact JWT string and metadata.</returns>
    AccessTokenResult GenerateAccessToken(Guid userId, Guid sessionId, string securityStamp);
}

namespace MaintenX.Api.Application.Auth.Services;

using MaintenX.Api.Application.Auth.Models;

/// <summary>
/// Core application service coordinating user registration, credential authentication,
/// session lifecycle management, refresh-token rotation, and transactional security audit durability.
/// </summary>
public interface IAuthenticationService
{
    /// <summary>
    /// Registers a new user account with timing-attack mitigation and uniform response formatting.
    /// </summary>
    /// <param name="email">Candidate user email address.</param>
    /// <param name="password">Plaintext password satisfying length invariants.</param>
    /// <param name="clientIp">Connecting client IP address, or null if unavailable.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>A generic <see cref="RegistrationResult"/> preventing account enumeration.</returns>
    Task<RegistrationResult> RegisterAsync(
        string email,
        string password,
        string? clientIp = null,
        CancellationToken cancellationToken = default);

    /// <summary>
    /// Authenticates user credentials with out-of-lock PBKDF2 hashing, constant-time dummy verification,
    /// snapshot revalidation, rolling 15-minute failure tracking, and session issuance.
    /// </summary>
    /// <param name="email">User email address.</param>
    /// <param name="password">Plaintext password provided during login.</param>
    /// <param name="clientIp">Connecting client IP address, or null if unavailable.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>A <see cref="LoginResult"/> indicating success, invalid credentials, or account lockout.</returns>
    Task<LoginResult> LoginAsync(
        string email,
        string password,
        string? clientIp = null,
        CancellationToken cancellationToken = default);

    /// <summary>
    /// Atomically rotates an active refresh token, issuing a new access and refresh token pair.
    /// Enforces strict lock ordering (Session -> RefreshToken) and immediate replay detection precedence.
    /// </summary>
    /// <param name="rawRefreshToken">Raw client refresh token.</param>
    /// <param name="clientIp">Connecting client IP address, or null if unavailable.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>A <see cref="RefreshTokenResult"/> with new tokens or replay detection outcome.</returns>
    Task<RefreshTokenResult> RefreshTokenAsync(
        string rawRefreshToken,
        string? clientIp = null,
        CancellationToken cancellationToken = default);

    /// <summary>
    /// Idempotently terminates a user session and revokes all associated child refresh tokens.
    /// Verifies session ownership if a caller user identity is supplied.
    /// </summary>
    /// <param name="sessionId">Identifier of the session to terminate.</param>
    /// <param name="callerUserId">Optional identifier of the authenticated caller for ownership verification.</param>
    /// <param name="clientIp">Connecting client IP address, or null if unavailable.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>A <see cref="LogoutResult"/> indicating outcome.</returns>
    Task<LogoutResult> LogoutAsync(
        Guid sessionId,
        Guid? callerUserId = null,
        string? clientIp = null,
        CancellationToken cancellationToken = default);

    /// <summary>
    /// Authenticated self-service password change. Verifies current password out-of-lock,
    /// rotates the security stamp, revokes all active sessions, and evicts local cache.
    /// </summary>
    /// <param name="userId">Unique user identifier.</param>
    /// <param name="currentPassword">Current plaintext password.</param>
    /// <param name="newPassword">New plaintext password satisfying length invariants.</param>
    /// <param name="clientIp">Connecting client IP address, or null if unavailable.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>A <see cref="PasswordMutationResult"/>.</returns>
    Task<PasswordMutationResult> ChangePasswordAsync(
        Guid userId,
        string currentPassword,
        string newPassword,
        string? clientIp = null,
        CancellationToken cancellationToken = default);

    /// <summary>
    /// Authorized password reset executed by a verified administrative or recovery process.
    /// Rotates security stamp, revokes all active sessions, and evicts local cache.
    /// </summary>
    /// <param name="userId">Unique user identifier.</param>
    /// <param name="newPassword">New plaintext password satisfying length invariants.</param>
    /// <param name="clientIp">Connecting client IP address, or null if unavailable.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>A <see cref="PasswordMutationResult"/>.</returns>
    Task<PasswordMutationResult> AuthorizedResetPasswordAsync(
        Guid userId,
        string newPassword,
        string? clientIp = null,
        CancellationToken cancellationToken = default);
}

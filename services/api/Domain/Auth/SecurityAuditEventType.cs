namespace MaintenX.Api.Domain.Auth;

/// <summary>
/// Categorized security and authentication event types for structured security audit logging.
/// </summary>
public enum SecurityAuditEventType
{
    /// <summary>
    /// User account was created / registered.
    /// </summary>
    UserRegistered = 1,

    /// <summary>
    /// Successful user authentication and session establishment.
    /// </summary>
    LoginSuccess = 2,

    /// <summary>
    /// Failed authentication attempt (invalid credentials).
    /// </summary>
    LoginFailed = 3,

    /// <summary>
    /// Account lockout triggered due to repeated failed authentication attempts.
    /// </summary>
    AccountLockedOut = 4,

    /// <summary>
    /// Refresh token rotated successfully to issue new access and refresh tokens.
    /// </summary>
    TokenRefreshed = 5,

    /// <summary>
    /// Replay of an already-rotated refresh token detected. Triggers immediate session revocation.
    /// </summary>
    TokenReplayDetected = 6,

    /// <summary>
    /// Explicit user session revocation (e.g. user logout, admin action).
    /// </summary>
    SessionRevoked = 7,

    /// <summary>
    /// User password changed or reset.
    /// </summary>
    PasswordChanged = 8,

    /// <summary>
    /// User security stamp rotated to invalidate concurrent sessions.
    /// </summary>
    SecurityStampRotated = 9,

    /// <summary>
    /// User account was administratively suspended.
    /// </summary>
    UserSuspended = 10,

    /// <summary>
    /// User account was reactivated from suspended state.
    /// </summary>
    UserReactivated = 11,

    /// <summary>
    /// User account was permanently deactivated.
    /// </summary>
    UserDeactivated = 12
}

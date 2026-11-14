namespace MaintenX.Api.Domain.Auth;

/// <summary>
/// Operational and authentication lifecycle status of a user account.
/// </summary>
public enum UserStatus
{
    /// <summary>
    /// User account has been registered but email address has not yet been confirmed.
    /// </summary>
    PendingVerification = 1,

    /// <summary>
    /// User account is active and permitted to authenticate.
    /// </summary>
    Active = 2,

    /// <summary>
    /// User account is administratively suspended. Cannot authenticate or refresh sessions.
    /// </summary>
    Suspended = 3,

    /// <summary>
    /// User account is permanently deactivated.
    /// </summary>
    Deactivated = 4
}

namespace MaintenX.Api.Domain.Auth;

/// <summary>
/// Operational and authentication lifecycle status of a user account.
/// </summary>
public enum UserStatus
{
    /// <summary>
    /// User account is active and permitted to authenticate.
    /// </summary>
    Active = 1,

    /// <summary>
    /// User account is administratively suspended. Cannot authenticate or refresh sessions.
    /// </summary>
    Suspended = 2,

    /// <summary>
    /// User account is permanently deactivated.
    /// </summary>
    Deactivated = 3
}

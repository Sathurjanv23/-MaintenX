namespace MaintenX.Api.Domain.Authorization;

/// <summary>
/// Lifecycle status of a <see cref="PlatformRoleGrant"/>.
/// </summary>
public enum PlatformRoleGrantStatus
{
    /// <summary>
    /// Grant is currently active and eligible for platform-level authorization.
    /// </summary>
    Active = 1,

    /// <summary>
    /// Grant has been permanently revoked. Terminal state; re-granting requires a new grant record.
    /// </summary>
    Revoked = 2
}

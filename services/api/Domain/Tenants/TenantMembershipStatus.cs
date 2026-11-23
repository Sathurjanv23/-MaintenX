namespace MaintenX.Api.Domain.Tenants;

/// <summary>
/// Operational and access lifecycle status of a user's membership within a tenant organization.
/// </summary>
public enum TenantMembershipStatus
{
    /// <summary>
    /// Membership has been provisioned or invited, but onboarding or user acceptance is pending.
    /// </summary>
    Pending = 1,

    /// <summary>
    /// Membership is active and authorized to access tenant resources.
    /// </summary>
    Active = 2,

    /// <summary>
    /// Membership is temporarily suspended (e.g. administrative hold, organizational review).
    /// Access to the tenant is denied while suspended.
    /// </summary>
    Suspended = 3,

    /// <summary>
    /// Membership has been revoked/deactivated. This is a terminal state.
    /// </summary>
    Revoked = 4
}

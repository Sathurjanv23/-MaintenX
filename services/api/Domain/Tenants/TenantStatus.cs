namespace MaintenX.Api.Domain.Tenants;

/// <summary>
/// Represents the lifecycle and operational status of a tenant organization in the platform.
/// </summary>
public enum TenantStatus
{
    /// <summary>
    /// Tenant is active and fully operational.
    /// </summary>
    Active = 1,

    /// <summary>
    /// Tenant operations and user access are temporarily suspended (e.g. billing, administrative hold).
    /// </summary>
    Suspended = 2,

    /// <summary>
    /// Tenant has been provisioned in the catalogue but has not completed initial onboarding.
    /// </summary>
    PendingOnboarding = 3,

    /// <summary>
    /// Tenant is permanently deactivated.
    /// </summary>
    Deactivated = 4
}

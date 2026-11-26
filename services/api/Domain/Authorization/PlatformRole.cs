namespace MaintenX.Api.Domain.Authorization;

/// <summary>
/// Authoritative global platform roles, strictly separated from tenant-level <see cref="MaintenX.Api.Domain.Tenants.TenantMembershipRole"/>.
/// </summary>
public enum PlatformRole
{
    /// <summary>
    /// Global platform administrator authorized to review, activate, suspend, and deactivate tenant organizations.
    /// Does not automatically grant access to tenant business data.
    /// </summary>
    PlatformAdministrator = 1
}

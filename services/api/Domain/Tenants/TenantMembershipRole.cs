namespace MaintenX.Api.Domain.Tenants;

/// <summary>
/// Foundational membership role of a user within a tenant organization for FEAT-003.
/// Establishes minimal organizational hierarchy (Owner, Administrator, Member) without
/// defining the comprehensive fine-grained RBAC permission matrix (deferred to FEAT-004).
/// </summary>
public enum TenantMembershipRole
{
    /// <summary>
    /// Primary owner of the tenant organization. Full administrative control over tenant settings and memberships.
    /// </summary>
    Owner = 1,

    /// <summary>
    /// Administrator within the tenant organization. Authorized to manage members and operational settings.
    /// </summary>
    Administrator = 2,

    /// <summary>
    /// Regular member of the tenant organization with standard operational access.
    /// </summary>
    Member = 3
}

namespace MaintenX.Api.Domain.Authorization;

/// <summary>
/// Explicit authorization scope boundary separating global platform administration
/// from tenant-specific operational authority.
/// </summary>
public enum AuthorizationScopeKind
{
    /// <summary>
    /// Global platform-level authorization scope (e.g., platform tenant approval and lifecycle governance).
    /// Strictly separated from tenant-level roles.
    /// </summary>
    Platform = 1,

    /// <summary>
    /// Organization-scoped authorization boundary bound to a single specific <c>TenantId</c>.
    /// </summary>
    Tenant = 2
}

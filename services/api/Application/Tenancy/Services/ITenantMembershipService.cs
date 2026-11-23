namespace MaintenX.Api.Application.Tenancy.Services;

using MaintenX.Api.Application.Tenancy.Contracts;
using MaintenX.Api.Application.Tenancy.Models;

/// <summary>
/// Application service contract for querying and managing tenant memberships.
/// Enforces tenant boundaries and prevents cross-tenant membership enumeration.
/// </summary>
public interface ITenantMembershipService
{
    /// <summary>
    /// Retrieves all tenant memberships held by the specified user across organizations.
    /// Safe for workspace switching without leaking other users' memberships.
    /// </summary>
    /// <param name="userId">Identifier of the authenticated user.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>Read-only list of the caller's tenant memberships.</returns>
    Task<IReadOnlyList<UserTenantMembershipResponse>> GetUserMembershipsAsync(
        Guid userId,
        CancellationToken cancellationToken = default);

    /// <summary>
    /// Retrieves a user's membership within a specific tenant organization.
    /// </summary>
    /// <param name="tenantId">Target tenant organization identifier.</param>
    /// <param name="userId">Target user identifier.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>A <see cref="TenantMembershipResult"/> with membership details or not-found outcome.</returns>
    Task<TenantMembershipResult> GetMembershipAsync(
        Guid tenantId,
        Guid userId,
        CancellationToken cancellationToken = default);
}

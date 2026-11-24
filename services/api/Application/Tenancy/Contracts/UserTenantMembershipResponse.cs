namespace MaintenX.Api.Application.Tenancy.Contracts;

/// <summary>
/// Safe application data contract representing a user's membership across tenant organizations.
/// Includes organization metadata for multi-tenant workspace selection without disclosing foreign member lists.
/// </summary>
/// <param name="MembershipId">Unique identifier of the user's membership.</param>
/// <param name="TenantId">Identifier of the tenant organization.</param>
/// <param name="TenantSlug">Normalized URL slug of the organization.</param>
/// <param name="TenantDisplayName">Display name of the organization.</param>
/// <param name="Role">Organizational role held by the authenticated user in this tenant.</param>
/// <param name="Status">Status of the membership in this tenant organization.</param>
/// <param name="TenantStatus">Lifecycle status of the tenant organization.</param>
/// <param name="IsSelectable">Whether this workspace can be actively selected for tenancy session context (both membership and tenant are Active).</param>
/// <param name="CreatedAtUtc">UTC timestamp when the membership was created.</param>
public sealed record UserTenantMembershipResponse(
    Guid MembershipId,
    Guid TenantId,
    string TenantSlug,
    string TenantDisplayName,
    string Role,
    string Status,
    string TenantStatus,
    bool IsSelectable,
    DateTime CreatedAtUtc);

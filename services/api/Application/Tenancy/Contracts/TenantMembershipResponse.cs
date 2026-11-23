namespace MaintenX.Api.Application.Tenancy.Contracts;

/// <summary>
/// Safe application data contract representing a tenant membership record within a tenant context.
/// </summary>
/// <param name="MembershipId">Unique identifier of the membership record.</param>
/// <param name="TenantId">Identifier of the tenant organization.</param>
/// <param name="UserId">Identifier of the member user.</param>
/// <param name="Role">Organizational role assigned to the member (Owner, Administrator, Member).</param>
/// <param name="Status">Operational status of the membership (Pending, Active, Suspended, Revoked).</param>
/// <param name="CreatedAtUtc">UTC timestamp when membership was established.</param>
/// <param name="UpdatedAtUtc">UTC timestamp of most recent membership update.</param>
public sealed record TenantMembershipResponse(
    Guid MembershipId,
    Guid TenantId,
    Guid UserId,
    string Role,
    string Status,
    DateTime CreatedAtUtc,
    DateTime UpdatedAtUtc);

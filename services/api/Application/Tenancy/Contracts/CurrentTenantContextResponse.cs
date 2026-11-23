namespace MaintenX.Api.Application.Tenancy.Contracts;

/// <summary>
/// Data contract returning verified active tenant context information for the authenticated user.
/// </summary>
public sealed record CurrentTenantContextResponse(
    Guid TenantId,
    string TenantSlug,
    string TenantDisplayName,
    Guid UserId,
    Guid MembershipId,
    string Role,
    string Status,
    DateTime ResolvedAtUtc);

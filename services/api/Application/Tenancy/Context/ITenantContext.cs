namespace MaintenX.Api.Application.Tenancy.Context;

using MaintenX.Api.Domain.Tenants;

/// <summary>
/// Exposes strictly verified, immutable tenant context for the current request.
/// Guaranteed to represent an active tenant and an active membership for the authenticated user.
/// </summary>
public interface ITenantContext
{
    /// <summary>
    /// Unique identifier of the verified active tenant.
    /// </summary>
    Guid TenantId { get; }

    /// <summary>
    /// Normalized URL slug of the verified active tenant.
    /// </summary>
    string TenantSlug { get; }

    /// <summary>
    /// Human-readable display name of the verified active tenant.
    /// </summary>
    string TenantDisplayName { get; }

    /// <summary>
    /// Unique identifier of the authenticated user holding the membership.
    /// </summary>
    Guid UserId { get; }

    /// <summary>
    /// Unique identifier of the verified membership record associating the user and tenant.
    /// </summary>
    Guid MembershipId { get; }

    /// <summary>
    /// Organizational membership role of the user within this tenant.
    /// </summary>
    TenantMembershipRole Role { get; }

    /// <summary>
    /// Operational status of the membership (guaranteed to be Active when resolved).
    /// </summary>
    TenantMembershipStatus Status { get; }

    /// <summary>
    /// UTC timestamp marking when this tenant context was securely resolved.
    /// </summary>
    DateTime ResolvedAtUtc { get; }
}

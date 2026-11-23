namespace MaintenX.Api.Application.Tenancy.Context;

using MaintenX.Api.Domain.Tenants;

/// <summary>
/// Immutable implementation of <see cref="ITenantContext"/> representing verified tenant and membership context.
/// </summary>
public sealed class TenantContext : ITenantContext
{
    public Guid TenantId { get; }
    public string TenantSlug { get; }
    public string TenantDisplayName { get; }
    public Guid UserId { get; }
    public Guid MembershipId { get; }
    public TenantMembershipRole Role { get; }
    public TenantMembershipStatus Status { get; }
    public DateTime ResolvedAtUtc { get; }

    public TenantContext(
        Guid tenantId,
        string tenantSlug,
        string tenantDisplayName,
        Guid userId,
        Guid membershipId,
        TenantMembershipRole role,
        TenantMembershipStatus status,
        DateTime resolvedAtUtc)
    {
        if (tenantId == Guid.Empty)
        {
            throw new ArgumentException("TenantId cannot be empty.", nameof(tenantId));
        }

        if (string.IsNullOrWhiteSpace(tenantSlug))
        {
            throw new ArgumentException("TenantSlug cannot be empty or whitespace.", nameof(tenantSlug));
        }

        if (string.IsNullOrWhiteSpace(tenantDisplayName))
        {
            throw new ArgumentException("TenantDisplayName cannot be empty or whitespace.", nameof(tenantDisplayName));
        }

        if (userId == Guid.Empty)
        {
            throw new ArgumentException("UserId cannot be empty.", nameof(userId));
        }

        if (membershipId == Guid.Empty)
        {
            throw new ArgumentException("MembershipId cannot be empty.", nameof(membershipId));
        }

        TenantId = tenantId;
        TenantSlug = tenantSlug.Trim();
        TenantDisplayName = tenantDisplayName.Trim();
        UserId = userId;
        MembershipId = membershipId;
        Role = role;
        Status = status;
        ResolvedAtUtc = resolvedAtUtc;
    }
}

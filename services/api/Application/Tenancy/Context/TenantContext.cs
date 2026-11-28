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

    /// <summary>
    /// Well-known synthetic membership identifier assigned to administrative bypass contexts.
    /// Distinguishes platform administrator bypass access from genuine organizational memberships.
    /// </summary>
    public static readonly Guid AdministrativeBypassMembershipId = Guid.Parse("ffffffff-ffff-ffff-ffff-ffffffffffff");

    /// <summary>
    /// Creates a verified administrative bypass tenant context for an authorized platform administrator.
    /// </summary>
    public static TenantContext CreateAdministrativeBypass(
        Guid tenantId,
        string tenantSlug,
        string tenantDisplayName,
        Guid userId,
        DateTime resolvedAtUtc) =>
        new(
            tenantId,
            tenantSlug,
            tenantDisplayName,
            userId,
            membershipId: AdministrativeBypassMembershipId,
            role: TenantMembershipRole.Owner,
            status: TenantMembershipStatus.Active,
            resolvedAtUtc);

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

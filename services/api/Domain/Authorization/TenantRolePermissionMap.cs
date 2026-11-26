namespace MaintenX.Api.Domain.Authorization;

using System.Collections.Frozen;
using MaintenX.Api.Domain.Tenants;

/// <summary>
/// Immutable domain mapping from <see cref="TenantMembershipRole"/> to approved tenant-scoped permissions
/// in <see cref="PermissionCatalog"/>.
/// <para>
/// Enforces fail-closed, deny-by-default semantics: unknown roles, unknown permissions, and platform-scoped
/// permissions are always denied. Role-level capability eligibility does not replace resource-specific checks
/// (such as last-owner protection or target-role hierarchy) enforced in application services.
/// </para>
/// </summary>
public static class TenantRolePermissionMap
{
    private static readonly FrozenSet<PermissionKey> EmptySet = FrozenSet<PermissionKey>.Empty;
    private static readonly FrozenDictionary<TenantMembershipRole, FrozenSet<PermissionKey>> _roleMappings;

    static TenantRolePermissionMap()
    {
        var ownerPermissions = new[]
        {
            PermissionCatalog.Tenant.MetadataRead,
            PermissionCatalog.Tenant.SettingsUpdate,
            PermissionCatalog.Tenant.MembersRead,
            PermissionCatalog.Tenant.MembersInvite,
            PermissionCatalog.Tenant.MembersRolesAssign,
            PermissionCatalog.Tenant.MembersSuspend,
            PermissionCatalog.Tenant.MembersRestore,
            PermissionCatalog.Tenant.MembersRevoke,
            PermissionCatalog.Tenant.OwnershipTransfer,
            PermissionCatalog.Tenant.AuditRead
        };

        var administratorPermissions = new[]
        {
            PermissionCatalog.Tenant.MetadataRead,
            PermissionCatalog.Tenant.SettingsUpdate,
            PermissionCatalog.Tenant.MembersRead,
            PermissionCatalog.Tenant.MembersInvite,
            PermissionCatalog.Tenant.MembersSuspend,
            PermissionCatalog.Tenant.MembersRestore,
            PermissionCatalog.Tenant.MembersRevoke,
            PermissionCatalog.Tenant.AuditRead
        };

        var memberPermissions = new[]
        {
            PermissionCatalog.Tenant.MetadataRead
        };

        var map = new Dictionary<TenantMembershipRole, FrozenSet<PermissionKey>>
        {
            [TenantMembershipRole.Owner] = BuildValidatedTenantSet(ownerPermissions),
            [TenantMembershipRole.Administrator] = BuildValidatedTenantSet(administratorPermissions),
            [TenantMembershipRole.Member] = BuildValidatedTenantSet(memberPermissions)
        };

        _roleMappings = map.ToFrozenDictionary();
    }

    private static FrozenSet<PermissionKey> BuildValidatedTenantSet(IEnumerable<PermissionKey> keys)
    {
        var set = new HashSet<PermissionKey>();
        foreach (var key in keys)
        {
            if (!PermissionCatalog.IsRegistered(key))
            {
                throw new InvalidOperationException($"Permission '{key.Value}' is not registered in PermissionCatalog.");
            }

            if (key.Scope != AuthorizationScopeKind.Tenant)
            {
                throw new InvalidOperationException($"Platform permission '{key.Value}' cannot be mapped to a tenant role.");
            }

            set.Add(key);
        }

        return set.ToFrozenSet();
    }

    /// <summary>
    /// Returns the immutable set of tenant-scoped permissions eligible for <paramref name="role"/>.
    /// Unknown or undefined enum values fail closed with an empty set.
    /// </summary>
    public static IReadOnlySet<PermissionKey> GetPermissions(TenantMembershipRole role)
    {
        if (!Enum.IsDefined(role) || !_roleMappings.TryGetValue(role, out var permissions))
        {
            return EmptySet;
        }

        return permissions;
    }

    /// <summary>
    /// Evaluates whether <paramref name="role"/> is eligible for <paramref name="permission"/>.
    /// Denies null, unregistered, platform-scoped, and unknown-role queries.
    /// </summary>
    public static bool HasPermission(TenantMembershipRole role, PermissionKey? permission)
    {
        if (permission is null ||
            !Enum.IsDefined(role) ||
            permission.Scope != AuthorizationScopeKind.Tenant ||
            !PermissionCatalog.IsRegistered(permission))
        {
            return false;
        }

        return _roleMappings.TryGetValue(role, out var permissions) && permissions.Contains(permission);
    }

    /// <summary>
    /// Evaluates whether <paramref name="role"/> is eligible for the canonical identifier <paramref name="rawPermission"/>.
    /// Denies null, empty, malformed, wildcard, unregistered, platform-scoped, and unknown-role queries.
    /// </summary>
    public static bool HasPermission(TenantMembershipRole role, string? rawPermission)
        => PermissionKey.TryParse(rawPermission, out var permission) && HasPermission(role, permission);
}

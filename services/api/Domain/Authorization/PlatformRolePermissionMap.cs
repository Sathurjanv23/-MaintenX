namespace MaintenX.Api.Domain.Authorization;

using System.Collections.Frozen;

/// <summary>
/// Immutable domain mapping from <see cref="PlatformRole"/> to approved platform-scoped permissions
/// in <see cref="PermissionCatalog"/>. Strictly excludes all tenant-scoped permissions.
/// </summary>
public static class PlatformRolePermissionMap
{
    private static readonly FrozenSet<PermissionKey> EmptySet = FrozenSet<PermissionKey>.Empty;
    private static readonly FrozenDictionary<PlatformRole, FrozenSet<PermissionKey>> _roleMappings;

    static PlatformRolePermissionMap()
    {
        var adminPermissions = new[]
        {
            PermissionCatalog.Platform.TenantsRead,
            PermissionCatalog.Platform.TenantsActivate,
            PermissionCatalog.Platform.TenantsSuspend,
            PermissionCatalog.Platform.TenantsDeactivate
        };

        foreach (var perm in adminPermissions)
        {
            if (!PermissionCatalog.IsRegistered(perm) || perm.Scope != AuthorizationScopeKind.Platform)
            {
                throw new InvalidOperationException($"Invalid platform permission mapping: '{perm.Value}'.");
            }
        }

        _roleMappings = new Dictionary<PlatformRole, FrozenSet<PermissionKey>>
        {
            [PlatformRole.PlatformAdministrator] = adminPermissions.ToFrozenSet()
        }.ToFrozenDictionary();
    }

    /// <summary>
    /// Returns the immutable set of platform-scoped permissions eligible for <paramref name="role"/>.
    /// Unknown roles fail closed with an empty set.
    /// </summary>
    public static IReadOnlySet<PermissionKey> GetPermissions(PlatformRole role)
    {
        if (!Enum.IsDefined(role) || !_roleMappings.TryGetValue(role, out var permissions))
        {
            return EmptySet;
        }

        return permissions;
    }

    /// <summary>
    /// Evaluates whether <paramref name="role"/> is eligible for <paramref name="permission"/>.
    /// Denies null, unregistered, tenant-scoped, and unknown-role queries.
    /// </summary>
    public static bool HasPermission(PlatformRole role, PermissionKey? permission)
    {
        if (permission is null ||
            !Enum.IsDefined(role) ||
            permission.Scope != AuthorizationScopeKind.Platform ||
            !PermissionCatalog.IsRegistered(permission))
        {
            return false;
        }

        return _roleMappings.TryGetValue(role, out var permissions) && permissions.Contains(permission);
    }

    /// <summary>
    /// Evaluates whether an active <paramref name="grant"/> is eligible for <paramref name="permission"/>.
    /// Revoked or null grants always fail closed.
    /// </summary>
    public static bool CanAuthorize(PlatformRoleGrant? grant, PermissionKey? permission)
        => grant is not null && grant.IsActive && HasPermission(grant.Role, permission);
}

namespace MaintenX.Api.Domain.Authorization;

using System.Collections.Frozen;
using System.Collections.Immutable;

/// <summary>
/// Centralized, immutable catalog of all approved platform-scoped and tenant-scoped permissions.
/// <para>
/// Distinguishes syntactic identifier validity (<see cref="PermissionKey"/>) from catalog registration
/// (<see cref="IsRegistered(PermissionKey?)"/>). Unknown permissions are never implicitly recognized or granted.
/// </para>
/// </summary>
public static class PermissionCatalog
{
    /// <summary>
    /// Canonical platform-scoped permission identifiers (<see cref="AuthorizationScopeKind.Platform"/>).
    /// Platform permissions must never be assigned to tenant roles.
    /// </summary>
    public static class Platform
    {
        public static readonly PermissionKey TenantsRead = PermissionKey.Parse("platform.tenants.read");
        public static readonly PermissionKey TenantsActivate = PermissionKey.Parse("platform.tenants.activate");
        public static readonly PermissionKey TenantsSuspend = PermissionKey.Parse("platform.tenants.suspend");
        public static readonly PermissionKey TenantsDeactivate = PermissionKey.Parse("platform.tenants.deactivate");
    }

    /// <summary>
    /// Canonical tenant-scoped permission identifiers (<see cref="AuthorizationScopeKind.Tenant"/>).
    /// </summary>
    public static class Tenant
    {
        public static readonly PermissionKey MetadataRead = PermissionKey.Parse("tenant.metadata.read");
        public static readonly PermissionKey SettingsUpdate = PermissionKey.Parse("tenant.settings.update");
        public static readonly PermissionKey MembersRead = PermissionKey.Parse("tenant.members.read");
        public static readonly PermissionKey MembersInvite = PermissionKey.Parse("tenant.members.invite");
        public static readonly PermissionKey MembersRolesAssign = PermissionKey.Parse("tenant.members.roles.assign");
        public static readonly PermissionKey MembersSuspend = PermissionKey.Parse("tenant.members.suspend");
        public static readonly PermissionKey MembersRestore = PermissionKey.Parse("tenant.members.restore");
        public static readonly PermissionKey MembersRevoke = PermissionKey.Parse("tenant.members.revoke");
        public static readonly PermissionKey OwnershipTransfer = PermissionKey.Parse("tenant.ownership.transfer");
        public static readonly PermissionKey AuditRead = PermissionKey.Parse("tenant.audit.read");
    }

    private static readonly ImmutableArray<PermissionDefinition> _allDefinitions;
    private static readonly ImmutableArray<PermissionDefinition> _platformDefinitions;
    private static readonly ImmutableArray<PermissionDefinition> _tenantDefinitions;
    private static readonly FrozenDictionary<PermissionKey, PermissionDefinition> _byKey;

    static PermissionCatalog()
    {
        var definitions = new[]
        {
            // Platform-scoped permissions (platform.tenants.activate covers both onboarding approval and reactivation)
            new PermissionDefinition(Platform.TenantsRead, "View platform-wide tenant catalog and pending onboarding reviews."),
            new PermissionDefinition(Platform.TenantsActivate, "Approve pending onboarding tenants and reactivate suspended tenants."),
            new PermissionDefinition(Platform.TenantsSuspend, "Temporarily suspend an active tenant organization."),
            new PermissionDefinition(Platform.TenantsDeactivate, "Permanently deactivate a tenant organization."),

            // Tenant-scoped permissions
            new PermissionDefinition(Tenant.MetadataRead, "Read tenant organization metadata and active context."),
            new PermissionDefinition(Tenant.SettingsUpdate, "Update permitted tenant organization settings."),
            new PermissionDefinition(Tenant.MembersRead, "List and inspect memberships within the target tenant."),
            new PermissionDefinition(Tenant.MembersInvite, "Create and issue membership invitations for the target tenant."),
            new PermissionDefinition(Tenant.MembersRolesAssign, "Assign or change organizational roles within the target tenant."),
            new PermissionDefinition(Tenant.MembersSuspend, "Suspend an active membership within the target tenant."),
            new PermissionDefinition(Tenant.MembersRestore, "Restore a suspended membership to active status within the target tenant."),
            new PermissionDefinition(Tenant.MembersRevoke, "Permanently revoke a membership within the target tenant."),
            new PermissionDefinition(Tenant.OwnershipTransfer, "Transfer primary organization ownership to another active member."),
            new PermissionDefinition(Tenant.AuditRead, "View tenant-scoped audit events for the target tenant.")
        };

        var dict = new Dictionary<PermissionKey, PermissionDefinition>(definitions.Length);
        foreach (var def in definitions)
        {
            if (!dict.TryAdd(def.Key, def))
            {
                throw new InvalidOperationException($"Duplicate permission identifier registered in catalog: '{def.Key.Value}'.");
            }
        }

        _allDefinitions = [.. definitions];
        _platformDefinitions = [.. definitions.Where(d => d.Scope == AuthorizationScopeKind.Platform)];
        _tenantDefinitions = [.. definitions.Where(d => d.Scope == AuthorizationScopeKind.Tenant)];
        _byKey = dict.ToFrozenDictionary();
    }

    /// <summary>
    /// Immutable deterministic collection of all registered permissions.
    /// </summary>
    public static IReadOnlyList<PermissionDefinition> All => _allDefinitions;

    /// <summary>
    /// Immutable deterministic collection of all registered platform-scoped permissions.
    /// </summary>
    public static IReadOnlyList<PermissionDefinition> PlatformPermissions => _platformDefinitions;

    /// <summary>
    /// Immutable deterministic collection of all registered tenant-scoped permissions.
    /// </summary>
    public static IReadOnlyList<PermissionDefinition> TenantPermissions => _tenantDefinitions;

    /// <summary>
    /// Returns <c>true</c> if <paramref name="key"/> is registered in the approved catalog.
    /// </summary>
    public static bool IsRegistered(PermissionKey? key)
        => key is not null && _byKey.ContainsKey(key);

    /// <summary>
    /// Returns <c>true</c> if <paramref name="rawKey"/> is a valid canonical identifier registered in the approved catalog.
    /// </summary>
    public static bool IsRegistered(string? rawKey)
        => PermissionKey.TryParse(rawKey, out var key) && IsRegistered(key);

    /// <summary>
    /// Attempts to retrieve the registered <see cref="PermissionDefinition"/> for <paramref name="key"/>.
    /// </summary>
    public static bool TryGetDefinition(PermissionKey? key, out PermissionDefinition? definition)
    {
        if (key is null)
        {
            definition = null;
            return false;
        }

        return _byKey.TryGetValue(key, out definition);
    }

    /// <summary>
    /// Attempts to parse <paramref name="rawKey"/> and retrieve its registered <see cref="PermissionDefinition"/>.
    /// </summary>
    public static bool TryGetDefinition(string? rawKey, out PermissionDefinition? definition)
    {
        if (!PermissionKey.TryParse(rawKey, out var key))
        {
            definition = null;
            return false;
        }

        return TryGetDefinition(key, out definition);
    }

    /// <summary>
    /// Returns all registered permissions belonging to the specified <paramref name="scope"/>.
    /// </summary>
    /// <exception cref="ArgumentException">Thrown when <paramref name="scope"/> is not a defined <see cref="AuthorizationScopeKind"/>.</exception>
    public static IReadOnlyList<PermissionDefinition> GetByScope(AuthorizationScopeKind scope) => scope switch
    {
        AuthorizationScopeKind.Platform => _platformDefinitions,
        AuthorizationScopeKind.Tenant => _tenantDefinitions,
        _ => throw new ArgumentException($"Invalid authorization scope kind: '{scope}'.", nameof(scope))
    };

    /// <summary>
    /// Validates that <paramref name="key"/> is registered in the catalog and compatible with <paramref name="scope"/>.
    /// </summary>
    public static bool IsRegisteredAndCompatible(PermissionKey? key, AuthorizationScope? scope)
        => key is not null && scope is not null && IsRegistered(key) && key.IsCompatibleWith(scope);
}

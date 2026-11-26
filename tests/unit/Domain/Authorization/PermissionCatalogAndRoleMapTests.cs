namespace MaintenX.UnitTests.Domain.Authorization;

using MaintenX.Api.Domain.Authorization;
using MaintenX.Api.Domain.Tenants;
using Xunit;

public class PermissionCatalogAndRoleMapTests
{
    // =========================================================================
    // A. PERMISSION CATALOG TESTS
    // =========================================================================

    [Fact]
    public void PermissionCatalog_ContainsExpectedPlatformAndTenantCounts_WithUniqueCanonicalIds()
    {
        Assert.Equal(4, PermissionCatalog.PlatformPermissions.Count);
        Assert.Equal(10, PermissionCatalog.TenantPermissions.Count);
        Assert.Equal(14, PermissionCatalog.All.Count);

        var distinctKeys = PermissionCatalog.All.Select(d => d.Key).Distinct().ToList();
        Assert.Equal(PermissionCatalog.All.Count, distinctKeys.Count);

        Assert.All(PermissionCatalog.PlatformPermissions, d =>
            Assert.Equal(AuthorizationScopeKind.Platform, d.Scope));
        Assert.All(PermissionCatalog.TenantPermissions, d =>
            Assert.Equal(AuthorizationScopeKind.Tenant, d.Scope));
    }

    [Theory]
    [InlineData("platform.tenants.read")]
    [InlineData("platform.tenants.activate")]
    [InlineData("platform.tenants.suspend")]
    [InlineData("platform.tenants.deactivate")]
    public void PermissionCatalog_ApprovedPlatformPermissions_AreRegisteredWithPlatformScope(string rawKey)
    {
        Assert.True(PermissionCatalog.IsRegistered(rawKey));
        Assert.True(PermissionCatalog.TryGetDefinition(rawKey, out var def));
        Assert.NotNull(def);
        Assert.Equal(AuthorizationScopeKind.Platform, def!.Scope);
        Assert.True(PermissionCatalog.IsRegisteredAndCompatible(def.Key, AuthorizationScope.Platform));
        Assert.False(PermissionCatalog.IsRegisteredAndCompatible(def.Key, AuthorizationScope.ForTenant(Guid.NewGuid())));
    }

    [Theory]
    [InlineData("tenant.metadata.read")]
    [InlineData("tenant.settings.update")]
    [InlineData("tenant.members.read")]
    [InlineData("tenant.members.invite")]
    [InlineData("tenant.members.roles.assign")]
    [InlineData("tenant.members.suspend")]
    [InlineData("tenant.members.restore")]
    [InlineData("tenant.members.revoke")]
    [InlineData("tenant.ownership.transfer")]
    [InlineData("tenant.audit.read")]
    public void PermissionCatalog_ApprovedTenantPermissions_AreRegisteredWithTenantScope(string rawKey)
    {
        Assert.True(PermissionCatalog.IsRegistered(rawKey));
        Assert.True(PermissionCatalog.TryGetDefinition(rawKey, out var def));
        Assert.NotNull(def);
        Assert.Equal(AuthorizationScopeKind.Tenant, def!.Scope);
        Assert.True(PermissionCatalog.IsRegisteredAndCompatible(def.Key, AuthorizationScope.ForTenant(Guid.NewGuid())));
        Assert.False(PermissionCatalog.IsRegisteredAndCompatible(def.Key, AuthorizationScope.Platform));
    }

    [Theory]
    [InlineData("tenant.unknown.permission")]
    [InlineData("platform.unknown.action")]
    [InlineData("tenant.workorders.create")]
    public void PermissionCatalog_UnknownValidFormatPermission_IsNotRegistered(string unknownKey)
    {
        var parsed = PermissionKey.Parse(unknownKey);
        Assert.False(PermissionCatalog.IsRegistered(parsed));
        Assert.False(PermissionCatalog.IsRegistered(unknownKey));
        Assert.False(PermissionCatalog.TryGetDefinition(parsed, out _));
        Assert.False(PermissionCatalog.IsRegisteredAndCompatible(parsed, AuthorizationScope.ForTenant(Guid.NewGuid())));
        Assert.False(PermissionCatalog.IsRegisteredAndCompatible(parsed, AuthorizationScope.Platform));
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("   ")]
    [InlineData("tenant.*")]
    [InlineData("platform.*")]
    [InlineData("invalid.prefix.read")]
    public void PermissionCatalog_InvalidOrWildcardIdentifiers_FailClosed(string? invalidKey)
    {
        Assert.False(PermissionCatalog.IsRegistered(invalidKey));
        Assert.False(PermissionCatalog.TryGetDefinition(invalidKey, out _));
    }

    [Fact]
    public void PermissionCatalog_Collections_CannotBeMutatedExternally()
    {
        Assert.ThrowsAny<NotSupportedException>(() =>
            ((IList<PermissionDefinition>)PermissionCatalog.All).Add(PermissionCatalog.All[0]));
        Assert.ThrowsAny<NotSupportedException>(() =>
            ((IList<PermissionDefinition>)PermissionCatalog.PlatformPermissions).Clear());
        Assert.ThrowsAny<NotSupportedException>(() =>
            ((IList<PermissionDefinition>)PermissionCatalog.TenantPermissions).Clear());
    }

    [Fact]
    public void PermissionCatalog_GetByScope_InvalidEnumThrows()
    {
        Assert.Throws<ArgumentException>(() => PermissionCatalog.GetByScope((AuthorizationScopeKind)0));
    }

    // =========================================================================
    // B. ROLE MAPPING TESTS
    // =========================================================================

    [Fact]
    public void TenantRolePermissionMap_Owner_ReceivesAll10TenantPermissionsAndZeroPlatformPermissions()
    {
        var ownerPerms = TenantRolePermissionMap.GetPermissions(TenantMembershipRole.Owner);

        Assert.Equal(10, ownerPerms.Count);
        Assert.All(PermissionCatalog.TenantPermissions, def => Assert.Contains(def.Key, ownerPerms));
        Assert.All(PermissionCatalog.PlatformPermissions, def => Assert.DoesNotContain(def.Key, ownerPerms));
    }

    [Fact]
    public void TenantRolePermissionMap_Administrator_ReceivesRestrictedAdminPermissionsOnly()
    {
        var adminPerms = TenantRolePermissionMap.GetPermissions(TenantMembershipRole.Administrator);

        Assert.Equal(8, adminPerms.Count);
        Assert.True(TenantRolePermissionMap.HasPermission(TenantMembershipRole.Administrator, PermissionCatalog.Tenant.MetadataRead));
        Assert.True(TenantRolePermissionMap.HasPermission(TenantMembershipRole.Administrator, PermissionCatalog.Tenant.SettingsUpdate));
        Assert.True(TenantRolePermissionMap.HasPermission(TenantMembershipRole.Administrator, PermissionCatalog.Tenant.MembersRead));
        Assert.True(TenantRolePermissionMap.HasPermission(TenantMembershipRole.Administrator, PermissionCatalog.Tenant.MembersInvite));
        Assert.True(TenantRolePermissionMap.HasPermission(TenantMembershipRole.Administrator, PermissionCatalog.Tenant.MembersSuspend));
        Assert.True(TenantRolePermissionMap.HasPermission(TenantMembershipRole.Administrator, PermissionCatalog.Tenant.MembersRestore));
        Assert.True(TenantRolePermissionMap.HasPermission(TenantMembershipRole.Administrator, PermissionCatalog.Tenant.MembersRevoke));
        Assert.True(TenantRolePermissionMap.HasPermission(TenantMembershipRole.Administrator, PermissionCatalog.Tenant.AuditRead));

        // Restricted from Administrator
        Assert.False(TenantRolePermissionMap.HasPermission(TenantMembershipRole.Administrator, PermissionCatalog.Tenant.MembersRolesAssign));
        Assert.False(TenantRolePermissionMap.HasPermission(TenantMembershipRole.Administrator, PermissionCatalog.Tenant.OwnershipTransfer));
    }

    [Fact]
    public void TenantRolePermissionMap_Member_ReceivesMetadataReadOnly()
    {
        var memberPerms = TenantRolePermissionMap.GetPermissions(TenantMembershipRole.Member);

        var onlyPerm = Assert.Single(memberPerms);
        Assert.Equal(PermissionCatalog.Tenant.MetadataRead, onlyPerm);

        Assert.False(TenantRolePermissionMap.HasPermission(TenantMembershipRole.Member, PermissionCatalog.Tenant.SettingsUpdate));
        Assert.False(TenantRolePermissionMap.HasPermission(TenantMembershipRole.Member, PermissionCatalog.Tenant.MembersRead));
        Assert.False(TenantRolePermissionMap.HasPermission(TenantMembershipRole.Member, PermissionCatalog.Tenant.MembersInvite));
        Assert.False(TenantRolePermissionMap.HasPermission(TenantMembershipRole.Member, PermissionCatalog.Tenant.MembersRolesAssign));
        Assert.False(TenantRolePermissionMap.HasPermission(TenantMembershipRole.Member, PermissionCatalog.Tenant.MembersSuspend));
        Assert.False(TenantRolePermissionMap.HasPermission(TenantMembershipRole.Member, PermissionCatalog.Tenant.MembersRevoke));
        Assert.False(TenantRolePermissionMap.HasPermission(TenantMembershipRole.Member, PermissionCatalog.Tenant.OwnershipTransfer));
        Assert.False(TenantRolePermissionMap.HasPermission(TenantMembershipRole.Member, PermissionCatalog.Tenant.AuditRead));
    }

    [Theory]
    [InlineData(TenantMembershipRole.Owner)]
    [InlineData(TenantMembershipRole.Administrator)]
    [InlineData(TenantMembershipRole.Member)]
    public void TenantRolePermissionMap_NoTenantRoleReceivesPlatformPermissions(TenantMembershipRole role)
    {
        foreach (var platformPerm in PermissionCatalog.PlatformPermissions)
        {
            Assert.False(TenantRolePermissionMap.HasPermission(role, platformPerm.Key));
            Assert.False(TenantRolePermissionMap.HasPermission(role, platformPerm.Key.Value));
        }

        var rolePerms = TenantRolePermissionMap.GetPermissions(role);
        Assert.All(rolePerms, p =>
        {
            Assert.Equal(AuthorizationScopeKind.Tenant, p.Scope);
            Assert.True(PermissionCatalog.IsRegistered(p));
        });
    }

    [Fact]
    public void TenantRolePermissionMap_InvalidOrDefaultRole_FailsClosed()
    {
        var invalidRole = (TenantMembershipRole)999;
        var defaultRole = default(TenantMembershipRole); // 0, undefined

        Assert.Empty(TenantRolePermissionMap.GetPermissions(invalidRole));
        Assert.Empty(TenantRolePermissionMap.GetPermissions(defaultRole));
        Assert.False(TenantRolePermissionMap.HasPermission(invalidRole, PermissionCatalog.Tenant.MetadataRead));
        Assert.False(TenantRolePermissionMap.HasPermission(defaultRole, PermissionCatalog.Tenant.MetadataRead));
    }

    [Fact]
    public void TenantRolePermissionMap_UnknownOrNullPermission_FailsClosed()
    {
        Assert.False(TenantRolePermissionMap.HasPermission(TenantMembershipRole.Owner, (PermissionKey?)null));
        Assert.False(TenantRolePermissionMap.HasPermission(TenantMembershipRole.Owner, (string?)null));
        Assert.False(TenantRolePermissionMap.HasPermission(TenantMembershipRole.Owner, "tenant.unknown.action"));
        Assert.False(TenantRolePermissionMap.HasPermission(TenantMembershipRole.Owner, "tenant.*"));
    }

    [Fact]
    public void TenantRolePermissionMap_ReturnedSets_CannotBeMutatedExternally()
    {
        var ownerSet = TenantRolePermissionMap.GetPermissions(TenantMembershipRole.Owner);
        Assert.ThrowsAny<NotSupportedException>(() =>
            ((ICollection<PermissionKey>)ownerSet).Clear());
    }
}

namespace MaintenX.UnitTests.Domain.Authorization;

using MaintenX.Api.Domain.Authorization;
using MaintenX.Api.Domain.Tenants;
using Xunit;

public class PrivilegeInvariantsTests
{
    private static readonly DateTime T0 = new(2026, 11, 26, 10, 0, 0, DateTimeKind.Utc);

    // =========================================================================
    // A. PLATFORM GRANT MODEL TESTS
    // =========================================================================

    [Fact]
    public void PlatformRoleGrant_Create_SetsActiveStateImmutableIdentitiesAndVersion1()
    {
        var userId = Guid.NewGuid();
        var operatorId = Guid.NewGuid();

        var grant = PlatformRoleGrant.Create(userId, PlatformRole.PlatformAdministrator, operatorId, T0);

        Assert.NotEqual(Guid.Empty, grant.Id);
        Assert.Equal(userId, grant.UserId);
        Assert.Equal(PlatformRole.PlatformAdministrator, grant.Role);
        Assert.Equal(PlatformRoleGrantStatus.Active, grant.Status);
        Assert.True(grant.IsActive);
        Assert.Equal(T0, grant.GrantedAtUtc);
        Assert.Equal(operatorId, grant.GrantedByUserId);
        Assert.Null(grant.RevokedAtUtc);
        Assert.Null(grant.RevokedByUserId);
        Assert.Null(grant.RevocationReason);
        Assert.Equal(1, grant.Version);
    }

    [Fact]
    public void PlatformRoleGrant_Create_InvalidInputsRejected()
    {
        var validId = Guid.NewGuid();
        var nonUtc = new DateTime(2026, 11, 26, 10, 0, 0, DateTimeKind.Local);

        Assert.Throws<ArgumentException>(() =>
            PlatformRoleGrant.Create(Guid.Empty, PlatformRole.PlatformAdministrator, validId, T0));
        Assert.Throws<ArgumentException>(() =>
            PlatformRoleGrant.Create(validId, PlatformRole.PlatformAdministrator, Guid.Empty, T0));
        Assert.Throws<ArgumentException>(() =>
            PlatformRoleGrant.Create(validId, (PlatformRole)999, validId, T0));
        Assert.Throws<ArgumentException>(() =>
            PlatformRoleGrant.Create(validId, PlatformRole.PlatformAdministrator, validId, nonUtc));
    }

    [Fact]
    public void PlatformRoleGrant_Revoke_TransitionsToTerminalRevokedAndIncrementsVersionOnce()
    {
        var grant = PlatformRoleGrant.Create(Guid.NewGuid(), PlatformRole.PlatformAdministrator, Guid.NewGuid(), T0);
        var revokerId = Guid.NewGuid();
        var revokeTime = T0.AddHours(1);

        grant.Revoke(revokerId, "  Role rotated  ", revokeTime);

        Assert.Equal(PlatformRoleGrantStatus.Revoked, grant.Status);
        Assert.False(grant.IsActive);
        Assert.Equal(revokeTime, grant.RevokedAtUtc);
        Assert.Equal(revokerId, grant.RevokedByUserId);
        Assert.Equal("Role rotated", grant.RevocationReason);
        Assert.Equal(2, grant.Version);

        // Repeated revocation is idempotent (no Version bump or metadata overwrite)
        grant.Revoke(Guid.NewGuid(), "Second revocation", revokeTime.AddMinutes(5));
        Assert.Equal(2, grant.Version);
        Assert.Equal(revokerId, grant.RevokedByUserId);
        Assert.Equal("Role rotated", grant.RevocationReason);
    }

    [Fact]
    public void PlatformRoleGrant_Revoke_InvalidMetadataOrTimestampRejectedAndPreservesState()
    {
        var grant = PlatformRoleGrant.Create(Guid.NewGuid(), PlatformRole.PlatformAdministrator, Guid.NewGuid(), T0);
        var validRevoker = Guid.NewGuid();

        Assert.Throws<ArgumentException>(() => grant.Revoke(Guid.Empty, "Valid reason", T0.AddMinutes(1)));
        Assert.Throws<ArgumentException>(() => grant.Revoke(validRevoker, "  ", T0.AddMinutes(1)));
        Assert.Throws<ArgumentException>(() => grant.Revoke(validRevoker, "ab", T0.AddMinutes(1)));
        Assert.Throws<ArgumentException>(() => grant.Revoke(validRevoker, "Valid reason", T0.AddSeconds(-1)));

        Assert.Equal(PlatformRoleGrantStatus.Active, grant.Status);
        Assert.Equal(1, grant.Version);
        Assert.Null(grant.RevokedAtUtc);
    }

    // =========================================================================
    // B. PLATFORM PERMISSION SEPARATION
    // =========================================================================

    [Fact]
    public void PlatformRolePermissionMap_SeparatesPlatformAndTenantScopes_AndDeniesRevokedGrants()
    {
        var adminPerms = PlatformRolePermissionMap.GetPermissions(PlatformRole.PlatformAdministrator);
        Assert.Equal(4, adminPerms.Count);
        Assert.All(adminPerms, p => Assert.Equal(AuthorizationScopeKind.Platform, p.Scope));

        // Unknown role & unknown/tenant permissions fail closed
        Assert.Empty(PlatformRolePermissionMap.GetPermissions((PlatformRole)999));
        Assert.False(PlatformRolePermissionMap.HasPermission(PlatformRole.PlatformAdministrator, PermissionCatalog.Tenant.SettingsUpdate));
        Assert.False(PlatformRolePermissionMap.HasPermission(PlatformRole.PlatformAdministrator, (PermissionKey?)null));

        var grant = PlatformRoleGrant.Create(Guid.NewGuid(), PlatformRole.PlatformAdministrator, Guid.NewGuid(), T0);
        Assert.True(PlatformRolePermissionMap.CanAuthorize(grant, PermissionCatalog.Platform.TenantsActivate));
        Assert.False(PlatformRolePermissionMap.CanAuthorize(grant, PermissionCatalog.Tenant.MetadataRead));

        grant.Revoke(Guid.NewGuid(), "Revoked for test", T0.AddMinutes(1));
        Assert.False(PlatformRolePermissionMap.CanAuthorize(grant, PermissionCatalog.Platform.TenantsActivate));
        Assert.False(PlatformRolePermissionMap.CanAuthorize(null, PermissionCatalog.Platform.TenantsActivate));
    }

    // =========================================================================
    // C. TENANT ROLE HIERARCHY & INVITATION BOUNDARIES
    // =========================================================================

    [Fact]
    public void TenantPrivilegeRules_RoleAssignment_EnforcesHierarchyAndBlocksSelfOrOwnerEscalation()
    {
        var tenantId = Guid.NewGuid();
        var owner = TenantMembership.Create(tenantId, Guid.NewGuid(), TenantMembershipRole.Owner, TenantMembershipStatus.Active, T0);
        var admin = TenantMembership.Create(tenantId, Guid.NewGuid(), TenantMembershipRole.Administrator, TenantMembershipStatus.Active, T0);
        var member = TenantMembership.Create(tenantId, Guid.NewGuid(), TenantMembershipRole.Member, TenantMembershipStatus.Active, T0);
        var all = new[] { owner, admin, member };

        // Owner can promote Member -> Administrator
        Assert.True(TenantPrivilegeRules.CanAssignRole(owner, member, TenantMembershipRole.Administrator, TenantStatus.Active, all).IsAllowed);

        // Owner cannot promote Member -> Owner via AssignRole (must use OwnershipTransfer)
        Assert.False(TenantPrivilegeRules.CanAssignRole(owner, member, TenantMembershipRole.Owner, TenantStatus.Active, all).IsAllowed);

        // Self-targeted role change denied
        Assert.False(TenantPrivilegeRules.CanAssignRole(owner, owner, TenantMembershipRole.Administrator, TenantStatus.Active, all).IsAllowed);

        // Admin and Member cannot assign roles
        Assert.False(TenantPrivilegeRules.CanAssignRole(admin, member, TenantMembershipRole.Administrator, TenantStatus.Active, all).IsAllowed);
        Assert.False(TenantPrivilegeRules.CanAssignRole(member, admin, TenantMembershipRole.Member, TenantStatus.Active, all).IsAllowed);

        // Cross-tenant denied
        var otherTenantMember = TenantMembership.Create(Guid.NewGuid(), Guid.NewGuid(), TenantMembershipRole.Member, TenantMembershipStatus.Active, T0);
        Assert.False(TenantPrivilegeRules.CanAssignRole(owner, otherTenantMember, TenantMembershipRole.Administrator, TenantStatus.Active, all).IsAllowed);

        // Inactive tenant or inactive actor denied
        Assert.False(TenantPrivilegeRules.CanAssignRole(owner, member, TenantMembershipRole.Administrator, TenantStatus.Suspended, all).IsAllowed);
        var suspendedOwner = TenantMembership.Create(tenantId, Guid.NewGuid(), TenantMembershipRole.Owner, TenantMembershipStatus.Suspended, T0);
        Assert.False(TenantPrivilegeRules.CanAssignRole(suspendedOwner, member, TenantMembershipRole.Administrator, TenantStatus.Active, all).IsAllowed);
    }

    [Fact]
    public void TenantPrivilegeRules_Invitations_CannotBypassHierarchy()
    {
        var tenantId = Guid.NewGuid();
        var owner = TenantMembership.Create(tenantId, Guid.NewGuid(), TenantMembershipRole.Owner, TenantMembershipStatus.Active, T0);
        var admin = TenantMembership.Create(tenantId, Guid.NewGuid(), TenantMembershipRole.Administrator, TenantMembershipStatus.Active, T0);
        var member = TenantMembership.Create(tenantId, Guid.NewGuid(), TenantMembershipRole.Member, TenantMembershipStatus.Active, T0);

        Assert.True(TenantPrivilegeRules.CanInviteWithRole(owner, TenantMembershipRole.Administrator, TenantStatus.Active).IsAllowed);
        Assert.True(TenantPrivilegeRules.CanInviteWithRole(owner, TenantMembershipRole.Member, TenantStatus.Active).IsAllowed);
        Assert.False(TenantPrivilegeRules.CanInviteWithRole(owner, TenantMembershipRole.Owner, TenantStatus.Active).IsAllowed);

        Assert.True(TenantPrivilegeRules.CanInviteWithRole(admin, TenantMembershipRole.Member, TenantStatus.Active).IsAllowed);
        Assert.False(TenantPrivilegeRules.CanInviteWithRole(admin, TenantMembershipRole.Administrator, TenantStatus.Active).IsAllowed);
        Assert.False(TenantPrivilegeRules.CanInviteWithRole(admin, TenantMembershipRole.Owner, TenantStatus.Active).IsAllowed);

        Assert.False(TenantPrivilegeRules.CanInviteWithRole(member, TenantMembershipRole.Member, TenantStatus.Active).IsAllowed);
    }

    // =========================================================================
    // D. LAST ACTIVE OWNER PROTECTION
    // =========================================================================

    [Fact]
    public void TenantPrivilegeRules_LastActiveOwner_CannotBeRevokedSuspendedOrDemoted()
    {
        var tenantId = Guid.NewGuid();
        var activeOwner = TenantMembership.Create(tenantId, Guid.NewGuid(), TenantMembershipRole.Owner, TenantMembershipStatus.Active, T0);
        var pendingOwner = TenantMembership.Create(tenantId, Guid.NewGuid(), TenantMembershipRole.Owner, TenantMembershipStatus.Pending, T0);
        var suspendedOwner = TenantMembership.Create(tenantId, Guid.NewGuid(), TenantMembershipRole.Owner, TenantMembershipStatus.Suspended, T0);
        var revokedOwner = TenantMembership.Create(tenantId, Guid.NewGuid(), TenantMembershipRole.Owner, TenantMembershipStatus.Active, T0);
        revokedOwner.Revoke(T0.AddMinutes(1));
        var otherTenantOwner = TenantMembership.Create(Guid.NewGuid(), Guid.NewGuid(), TenantMembershipRole.Owner, TenantMembershipStatus.Active, T0);
        var admin = TenantMembership.Create(tenantId, Guid.NewGuid(), TenantMembershipRole.Administrator, TenantMembershipStatus.Active, T0);

        // Pending, Suspended, Revoked, and cross-tenant Owners do NOT satisfy the active owner invariant
        var memberships = new[] { activeOwner, pendingOwner, suspendedOwner, revokedOwner, otherTenantOwner, admin };

        Assert.False(TenantPrivilegeRules.CanRevokeMembership(activeOwner, activeOwner, TenantStatus.Active, memberships).IsAllowed);
        Assert.False(TenantPrivilegeRules.CanSuspendMembership(activeOwner, activeOwner, TenantStatus.Active, memberships).IsAllowed);

        // Admin cannot manipulate Owner
        Assert.False(TenantPrivilegeRules.CanRevokeMembership(admin, activeOwner, TenantStatus.Active, memberships).IsAllowed);
        Assert.False(TenantPrivilegeRules.CanSuspendMembership(admin, activeOwner, TenantStatus.Active, memberships).IsAllowed);

        // When a second distinct Active Owner exists in the same tenant, revocation/demotion of the first is allowed
        var secondOwner = TenantMembership.Create(tenantId, Guid.NewGuid(), TenantMembershipRole.Owner, TenantMembershipStatus.Active, T0);
        var withTwoOwners = new[] { activeOwner, secondOwner, admin };
        Assert.True(TenantPrivilegeRules.CanRevokeMembership(secondOwner, activeOwner, TenantStatus.Active, withTwoOwners).IsAllowed);
        Assert.True(TenantPrivilegeRules.CanSuspendMembership(secondOwner, activeOwner, TenantStatus.Active, withTwoOwners).IsAllowed);
        Assert.True(TenantPrivilegeRules.CanAssignRole(secondOwner, activeOwner, TenantMembershipRole.Administrator, TenantStatus.Active, withTwoOwners).IsAllowed);
    }

    // =========================================================================
    // E. OWNERSHIP TRANSFER & LAST PLATFORM ADMIN PROTECTION
    // =========================================================================

    [Fact]
    public void TenantPrivilegeRules_OwnershipTransfer_EnforcesEligibilityAndSameTenant()
    {
        var tenantId = Guid.NewGuid();
        var owner = TenantMembership.Create(tenantId, Guid.NewGuid(), TenantMembershipRole.Owner, TenantMembershipStatus.Active, T0);
        var activeAdmin = TenantMembership.Create(tenantId, Guid.NewGuid(), TenantMembershipRole.Administrator, TenantMembershipStatus.Active, T0);
        var suspendedMember = TenantMembership.Create(tenantId, Guid.NewGuid(), TenantMembershipRole.Member, TenantMembershipStatus.Suspended, T0);
        var revokedMember = TenantMembership.Create(tenantId, Guid.NewGuid(), TenantMembershipRole.Member, TenantMembershipStatus.Active, T0);
        revokedMember.Revoke(T0.AddMinutes(1));
        var foreignMember = TenantMembership.Create(Guid.NewGuid(), Guid.NewGuid(), TenantMembershipRole.Member, TenantMembershipStatus.Active, T0);

        Assert.True(TenantPrivilegeRules.CanTransferOwnership(owner, activeAdmin, TenantStatus.Active).IsAllowed);
        Assert.False(TenantPrivilegeRules.CanTransferOwnership(owner, owner, TenantStatus.Active).IsAllowed);
        Assert.False(TenantPrivilegeRules.CanTransferOwnership(owner, suspendedMember, TenantStatus.Active).IsAllowed);
        Assert.False(TenantPrivilegeRules.CanTransferOwnership(owner, revokedMember, TenantStatus.Active).IsAllowed);
        Assert.False(TenantPrivilegeRules.CanTransferOwnership(owner, foreignMember, TenantStatus.Active).IsAllowed);
        Assert.False(TenantPrivilegeRules.CanTransferOwnership(activeAdmin, owner, TenantStatus.Active).IsAllowed);
    }

    [Fact]
    public void PlatformPrivilegeRules_LastPlatformAdmin_CannotBeRevoked()
    {
        var admin1User = Guid.NewGuid();
        var admin1Grant = PlatformRoleGrant.Create(admin1User, PlatformRole.PlatformAdministrator, Guid.NewGuid(), T0);
        var duplicateAdmin1Grant = PlatformRoleGrant.Create(admin1User, PlatformRole.PlatformAdministrator, Guid.NewGuid(), T0);
        var revokedAdminGrant = PlatformRoleGrant.Create(Guid.NewGuid(), PlatformRole.PlatformAdministrator, Guid.NewGuid(), T0);
        revokedAdminGrant.Revoke(admin1User, "Previously revoked", T0.AddMinutes(1));

        // Duplicate grant for same user & revoked grant for another user do NOT satisfy count
        var grants = new[] { admin1Grant, duplicateAdmin1Grant, revokedAdminGrant };
        Assert.False(PlatformPrivilegeRules.CanRevokeGrant(admin1Grant, admin1Grant, grants).IsAllowed);

        // Second distinct active PlatformAdministrator allows revoking the first
        var admin2Grant = PlatformRoleGrant.Create(Guid.NewGuid(), PlatformRole.PlatformAdministrator, admin1User, T0);
        var twoAdmins = new[] { admin1Grant, admin2Grant };
        Assert.True(PlatformPrivilegeRules.CanRevokeGrant(admin2Grant, admin1Grant, twoAdmins).IsAllowed);
    }
}

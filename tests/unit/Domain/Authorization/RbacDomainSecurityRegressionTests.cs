namespace MaintenX.UnitTests.Domain.Authorization;

using MaintenX.Api.Domain.Authorization;
using MaintenX.Api.Domain.Tenants;
using Xunit;

/// <summary>
/// Exhaustive negative and security boundary regression tests for FEAT-004 Step 4.1 (Task 4.1.4).
/// </summary>
public class RbacDomainSecurityRegressionTests
{
    private static readonly DateTime T0 = new(2026, 11, 27, 10, 0, 0, DateTimeKind.Utc);

    public static IEnumerable<object[]> RolePermissionMatrixCases()
    {
        var allTenantPerms = PermissionCatalog.TenantPermissions.Select(p => p.Key).ToList();
        var allPlatformPerms = PermissionCatalog.PlatformPermissions.Select(p => p.Key).ToList();

        // Owner: all 10 tenant permissions allowed; all 4 platform permissions denied
        foreach (var perm in allTenantPerms)
            yield return new object[] { TenantMembershipRole.Owner, perm, true };
        foreach (var perm in allPlatformPerms)
            yield return new object[] { TenantMembershipRole.Owner, perm, false };

        // Administrator: 8 tenant permissions allowed; roles.assign, ownership.transfer, and all 4 platform permissions denied
        var adminExcluded = new HashSet<PermissionKey>
        {
            PermissionCatalog.Tenant.MembersRolesAssign,
            PermissionCatalog.Tenant.OwnershipTransfer
        };
        foreach (var perm in allTenantPerms)
            yield return new object[] { TenantMembershipRole.Administrator, perm, !adminExcluded.Contains(perm) };
        foreach (var perm in allPlatformPerms)
            yield return new object[] { TenantMembershipRole.Administrator, perm, false };

        // Member: only tenant.metadata.read allowed; all others denied
        foreach (var perm in allTenantPerms)
            yield return new object[] { TenantMembershipRole.Member, perm, perm == PermissionCatalog.Tenant.MetadataRead };
        foreach (var perm in allPlatformPerms)
            yield return new object[] { TenantMembershipRole.Member, perm, false };
    }

    [Theory]
    [MemberData(nameof(RolePermissionMatrixCases))]
    public void ExhaustiveRolePermissionMatrix_MatchesExactSpecification(
        TenantMembershipRole role,
        PermissionKey permission,
        bool expectedAllowed)
    {
        Assert.Equal(expectedAllowed, TenantRolePermissionMap.HasPermission(role, permission));
        Assert.Equal(expectedAllowed, TenantRolePermissionMap.HasPermission(role, permission.Value));
    }

    public static IEnumerable<object[]> PlatformRolePermissionMatrixCases()
    {
        foreach (var perm in PermissionCatalog.PlatformPermissions.Select(p => p.Key))
            yield return new object[] { PlatformRole.PlatformAdministrator, perm, true };

        foreach (var perm in PermissionCatalog.TenantPermissions.Select(p => p.Key))
            yield return new object[] { PlatformRole.PlatformAdministrator, perm, false };
    }

    [Theory]
    [MemberData(nameof(PlatformRolePermissionMatrixCases))]
    public void ExhaustivePlatformRolePermissionMatrix_MatchesExactSpecification(
        PlatformRole role,
        PermissionKey permission,
        bool expectedAllowed)
    {
        Assert.Equal(expectedAllowed, PlatformRolePermissionMap.HasPermission(role, permission));
    }

    [Fact]
    public void DuplicateOwnerRecordsForTargetUser_CannotSatisfyLastActiveOwnerInvariant()
    {
        var tenantId = Guid.NewGuid();
        var targetUserId = Guid.NewGuid();
        var ownerPrimary = TenantMembership.Create(tenantId, targetUserId, TenantMembershipRole.Owner, TenantMembershipStatus.Active, T0);
        var ownerDuplicate = TenantMembership.Create(tenantId, targetUserId, TenantMembershipRole.Owner, TenantMembershipStatus.Active, T0.AddSeconds(1));
        var otherUserOwner = TenantMembership.Create(tenantId, Guid.NewGuid(), TenantMembershipRole.Owner, TenantMembershipStatus.Active, T0);

        // Only targetUserId's duplicate records exist -> remaining distinct other active owners == 0
        var onlyTargetDuplicates = new[] { ownerPrimary, ownerDuplicate };
        Assert.Equal(0, TenantPrivilegeRules.CountRemainingActiveOwnersExcluding(onlyTargetDuplicates, tenantId, targetUserId));
        Assert.False(TenantPrivilegeRules.CanRevokeMembership(ownerPrimary, ownerPrimary, TenantStatus.Active, onlyTargetDuplicates).IsAllowed);
        Assert.False(TenantPrivilegeRules.CanSuspendMembership(ownerPrimary, ownerPrimary, TenantStatus.Active, onlyTargetDuplicates).IsAllowed);

        // When a distinct other user is also an Active Owner -> count == 1 -> allowed
        var withDistinctOther = new[] { ownerPrimary, ownerDuplicate, otherUserOwner };
        Assert.Equal(1, TenantPrivilegeRules.CountRemainingActiveOwnersExcluding(withDistinctOther, tenantId, targetUserId));
        Assert.True(TenantPrivilegeRules.CanRevokeMembership(otherUserOwner, ownerPrimary, TenantStatus.Active, withDistinctOther).IsAllowed);
    }

    [Theory]
    [InlineData(TenantStatus.PendingOnboarding)]
    [InlineData(TenantStatus.Suspended)]
    [InlineData(TenantStatus.Deactivated)]
    [InlineData((TenantStatus)999)]
    public void TenantPrivilegeRules_InactiveOrInvalidTenantStatus_DeniesAllPrivilegeMutations(TenantStatus status)
    {
        var tenantId = Guid.NewGuid();
        var owner = TenantMembership.Create(tenantId, Guid.NewGuid(), TenantMembershipRole.Owner, TenantMembershipStatus.Active, T0);
        var member = TenantMembership.Create(tenantId, Guid.NewGuid(), TenantMembershipRole.Member, TenantMembershipStatus.Active, T0);
        var suspended = TenantMembership.Create(tenantId, Guid.NewGuid(), TenantMembershipRole.Member, TenantMembershipStatus.Suspended, T0);
        var all = new[] { owner, member, suspended };

        Assert.False(TenantPrivilegeRules.CanAssignRole(owner, member, TenantMembershipRole.Administrator, status, all).IsAllowed);
        Assert.False(TenantPrivilegeRules.CanInviteWithRole(owner, TenantMembershipRole.Member, status).IsAllowed);
        Assert.False(TenantPrivilegeRules.CanSuspendMembership(owner, member, status, all).IsAllowed);
        Assert.False(TenantPrivilegeRules.CanRestoreMembership(owner, suspended, status).IsAllowed);
        Assert.False(TenantPrivilegeRules.CanRevokeMembership(owner, member, status, all).IsAllowed);
        Assert.False(TenantPrivilegeRules.CanTransferOwnership(owner, member, status).IsAllowed);
    }

    [Theory]
    [InlineData(TenantMembershipStatus.Pending)]
    [InlineData(TenantMembershipStatus.Suspended)]
    [InlineData(TenantMembershipStatus.Revoked)]
    public void TenantPrivilegeRules_InactiveActorMembership_DeniesAllPrivilegeMutations(TenantMembershipStatus actorStatus)
    {
        var tenantId = Guid.NewGuid();
        var actor = TenantMembership.Create(tenantId, Guid.NewGuid(), TenantMembershipRole.Owner, TenantMembershipStatus.Active, T0);
        if (actorStatus == TenantMembershipStatus.Pending)
            actor = TenantMembership.Create(tenantId, Guid.NewGuid(), TenantMembershipRole.Owner, TenantMembershipStatus.Pending, T0);
        else if (actorStatus == TenantMembershipStatus.Suspended)
            actor.Suspend(T0.AddMinutes(1));
        else if (actorStatus == TenantMembershipStatus.Revoked)
            actor.Revoke(T0.AddMinutes(1));

        var member = TenantMembership.Create(tenantId, Guid.NewGuid(), TenantMembershipRole.Member, TenantMembershipStatus.Active, T0);
        var suspended = TenantMembership.Create(tenantId, Guid.NewGuid(), TenantMembershipRole.Member, TenantMembershipStatus.Suspended, T0);
        var all = new[] { actor, member, suspended };

        Assert.False(TenantPrivilegeRules.CanAssignRole(actor, member, TenantMembershipRole.Administrator, TenantStatus.Active, all).IsAllowed);
        Assert.False(TenantPrivilegeRules.CanInviteWithRole(actor, TenantMembershipRole.Member, TenantStatus.Active).IsAllowed);
        Assert.False(TenantPrivilegeRules.CanSuspendMembership(actor, member, TenantStatus.Active, all).IsAllowed);
        Assert.False(TenantPrivilegeRules.CanRestoreMembership(actor, suspended, TenantStatus.Active).IsAllowed);
        Assert.False(TenantPrivilegeRules.CanRevokeMembership(actor, member, TenantStatus.Active, all).IsAllowed);
        Assert.False(TenantPrivilegeRules.CanTransferOwnership(actor, member, TenantStatus.Active).IsAllowed);
    }

    [Fact]
    public void TenantPrivilegeRules_AdministratorCannotManipulateOwnerOrOtherAdministrators()
    {
        var tenantId = Guid.NewGuid();
        var owner = TenantMembership.Create(tenantId, Guid.NewGuid(), TenantMembershipRole.Owner, TenantMembershipStatus.Active, T0);
        var admin1 = TenantMembership.Create(tenantId, Guid.NewGuid(), TenantMembershipRole.Administrator, TenantMembershipStatus.Active, T0);
        var admin2 = TenantMembership.Create(tenantId, Guid.NewGuid(), TenantMembershipRole.Administrator, TenantMembershipStatus.Active, T0);
        var suspendedAdmin = TenantMembership.Create(tenantId, Guid.NewGuid(), TenantMembershipRole.Administrator, TenantMembershipStatus.Suspended, T0);
        var all = new[] { owner, admin1, admin2, suspendedAdmin };

        Assert.False(TenantPrivilegeRules.CanSuspendMembership(admin1, owner, TenantStatus.Active, all).IsAllowed);
        Assert.False(TenantPrivilegeRules.CanRevokeMembership(admin1, owner, TenantStatus.Active, all).IsAllowed);
        Assert.False(TenantPrivilegeRules.CanSuspendMembership(admin1, admin2, TenantStatus.Active, all).IsAllowed);
        Assert.False(TenantPrivilegeRules.CanRevokeMembership(admin1, admin2, TenantStatus.Active, all).IsAllowed);
        Assert.False(TenantPrivilegeRules.CanRestoreMembership(admin1, suspendedAdmin, TenantStatus.Active).IsAllowed);
    }

    [Fact]
    public void PlatformRoleGrant_DefaultAndCrossScopeChecks_FailClosed()
    {
        Assert.False(PlatformRolePermissionMap.CanAuthorize(null, PermissionCatalog.Platform.TenantsRead));
        Assert.False(PlatformRolePermissionMap.HasPermission((PlatformRole)0, PermissionCatalog.Platform.TenantsRead));
        Assert.False(PlatformRolePermissionMap.HasPermission(PlatformRole.PlatformAdministrator, PermissionCatalog.Tenant.MetadataRead));
        Assert.Null(default(AuthorizationScope));
        Assert.Null(default(PermissionKey));
    }
}

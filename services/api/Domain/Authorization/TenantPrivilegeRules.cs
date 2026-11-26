namespace MaintenX.Api.Domain.Authorization;

using MaintenX.Api.Domain.Tenants;

/// <summary>
/// Domain eligibility rules governing tenant privilege assignment, invitation role boundaries,
/// membership lifecycle mutations, last-active-owner protection, and ownership transfer.
/// <para>
/// These rules enforce domain invariants only; runtime identity verification and concurrency
/// serialization (e.g., tenant-wide transaction locks) must be enforced by application/persistence services.
/// </para>
/// </summary>
public static class TenantPrivilegeRules
{
    /// <summary>
    /// Evaluates whether <paramref name="actor"/> may assign <paramref name="proposedRole"/> to <paramref name="target"/>.
    /// </summary>
    public static PrivilegeCheckResult CanAssignRole(
        TenantMembership? actor,
        TenantMembership? target,
        TenantMembershipRole proposedRole,
        TenantStatus tenantStatus,
        IReadOnlyCollection<TenantMembership>? currentTenantMemberships)
    {
        if (actor is null || target is null || currentTenantMemberships is null)
        {
            return PrivilegeCheckResult.Denied("Actor, target membership, and current membership collection are required.");
        }

        if (!Enum.IsDefined(tenantStatus) || tenantStatus != TenantStatus.Active)
        {
            return PrivilegeCheckResult.Denied("Role assignment requires an Active tenant organization.");
        }

        if (!IsEligibleActiveActor(actor, PermissionCatalog.Tenant.MembersRolesAssign, out var actorError))
        {
            return PrivilegeCheckResult.Denied(actorError);
        }

        if (actor.TenantId != target.TenantId)
        {
            return PrivilegeCheckResult.Denied("Cross-tenant role assignment is prohibited.");
        }

        if (!Enum.IsDefined(target.Role) || !Enum.IsDefined(target.Status) || !Enum.IsDefined(proposedRole))
        {
            return PrivilegeCheckResult.Denied("Unknown membership role or status.");
        }

        if (target.Status == TenantMembershipStatus.Revoked)
        {
            return PrivilegeCheckResult.Denied("Cannot assign roles to a permanently revoked membership.");
        }

        if (actor.UserId == target.UserId || actor.Id == target.Id)
        {
            return PrivilegeCheckResult.Denied("Self-targeted role mutation is prohibited; use ownership transfer where applicable.");
        }

        if (proposedRole == TenantMembershipRole.Owner)
        {
            return PrivilegeCheckResult.Denied("Owner role cannot be granted via ordinary role assignment; use ownership transfer.");
        }

        if (target.Role == TenantMembershipRole.Owner &&
            target.Status == TenantMembershipStatus.Active &&
            CountRemainingActiveOwnersExcluding(currentTenantMemberships, actor.TenantId, target.Id) < 1)
        {
            return PrivilegeCheckResult.Denied("Cannot demote the last active Owner of the tenant organization.");
        }

        return PrivilegeCheckResult.Allowed();
    }

    /// <summary>
    /// Evaluates whether <paramref name="actor"/> may issue a membership invitation for <paramref name="invitedRole"/>.
    /// </summary>
    public static PrivilegeCheckResult CanInviteWithRole(
        TenantMembership? actor,
        TenantMembershipRole invitedRole,
        TenantStatus tenantStatus)
    {
        if (actor is null)
        {
            return PrivilegeCheckResult.Denied("Actor membership is required.");
        }

        if (!Enum.IsDefined(tenantStatus) || tenantStatus != TenantStatus.Active)
        {
            return PrivilegeCheckResult.Denied("Invitations require an Active tenant organization.");
        }

        if (!IsEligibleActiveActor(actor, PermissionCatalog.Tenant.MembersInvite, out var actorError))
        {
            return PrivilegeCheckResult.Denied(actorError);
        }

        if (!Enum.IsDefined(invitedRole))
        {
            return PrivilegeCheckResult.Denied("Unknown invited role.");
        }

        if (invitedRole == TenantMembershipRole.Owner)
        {
            return PrivilegeCheckResult.Denied("Owner role cannot be granted via invitation.");
        }

        // Administrator may only invite Member (cannot invite Administrator or Owner)
        if (actor.Role == TenantMembershipRole.Administrator && invitedRole != TenantMembershipRole.Member)
        {
            return PrivilegeCheckResult.Denied("Administrators may only invite users with the Member role.");
        }

        return PrivilegeCheckResult.Allowed();
    }

    /// <summary>
    /// Evaluates whether <paramref name="actor"/> may suspend <paramref name="target"/>.
    /// </summary>
    public static PrivilegeCheckResult CanSuspendMembership(
        TenantMembership? actor,
        TenantMembership? target,
        TenantStatus tenantStatus,
        IReadOnlyCollection<TenantMembership>? currentTenantMemberships)
    {
        if (actor is null || target is null || currentTenantMemberships is null)
        {
            return PrivilegeCheckResult.Denied("Actor, target membership, and current membership collection are required.");
        }

        if (!Enum.IsDefined(tenantStatus) || tenantStatus != TenantStatus.Active)
        {
            return PrivilegeCheckResult.Denied("Membership suspension requires an Active tenant organization.");
        }

        if (!IsEligibleActiveActor(actor, PermissionCatalog.Tenant.MembersSuspend, out var actorError))
        {
            return PrivilegeCheckResult.Denied(actorError);
        }

        if (actor.TenantId != target.TenantId)
        {
            return PrivilegeCheckResult.Denied("Cross-tenant membership suspension is prohibited.");
        }

        if (!Enum.IsDefined(target.Role) || !Enum.IsDefined(target.Status))
        {
            return PrivilegeCheckResult.Denied("Unknown target role or status.");
        }

        if (target.Status != TenantMembershipStatus.Active)
        {
            return PrivilegeCheckResult.Denied("Only active memberships can be suspended.");
        }

        if (actor.Role == TenantMembershipRole.Administrator && target.Role != TenantMembershipRole.Member)
        {
            return PrivilegeCheckResult.Denied("Administrators cannot suspend Owners or other Administrators.");
        }

        if (target.Role == TenantMembershipRole.Owner &&
            CountRemainingActiveOwnersExcluding(currentTenantMemberships, actor.TenantId, target.Id) < 1)
        {
            return PrivilegeCheckResult.Denied("Cannot suspend the last active Owner of the tenant organization.");
        }

        return PrivilegeCheckResult.Allowed();
    }

    /// <summary>
    /// Evaluates whether <paramref name="actor"/> may restore a suspended <paramref name="target"/> membership.
    /// </summary>
    public static PrivilegeCheckResult CanRestoreMembership(
        TenantMembership? actor,
        TenantMembership? target,
        TenantStatus tenantStatus)
    {
        if (actor is null || target is null)
        {
            return PrivilegeCheckResult.Denied("Actor and target membership are required.");
        }

        if (!Enum.IsDefined(tenantStatus) || tenantStatus != TenantStatus.Active)
        {
            return PrivilegeCheckResult.Denied("Membership restoration requires an Active tenant organization.");
        }

        if (!IsEligibleActiveActor(actor, PermissionCatalog.Tenant.MembersRestore, out var actorError))
        {
            return PrivilegeCheckResult.Denied(actorError);
        }

        if (actor.TenantId != target.TenantId)
        {
            return PrivilegeCheckResult.Denied("Cross-tenant membership restoration is prohibited.");
        }

        if (!Enum.IsDefined(target.Role) || !Enum.IsDefined(target.Status))
        {
            return PrivilegeCheckResult.Denied("Unknown target role or status.");
        }

        if (target.Status != TenantMembershipStatus.Suspended)
        {
            return PrivilegeCheckResult.Denied("Only suspended memberships can be restored.");
        }

        if (actor.Role == TenantMembershipRole.Administrator && target.Role != TenantMembershipRole.Member)
        {
            return PrivilegeCheckResult.Denied("Administrators cannot restore Owners or other Administrators.");
        }

        return PrivilegeCheckResult.Allowed();
    }

    /// <summary>
    /// Evaluates whether <paramref name="actor"/> may permanently revoke <paramref name="target"/>.
    /// </summary>
    public static PrivilegeCheckResult CanRevokeMembership(
        TenantMembership? actor,
        TenantMembership? target,
        TenantStatus tenantStatus,
        IReadOnlyCollection<TenantMembership>? currentTenantMemberships)
    {
        if (actor is null || target is null || currentTenantMemberships is null)
        {
            return PrivilegeCheckResult.Denied("Actor, target membership, and current membership collection are required.");
        }

        if (!Enum.IsDefined(tenantStatus) || tenantStatus != TenantStatus.Active)
        {
            return PrivilegeCheckResult.Denied("Membership revocation requires an Active tenant organization.");
        }

        if (!IsEligibleActiveActor(actor, PermissionCatalog.Tenant.MembersRevoke, out var actorError))
        {
            return PrivilegeCheckResult.Denied(actorError);
        }

        if (actor.TenantId != target.TenantId)
        {
            return PrivilegeCheckResult.Denied("Cross-tenant membership revocation is prohibited.");
        }

        if (!Enum.IsDefined(target.Role) || !Enum.IsDefined(target.Status))
        {
            return PrivilegeCheckResult.Denied("Unknown target role or status.");
        }

        if (target.Status == TenantMembershipStatus.Revoked)
        {
            return PrivilegeCheckResult.Denied("Membership is already permanently revoked.");
        }

        if (actor.Role == TenantMembershipRole.Administrator && target.Role != TenantMembershipRole.Member)
        {
            return PrivilegeCheckResult.Denied("Administrators cannot revoke Owners or other Administrators.");
        }

        if (target.Role == TenantMembershipRole.Owner &&
            target.Status == TenantMembershipStatus.Active &&
            CountRemainingActiveOwnersExcluding(currentTenantMemberships, actor.TenantId, target.Id) < 1)
        {
            return PrivilegeCheckResult.Denied("Cannot revoke the last active Owner of the tenant organization.");
        }

        return PrivilegeCheckResult.Allowed();
    }

    /// <summary>
    /// Evaluates domain eligibility for transferring primary organization ownership from <paramref name="actor"/> to <paramref name="recipient"/>.
    /// </summary>
    public static PrivilegeCheckResult CanTransferOwnership(
        TenantMembership? actor,
        TenantMembership? recipient,
        TenantStatus tenantStatus)
    {
        if (actor is null || recipient is null)
        {
            return PrivilegeCheckResult.Denied("Source Owner and recipient memberships are required.");
        }

        if (!Enum.IsDefined(tenantStatus) || tenantStatus != TenantStatus.Active)
        {
            return PrivilegeCheckResult.Denied("Ownership transfer requires an Active tenant organization.");
        }

        if (!IsEligibleActiveActor(actor, PermissionCatalog.Tenant.OwnershipTransfer, out var actorError))
        {
            return PrivilegeCheckResult.Denied(actorError);
        }

        if (actor.Role != TenantMembershipRole.Owner)
        {
            return PrivilegeCheckResult.Denied("Only an active Owner can transfer organization ownership.");
        }

        if (recipient.TenantId != actor.TenantId)
        {
            return PrivilegeCheckResult.Denied("Cross-tenant ownership transfer is prohibited.");
        }

        if (recipient.UserId == actor.UserId || recipient.Id == actor.Id)
        {
            return PrivilegeCheckResult.Denied("Ownership cannot be transferred to the same user.");
        }

        if (!Enum.IsDefined(recipient.Status) || recipient.Status != TenantMembershipStatus.Active)
        {
            return PrivilegeCheckResult.Denied("Ownership transfer recipient must hold an Active membership.");
        }

        if (!Enum.IsDefined(recipient.Role))
        {
            return PrivilegeCheckResult.Denied("Unknown recipient membership role.");
        }

        if (recipient.Role == TenantMembershipRole.Owner)
        {
            return PrivilegeCheckResult.Denied("Recipient already holds the Owner role.");
        }

        return PrivilegeCheckResult.Allowed();
    }

    /// <summary>
    /// Counts distinct users holding an Active <see cref="TenantMembershipRole.Owner"/> membership
    /// in <paramref name="tenantId"/> excluding <paramref name="excludedMembershipId"/>.
    /// Pending, Suspended, Revoked, cross-tenant, and duplicate records do not count.
    /// </summary>
    public static int CountRemainingActiveOwnersExcluding(
        IReadOnlyCollection<TenantMembership> memberships,
        Guid tenantId,
        Guid excludedMembershipId)
    {
        ArgumentNullException.ThrowIfNull(memberships);

        return memberships
            .Where(m => m is not null
                        && m.TenantId == tenantId
                        && m.Id != excludedMembershipId
                        && m.Role == TenantMembershipRole.Owner
                        && m.Status == TenantMembershipStatus.Active)
            .Select(m => m.UserId)
            .Distinct()
            .Count();
    }

    private static bool IsEligibleActiveActor(
        TenantMembership actor,
        PermissionKey requiredPermission,
        out string error)
    {
        if (!Enum.IsDefined(actor.Role) || !Enum.IsDefined(actor.Status))
        {
            error = "Actor has an unknown role or membership status.";
            return false;
        }

        if (actor.Status != TenantMembershipStatus.Active)
        {
            error = "Actor must hold an Active membership.";
            return false;
        }

        if (!TenantRolePermissionMap.HasPermission(actor.Role, requiredPermission))
        {
            error = $"Role '{actor.Role}' is not eligible for '{requiredPermission.Value}'.";
            return false;
        }

        error = string.Empty;
        return true;
    }
}

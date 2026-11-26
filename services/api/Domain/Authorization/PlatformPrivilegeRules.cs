namespace MaintenX.Api.Domain.Authorization;

/// <summary>
/// Domain eligibility rules protecting global platform administrator invariants,
/// including last-active-platform-administrator protection.
/// </summary>
public static class PlatformPrivilegeRules
{
    /// <summary>
    /// Evaluates whether <paramref name="actorGrant"/> may revoke <paramref name="targetGrant"/>
    /// without leaving the platform with zero active administrators.
    /// </summary>
    public static PrivilegeCheckResult CanRevokeGrant(
        PlatformRoleGrant? actorGrant,
        PlatformRoleGrant? targetGrant,
        IReadOnlyCollection<PlatformRoleGrant>? allGrants)
    {
        if (actorGrant is null || targetGrant is null || allGrants is null)
        {
            return PrivilegeCheckResult.Denied("Actor grant, target grant, and current grant collection are required.");
        }

        if (!actorGrant.IsActive || !Enum.IsDefined(actorGrant.Role) || actorGrant.Role != PlatformRole.PlatformAdministrator)
        {
            return PrivilegeCheckResult.Denied("Actor must hold an active PlatformAdministrator grant.");
        }

        if (!targetGrant.IsActive || !Enum.IsDefined(targetGrant.Role))
        {
            return PrivilegeCheckResult.Denied("Target platform grant is not active or has an unknown role.");
        }

        if (targetGrant.Role == PlatformRole.PlatformAdministrator &&
            CountRemainingActiveAdminsExcluding(allGrants, targetGrant.UserId) < 1)
        {
            return PrivilegeCheckResult.Denied("Cannot revoke the last active PlatformAdministrator grant.");
        }

        return PrivilegeCheckResult.Allowed();
    }

    /// <summary>
    /// Counts distinct users holding an active <see cref="PlatformRole.PlatformAdministrator"/> grant
    /// excluding <paramref name="excludedUserId"/>.
    /// </summary>
    public static int CountRemainingActiveAdminsExcluding(
        IReadOnlyCollection<PlatformRoleGrant> grants,
        Guid excludedUserId)
    {
        ArgumentNullException.ThrowIfNull(grants);

        return grants
            .Where(g => g is not null
                        && g.UserId != excludedUserId
                        && g.Role == PlatformRole.PlatformAdministrator
                        && g.IsActive
                        && g.UserId != Guid.Empty)
            .Select(g => g.UserId)
            .Distinct()
            .Count();
    }
}

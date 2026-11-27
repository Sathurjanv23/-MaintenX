namespace MaintenX.Api.Domain.Authorization;

/// <summary>
/// Distinguishes the authoritative actor category that issued a <see cref="PlatformRoleGrant"/>.
/// </summary>
public enum GrantActorKind
{
    /// <summary>
    /// Grant was issued by an authenticated, authorized application user.
    /// </summary>
    User = 1,

    /// <summary>
    /// Initial bootstrap grant was issued by an authorized deployment operator outside application user accounts.
    /// </summary>
    DeploymentOperator = 2
}

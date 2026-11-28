namespace MaintenX.Api.Application.Authorization.Policies;

using MaintenX.Api.Domain.Authorization;
using Microsoft.AspNetCore.Authorization;

/// <summary>
/// Authorization requirement representing a mandatory platform-scoped permission.
/// </summary>
public sealed class PlatformPermissionRequirement : IAuthorizationRequirement
{
    public PermissionKey Permission { get; }

    public PlatformPermissionRequirement(PermissionKey permission)
    {
        ArgumentNullException.ThrowIfNull(permission);
        if (permission.Scope != AuthorizationScopeKind.Platform)
        {
            throw new ArgumentException($"Permission '{permission.Value}' must have Platform scope.", nameof(permission));
        }

        Permission = permission;
    }
}

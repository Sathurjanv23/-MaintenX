namespace MaintenX.Api.Application.Authorization.Policies;

using MaintenX.Api.Domain.Authorization;
using Microsoft.AspNetCore.Authorization;

/// <summary>
/// Authorization requirement representing a mandatory tenant-scoped permission.
/// </summary>
public sealed class TenantPermissionRequirement : IAuthorizationRequirement
{
    public PermissionKey Permission { get; }

    public TenantPermissionRequirement(PermissionKey permission)
    {
        ArgumentNullException.ThrowIfNull(permission);
        if (permission.Scope != AuthorizationScopeKind.Tenant)
        {
            throw new ArgumentException($"Permission '{permission.Value}' must have Tenant scope.", nameof(permission));
        }

        Permission = permission;
    }
}

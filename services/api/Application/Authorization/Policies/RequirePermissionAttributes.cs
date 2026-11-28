namespace MaintenX.Api.Application.Authorization.Policies;

using Microsoft.AspNetCore.Authorization;

/// <summary>
/// Declarative attribute requiring an authoritative platform-scoped permission.
/// </summary>
[AttributeUsage(AttributeTargets.Class | AttributeTargets.Method, AllowMultiple = true, Inherited = true)]
public sealed class RequirePlatformPermissionAttribute : AuthorizeAttribute
{
    public RequirePlatformPermissionAttribute(string permissionKey)
        : base(PermissionEndpointConventionBuilderExtensions.PlatformPolicyPrefix + permissionKey)
    {
    }
}

/// <summary>
/// Declarative attribute requiring an authoritative tenant-scoped permission.
/// </summary>
[AttributeUsage(AttributeTargets.Class | AttributeTargets.Method, AllowMultiple = true, Inherited = true)]
public sealed class RequireTenantPermissionAttribute : AuthorizeAttribute
{
    public RequireTenantPermissionAttribute(string permissionKey)
        : base(PermissionEndpointConventionBuilderExtensions.TenantPolicyPrefix + permissionKey)
    {
    }
}

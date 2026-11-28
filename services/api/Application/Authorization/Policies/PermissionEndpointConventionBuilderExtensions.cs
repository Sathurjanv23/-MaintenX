namespace MaintenX.Api.Application.Authorization.Policies;

using MaintenX.Api.Application.Tenancy.Middleware;
using MaintenX.Api.Domain.Authorization;
using Microsoft.AspNetCore.Builder;

/// <summary>
/// Declarative endpoint convention extensions for mapping fine-grained platform and tenant permission policies.
/// </summary>
public static class PermissionEndpointConventionBuilderExtensions
{
    public const string PlatformPolicyPrefix = "Platform:";
    public const string TenantPolicyPrefix = "Tenant:";

    public static string GetPlatformPolicyName(PermissionKey permission) => PlatformPolicyPrefix + permission.Value;
    public static string GetTenantPolicyName(PermissionKey permission) => TenantPolicyPrefix + permission.Value;

    /// <summary>
    /// Requires an active verified platform administrator possessing <paramref name="permission"/>.
    /// </summary>
    public static TBuilder RequirePlatformPermission<TBuilder>(this TBuilder builder, PermissionKey permission)
        where TBuilder : IEndpointConventionBuilder
    {
        ArgumentNullException.ThrowIfNull(permission);
        if (permission.Scope != AuthorizationScopeKind.Platform)
        {
            throw new ArgumentException($"Permission '{permission.Value}' must be Platform-scoped.", nameof(permission));
        }

        return builder.RequireAuthorization(GetPlatformPolicyName(permission));
    }

    /// <summary>
    /// Requires an active verified tenant context with a membership role possessing <paramref name="permission"/>.
    /// Automatically enforces tenant context resolution via <see cref="TenantEndpointConventionBuilderExtensions.RequireTenantContext{TBuilder}"/>.
    /// </summary>
    public static TBuilder RequireTenantPermission<TBuilder>(this TBuilder builder, PermissionKey permission)
        where TBuilder : IEndpointConventionBuilder
    {
        ArgumentNullException.ThrowIfNull(permission);
        if (permission.Scope != AuthorizationScopeKind.Tenant)
        {
            throw new ArgumentException($"Permission '{permission.Value}' must be Tenant-scoped.", nameof(permission));
        }

        return builder.RequireTenantContext().RequireAuthorization(GetTenantPolicyName(permission));
    }
}

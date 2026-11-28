namespace MaintenX.Api.Application.Authorization;

using MaintenX.Api.Application.Authorization.Policies;
using MaintenX.Api.Application.Authorization.Services;
using MaintenX.Api.Domain.Authorization;
using Microsoft.AspNetCore.Authorization;
using Microsoft.Extensions.DependencyInjection;

/// <summary>
/// Dependency injection registration extensions for server-side platform and tenant authorization services,
/// policy authorization handlers, and declarative permission requirements.
/// </summary>
public static class AuthorizationServiceExtensions
{
    /// <summary>
    /// Registers authorization services, grant resolvers, policy handlers, and declarative permission policies.
    /// </summary>
    public static IServiceCollection AddMaintenXAuthorization(this IServiceCollection services)
    {
        ArgumentNullException.ThrowIfNull(services);

        services.AddHttpContextAccessor();
        services.AddScoped<IPlatformGrantResolver, PlatformGrantResolver>();
        services.AddScoped<IPlatformGrantService, PlatformGrantService>();
        services.AddScoped<IBootstrapOperatorAuthorizationProvider, HostBootstrapOperatorAuthorizationProvider>();
        services.AddScoped<IPlatformAdminBootstrapService, PlatformAdminBootstrapService>();

        // Policy authorization handlers
        services.AddScoped<IAuthorizationHandler, PlatformPermissionHandler>();
        services.AddScoped<IAuthorizationHandler, TenantPermissionHandler>();

        // Configure declarative permission policies
        services.AddAuthorization(options =>
        {
            foreach (var def in PermissionCatalog.PlatformPermissions)
            {
                var policyName = PermissionEndpointConventionBuilderExtensions.GetPlatformPolicyName(def.Key);
                options.AddPolicy(policyName, policy =>
                {
                    policy.RequireAuthenticatedUser();
                    policy.Requirements.Add(new PlatformPermissionRequirement(def.Key));
                });
            }

            foreach (var def in PermissionCatalog.TenantPermissions)
            {
                var policyName = PermissionEndpointConventionBuilderExtensions.GetTenantPolicyName(def.Key);
                options.AddPolicy(policyName, policy =>
                {
                    policy.RequireAuthenticatedUser();
                    policy.Requirements.Add(new TenantPermissionRequirement(def.Key));
                });
            }
        });

        return services;
    }
}

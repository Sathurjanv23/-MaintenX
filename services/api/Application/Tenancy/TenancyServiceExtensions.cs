namespace MaintenX.Api.Application.Tenancy;

using MaintenX.Api.Application.Tenancy.Context;
using MaintenX.Api.Application.Tenancy.Middleware;
using MaintenX.Api.Application.Tenancy.Resolution;
using MaintenX.Api.Application.Tenancy.Services;
using MaintenX.Api.Common.Modules;
using Microsoft.AspNetCore.Builder;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;

/// <summary>
/// Service and middleware registration extensions for MaintenX multi-tenancy context and resolution.
/// </summary>
public static class TenancyServiceExtensions
{
    /// <summary>
    /// Registers tenant context abstractions, scoped context accessor, and server-side resolution services.
    /// </summary>
    public static IServiceCollection AddMaintenXTenancy(this IServiceCollection services)
    {
        ArgumentNullException.ThrowIfNull(services);

        // 1. Scoped Tenant Context Accessor
        services.AddScoped<TenantContextAccessor>();
        services.AddScoped<ITenantContextAccessor>(sp => sp.GetRequiredService<TenantContextAccessor>());

        // 2. Scoped Direct ITenantContext (throws if resolved outside verified tenant context)
        services.AddScoped<ITenantContext>(sp =>
        {
            var accessor = sp.GetRequiredService<ITenantContextAccessor>();
            if (accessor.Current is null)
            {
                throw new InvalidOperationException(
                    "No active tenant context is available for the current request. " +
                    "Ensure the endpoint requires tenant context via .RequireTenantContext() and the request passed tenant resolution.");
            }
            return accessor.Current;
        });

        // 3. Scoped Tenant Resolution Service
        services.AddScoped<ITenantResolutionService, TenantResolutionService>();

        // 4. Scoped Tenant Application Service
        services.AddScoped<ITenantService, TenantService>();

        // 5. Tenancy HTTP Presentation Module
        services.AddSingleton<IModule, TenancyModule>();

        return services;
    }

    /// <summary>
    /// Adds <see cref="TenantResolutionMiddleware"/> to the HTTP request pipeline.
    /// Must execute after authentication and authorization so the caller's ClaimsPrincipal is established.
    /// </summary>
    public static IApplicationBuilder UseTenantResolution(this IApplicationBuilder app)
    {
        ArgumentNullException.ThrowIfNull(app);
        return app.UseMiddleware<TenantResolutionMiddleware>();
    }
}

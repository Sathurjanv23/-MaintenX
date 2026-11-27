namespace MaintenX.Api.Application.Authorization;

using MaintenX.Api.Application.Authorization.Services;
using Microsoft.Extensions.DependencyInjection;

/// <summary>
/// Dependency injection registration extensions for server-side platform authorization services.
/// </summary>
public static class AuthorizationServiceExtensions
{
    /// <summary>
    /// Registers <see cref="IPlatformGrantResolver"/> as a scoped service matching <c>MaintenXDbContext</c>
    /// and <c>IAuthenticationService</c> lifetimes, along with <c>IHttpContextAccessor</c>.
    /// </summary>
    public static IServiceCollection AddMaintenXAuthorization(this IServiceCollection services)
    {
        ArgumentNullException.ThrowIfNull(services);

        services.AddHttpContextAccessor();
        services.AddScoped<IPlatformGrantResolver, PlatformGrantResolver>();
        services.AddScoped<IBootstrapOperatorAuthorizationProvider, HostBootstrapOperatorAuthorizationProvider>();
        services.AddScoped<IPlatformAdminBootstrapService, PlatformAdminBootstrapService>();
        return services;
    }
}

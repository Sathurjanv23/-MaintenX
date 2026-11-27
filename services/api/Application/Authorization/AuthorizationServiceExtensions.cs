namespace MaintenX.Api.Application.Authorization;

using MaintenX.Api.Application.Authorization.Services;
using Microsoft.Extensions.DependencyInjection;

/// <summary>
/// Dependency injection registration extensions for server-side platform authorization services.
/// </summary>
public static class AuthorizationServiceExtensions
{
    /// <summary>
    /// Registers <see cref="IPlatformGrantResolver"/> as a scoped service matching <c>MaintenXDbContext</c> lifetime.
    /// </summary>
    public static IServiceCollection AddMaintenXAuthorization(this IServiceCollection services)
    {
        ArgumentNullException.ThrowIfNull(services);

        services.AddScoped<IPlatformGrantResolver, PlatformGrantResolver>();
        return services;
    }
}

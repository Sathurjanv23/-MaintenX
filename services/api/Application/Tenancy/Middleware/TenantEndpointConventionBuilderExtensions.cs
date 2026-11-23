namespace MaintenX.Api.Application.Tenancy.Middleware;

using Microsoft.AspNetCore.Builder;

/// <summary>
/// Extension methods for registering tenant context requirements on Minimal API endpoint routes.
/// </summary>
public static class TenantEndpointConventionBuilderExtensions
{
    /// <summary>
    /// Enforces that the endpoint strictly requires an active, verified <see cref="MaintenX.Api.Application.Tenancy.Context.ITenantContext"/>.
    /// If no tenant is selected or the caller lacks an active membership in the selected tenant,
    /// the request is rejected before reaching the endpoint handler.
    /// </summary>
    public static TBuilder RequireTenantContext<TBuilder>(this TBuilder builder) where TBuilder : IEndpointConventionBuilder
    {
        ArgumentNullException.ThrowIfNull(builder);
        builder.WithMetadata(new RequireTenantContextAttribute());
        return builder;
    }
}

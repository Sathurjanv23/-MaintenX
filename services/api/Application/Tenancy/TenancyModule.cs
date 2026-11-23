namespace MaintenX.Api.Application.Tenancy;

using MaintenX.Api.Application.Tenancy.Context;
using MaintenX.Api.Application.Tenancy.Contracts;
using MaintenX.Api.Application.Tenancy.Middleware;
using MaintenX.Api.Common.Modules;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Routing;

/// <summary>
/// Exposes tenancy diagnostic and verification endpoints conforming to MaintenX module conventions.
/// </summary>
public sealed class TenancyModule : IModule
{
    /// <inheritdoc />
    public IServiceCollection RegisterModule(IServiceCollection services, IConfiguration configuration)
    {
        // Core tenancy dependencies and context resolution are registered via AddMaintenXTenancy.
        return services;
    }

    /// <inheritdoc />
    public IEndpointRouteBuilder MapEndpoints(IEndpointRouteBuilder endpoints)
    {
        var group = endpoints.MapGroup("/api/v1/tenancy")
            .WithTags("Tenancy");

        // Verification endpoint reflecting the active verified tenant context
        group.MapGet("/current", (ITenantContext tenantContext) =>
        {
            return Results.Ok(new CurrentTenantContextResponse(
                tenantContext.TenantId,
                tenantContext.TenantSlug,
                tenantContext.TenantDisplayName,
                tenantContext.UserId,
                tenantContext.MembershipId,
                tenantContext.Role.ToString(),
                tenantContext.Status.ToString(),
                tenantContext.ResolvedAtUtc));
        })
        .WithName("GetCurrentTenantContext")
        .WithSummary("Retrieve active verified tenant context")
        .WithDescription("Returns the securely resolved and verified tenant context for the current authenticated request.")
        .RequireAuthorization()
        .RequireTenantContext()
        .Produces<CurrentTenantContextResponse>(StatusCodes.Status200OK)
        .ProducesProblem(StatusCodes.Status400BadRequest)
        .ProducesProblem(StatusCodes.Status401Unauthorized)
        .ProducesProblem(StatusCodes.Status403Forbidden)
        .ProducesProblem(StatusCodes.Status404NotFound);

        return endpoints;
    }
}

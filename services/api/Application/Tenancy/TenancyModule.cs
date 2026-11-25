namespace MaintenX.Api.Application.Tenancy;

using MaintenX.Api.Application.Tenancy.Context;
using MaintenX.Api.Application.Tenancy.Contracts;
using MaintenX.Api.Application.Tenancy.Endpoints;
using MaintenX.Api.Application.Tenancy.Middleware;
using MaintenX.Api.Application.Tenancy.Resolution;
using MaintenX.Api.Application.Tenancy.Services;
using MaintenX.Api.Common.Modules;
using MaintenX.Api.Common.Security;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
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
        // 1. Diagnostic and active tenant verification group
        var tenancyGroup = endpoints.MapGroup("/api/v1/tenancy")
            .WithTags("Tenancy");

        // Verification endpoint reflecting the active verified tenant context
        tenancyGroup.MapGet("/current", (ITenantContext tenantContext) =>
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

        // 2. Canonical tenant management route group (/api/v1/tenants)
        var tenantsGroup = endpoints.MapGroup("/api/v1/tenants")
            .WithTags("Tenants")
            .RequireAuthorization();

        // 2.1 Tenant Onboarding Endpoint (FEAT-003 Task 3.6.2)
        tenantsGroup.MapPost(string.Empty, async (
            [FromBody] CreateTenantRequest? request,
            ITenantActorResolver actorResolver,
            ITenantService tenantService,
            HttpContext httpContext,
            CancellationToken cancellationToken) =>
        {
            if (request is null)
            {
                return TenantResultHttpMapper.CreateProblem(
                    httpContext,
                    StatusCodes.Status400BadRequest,
                    "Bad Request",
                    "Request body cannot be empty.",
                    "VALIDATION_FAILED");
            }

            // Resolve server-side verified, trusted actor context (tenant-neutral: requireActiveTenantContext: false)
            var actorResolution = await actorResolver.ResolveActorAsync(
                httpContext.User,
                requireActiveTenantContext: false,
                cancellationToken);

            if (!actorResolution.IsSuccess || actorResolution.Actor is null)
            {
                return TenantResultHttpMapper.CreateProblem(
                    httpContext,
                    actorResolution.StatusCode,
                    actorResolution.ErrorTitle ?? "Unauthorized",
                    actorResolution.ErrorDetail ?? "Access denied.",
                    "UNAUTHORIZED");
            }

            var creatorActor = actorResolution.Actor;

            // Execute atomic onboarding application service (guarantees PendingOnboarding status & Owner membership)
            var creationResult = await tenantService.CreateTenantAsync(
                creatorActor.UserId,
                request,
                cancellationToken);

            // Returns 201 Created with approved representation; Location points to standard tenant route
            return creationResult.ToHttpResult(httpContext);
        })
        .WithName("CreateTenant")
        .WithSummary("Create and onboard a new tenant organization")
        .WithDescription("Creates a new tenant organization in PendingOnboarding status with an atomic Owner membership for the authenticated caller. Requires authenticated caller identity; does not require active tenant context.")
        .RequireRateLimiting(TenancyRateLimitPolicies.Onboarding)
        .Produces<CreateTenantResponse>(StatusCodes.Status201Created)
        .ProducesProblem(StatusCodes.Status400BadRequest)
        .ProducesProblem(StatusCodes.Status401Unauthorized)
        .ProducesProblem(StatusCodes.Status403Forbidden)
        .ProducesProblem(StatusCodes.Status409Conflict)
        .ProducesProblem(StatusCodes.Status429TooManyRequests);

        // 2.2 Workspace Membership Discovery Endpoint (FEAT-003 Task 3.6.3)
        tenantsGroup.MapGet("/me", async (
            ITenantActorResolver actorResolver,
            ITenantMembershipService membershipService,
            HttpContext httpContext,
            CancellationToken cancellationToken) =>
        {
            // Resolve server-side verified, trusted actor context (tenant-neutral: requireActiveTenantContext: false)
            var actorResolution = await actorResolver.ResolveActorAsync(
                httpContext.User,
                requireActiveTenantContext: false,
                cancellationToken);

            if (!actorResolution.IsSuccess || actorResolution.Actor is null)
            {
                return TenantResultHttpMapper.CreateProblem(
                    httpContext,
                    actorResolution.StatusCode,
                    actorResolution.ErrorTitle ?? "Unauthorized",
                    actorResolution.ErrorDetail ?? "Access denied.",
                    "UNAUTHORIZED");
            }

            var callerActor = actorResolution.Actor;

            // Retrieve all authorized, non-revoked memberships for workspace discovery
            var memberships = await membershipService.GetUserMembershipsAsync(
                callerActor.UserId,
                callerActor,
                cancellationToken);

            return Results.Ok(memberships);
        })
        .WithName("GetCurrentUserMemberships")
        .WithSummary("Discover tenant organizations accessible to the authenticated caller")
        .WithDescription("Returns all accessible tenant organizations and membership roles for multi-tenant workspace selection. Does not require X-Tenant-ID header.")
        .Produces<IReadOnlyList<UserTenantMembershipResponse>>(StatusCodes.Status200OK)
        .ProducesProblem(StatusCodes.Status401Unauthorized);

        // 2.3 Tenant Lookup Endpoint (FEAT-003 Task 3.6.4)
        tenantsGroup.MapGet("/{id}", async (
            string id,
            ITenantActorResolver actorResolver,
            ITenantService tenantService,
            HttpContext httpContext,
            CancellationToken cancellationToken) =>
        {
            if (!Guid.TryParse(id, out var tenantId) || tenantId == Guid.Empty)
            {
                return TenantResultHttpMapper.CreateProblem(
                    httpContext,
                    StatusCodes.Status400BadRequest,
                    "Bad Request",
                    "The supplied tenant identifier is not a valid non-empty GUID.",
                    "INVALID_TENANT_ID");
            }

            // Resolve server-side verified, trusted actor context (tenant-neutral: permits PendingOnboarding owner lookup)
            var actorResolution = await actorResolver.ResolveActorAsync(
                httpContext.User,
                requireActiveTenantContext: false,
                cancellationToken);

            if (!actorResolution.IsSuccess || actorResolution.Actor is null)
            {
                return TenantResultHttpMapper.CreateProblem(
                    httpContext,
                    actorResolution.StatusCode,
                    actorResolution.ErrorTitle ?? "Unauthorized",
                    actorResolution.ErrorDetail ?? "Access denied.",
                    "UNAUTHORIZED");
            }

            var lookupResult = await tenantService.GetTenantByIdAsync(
                tenantId,
                actorResolution.Actor,
                cancellationToken);

            return lookupResult.ToHttpResult(httpContext);
        })
        .WithName("GetTenantById")
        .WithSummary("Retrieve tenant organization metadata by identifier")
        .WithDescription("Returns tenant organization metadata if the authenticated caller holds an active membership in the target tenant. Enforces anti-enumeration by returning 404 Not Found for unauthorized or nonexistent tenants.")
        .Produces<TenantResponse>(StatusCodes.Status200OK)
        .ProducesProblem(StatusCodes.Status400BadRequest)
        .ProducesProblem(StatusCodes.Status401Unauthorized)
        .ProducesProblem(StatusCodes.Status404NotFound);

        // 2.4 Tenant Settings Update Endpoint (FEAT-003 Task 3.6.4)
        tenantsGroup.MapPatch("/{id}", async (
            string id,
            [FromBody] UpdateTenantRequest? request,
            ITenantActorResolver actorResolver,
            ITenantService tenantService,
            HttpContext httpContext,
            CancellationToken cancellationToken) =>
        {
            if (!Guid.TryParse(id, out var tenantId) || tenantId == Guid.Empty)
            {
                return TenantResultHttpMapper.CreateProblem(
                    httpContext,
                    StatusCodes.Status400BadRequest,
                    "Bad Request",
                    "The supplied tenant identifier is not a valid non-empty GUID.",
                    "INVALID_TENANT_ID");
            }

            if (request is null)
            {
                return TenantResultHttpMapper.CreateProblem(
                    httpContext,
                    StatusCodes.Status400BadRequest,
                    "Bad Request",
                    "Request body cannot be empty.",
                    "VALIDATION_FAILED");
            }

            if (!request.ExpectedVersion.HasValue)
            {
                return TenantResultHttpMapper.CreateProblem(
                    httpContext,
                    StatusCodes.Status400BadRequest,
                    "Bad Request",
                    "ExpectedVersion is required to update tenant settings.",
                    "MISSING_EXPECTED_VERSION");
            }

            if (request.ExpectedVersion.Value <= 0)
            {
                return TenantResultHttpMapper.CreateProblem(
                    httpContext,
                    StatusCodes.Status400BadRequest,
                    "Bad Request",
                    "ExpectedVersion must be a positive integer.",
                    "INVALID_EXPECTED_VERSION");
            }

            // Resolve server-side verified, trusted actor context with mandatory active tenant context
            var actorResolution = await actorResolver.ResolveActorAsync(
                httpContext.User,
                requireActiveTenantContext: true,
                cancellationToken);

            if (!actorResolution.IsSuccess || actorResolution.Actor is null)
            {
                return TenantResultHttpMapper.CreateProblem(
                    httpContext,
                    actorResolution.StatusCode,
                    actorResolution.ErrorTitle ?? "Unauthorized",
                    actorResolution.ErrorDetail ?? "Access denied.",
                    actorResolution.StatusCode == StatusCodes.Status401Unauthorized ? "UNAUTHORIZED" : "FORBIDDEN");
            }

            var callerActor = actorResolution.Actor;

            // Enforce strict consistency between route tenant ID and X-Tenant-ID active context
            if (!callerActor.TenantId.HasValue || callerActor.TenantId.Value != tenantId)
            {
                return TenantResultHttpMapper.CreateProblem(
                    httpContext,
                    StatusCodes.Status403Forbidden,
                    "Forbidden",
                    "Cross-tenant modification is denied: route tenant identifier does not match active tenant context.",
                    "FORBIDDEN");
            }

            var updateResult = await tenantService.UpdateTenantAsync(
                tenantId,
                request,
                callerActor,
                cancellationToken);

            return updateResult.ToHttpResult(httpContext);
        })
        .WithName("UpdateTenantSettings")
        .WithSummary("Update permitted tenant organization settings")
        .WithDescription("Updates permitted tenant settings (displayName) for an Active tenant. Requires Active Owner or Administrator membership, matching X-Tenant-ID context, and explicit ExpectedVersion concurrency precondition.")
        .RequireTenantContext()
        .Produces<TenantResponse>(StatusCodes.Status200OK)
        .ProducesProblem(StatusCodes.Status400BadRequest)
        .ProducesProblem(StatusCodes.Status401Unauthorized)
        .ProducesProblem(StatusCodes.Status403Forbidden)
        .ProducesProblem(StatusCodes.Status404NotFound)
        .ProducesProblem(StatusCodes.Status409Conflict);

        return endpoints;
    }
}

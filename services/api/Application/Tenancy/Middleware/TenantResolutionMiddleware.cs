namespace MaintenX.Api.Application.Tenancy.Middleware;

using MaintenX.Api.Application.Tenancy.Context;
using MaintenX.Api.Application.Tenancy.Resolution;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;

/// <summary>
/// Middleware executing after authentication that inspects endpoint metadata for <see cref="IRequireTenantContextMetadata"/>.
/// If required, evaluates the requested tenant via <see cref="ITenantResolutionService"/> and establishes the request-scoped
/// <see cref="ITenantContext"/>. Unauthenticated requests or invalid memberships are terminated with RFC 7807 Problem Details.
/// </summary>
public sealed class TenantResolutionMiddleware
{
    /// <summary>
    /// Standard HTTP header used by clients to explicitly select the target tenant.
    /// </summary>
    public const string TenantHeaderName = "X-Tenant-ID";

    /// <summary>
    /// Key used to store the verified <see cref="ITenantContext"/> in <see cref="HttpContext.Items"/>.
    /// </summary>
    public const string HttpContextItemKey = "TenantContext";

    private readonly RequestDelegate _next;

    public TenantResolutionMiddleware(RequestDelegate next)
    {
        _next = next ?? throw new ArgumentNullException(nameof(next));
    }

    public async Task InvokeAsync(
        HttpContext httpContext,
        ITenantResolutionService resolutionService,
        TenantContextAccessor contextAccessor)
    {
        ArgumentNullException.ThrowIfNull(httpContext);
        ArgumentNullException.ThrowIfNull(resolutionService);
        ArgumentNullException.ThrowIfNull(contextAccessor);

        var endpoint = httpContext.GetEndpoint();

        // 1. Check if endpoint is anonymous (skip tenant requirement)
        var isAnonymous = endpoint?.Metadata.GetMetadata<IAllowAnonymous>() is not null;
        var requiresTenant = !isAnonymous && endpoint?.Metadata.GetMetadata<IRequireTenantContextMetadata>() is not null;

        // 2. If endpoint does not require tenant context:
        // Check if an authenticated caller optionally supplied X-Tenant-ID to establish context opportunistically,
        // otherwise simply proceed without tenant context.
        if (!requiresTenant)
        {
            if (httpContext.User?.Identity?.IsAuthenticated == true &&
                httpContext.Request.Headers.TryGetValue(TenantHeaderName, out var optionalHeader) &&
                !string.IsNullOrWhiteSpace(optionalHeader))
            {
                var optionalResult = await resolutionService.ResolveAsync(
                    httpContext.User,
                    optionalHeader.ToString(),
                    httpContext.RequestAborted);

                if (optionalResult.IsSuccess && optionalResult.Context is not null)
                {
                    contextAccessor.SetContext(optionalResult.Context);
                    httpContext.Items[HttpContextItemKey] = optionalResult.Context;
                }
            }

            await _next(httpContext);
            return;
        }

        // 3. Endpoint strictly requires tenant context:
        string? requestedTenant = null;
        if (httpContext.Request.Headers.TryGetValue(TenantHeaderName, out var headerValue))
        {
            requestedTenant = headerValue.ToString();
        }

        var result = await resolutionService.ResolveAsync(
            httpContext.User,
            requestedTenant,
            httpContext.RequestAborted);

        if (!result.IsSuccess)
        {
            httpContext.Response.StatusCode = result.StatusCode;
            httpContext.Response.ContentType = "application/problem+json";

            var problem = new ProblemDetails
            {
                Status = result.StatusCode,
                Title = result.ErrorTitle,
                Detail = result.ErrorDetail,
                Instance = httpContext.Request.Path,
                Extensions =
                {
                    ["traceId"] = httpContext.TraceIdentifier,
                    ["timestamp"] = DateTimeOffset.UtcNow
                }
            };

            await httpContext.Response.WriteAsJsonAsync(
                problem,
                options: (System.Text.Json.JsonSerializerOptions?)null,
                contentType: "application/problem+json",
                cancellationToken: httpContext.RequestAborted);

            return;
        }

        contextAccessor.SetContext(result.Context!);
        httpContext.Items[HttpContextItemKey] = result.Context;

        await _next(httpContext);
    }
}

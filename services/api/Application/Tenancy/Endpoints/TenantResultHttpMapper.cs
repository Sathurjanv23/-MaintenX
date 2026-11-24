namespace MaintenX.Api.Application.Tenancy.Endpoints;

using MaintenX.Api.Application.Tenancy.Models;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;

/// <summary>
/// Centralized mapping helpers converting tenancy domain/application results to consistent HTTP responses.
/// Maps application outcomes to standard RFC 7807 Problem Details while concealing internal infrastructure details.
/// </summary>
public static class TenantResultHttpMapper
{
    /// <summary>
    /// Creates a standardized RFC 7807 ProblemDetails IResult for tenancy endpoints.
    /// </summary>
    public static IResult CreateProblem(
        HttpContext httpContext,
        int statusCode,
        string title,
        string detail,
        string? errorCode = null)
    {
        var problemDetails = new ProblemDetails
        {
            Status = statusCode,
            Title = title,
            Detail = detail,
            Instance = httpContext.Request.Path,
            Extensions =
            {
                ["traceId"] = httpContext.TraceIdentifier,
                ["timestamp"] = DateTimeOffset.UtcNow
            }
        };

        if (!string.IsNullOrWhiteSpace(errorCode))
        {
            problemDetails.Extensions["errorCode"] = errorCode;
        }

        return Results.Problem(problemDetails);
    }

    /// <summary>
    /// Maps a <see cref="CreateTenantResult"/> to an appropriate HTTP outcome.
    /// </summary>
    public static IResult ToHttpResult(this CreateTenantResult result, HttpContext httpContext, string? locationUri = null)
    {
        if (result.IsSuccess && result.Response is not null)
        {
            return locationUri is not null
                ? Results.Created(locationUri, result.Response)
                : Results.Created($"/api/v1/tenants/{result.Response.TenantId}", result.Response);
        }

        return CreateProblem(
            httpContext,
            result.StatusCode,
            GetStatusTitle(result.StatusCode),
            result.ErrorMessage ?? "Tenant creation failed.",
            result.ErrorCode);
    }

    /// <summary>
    /// Maps a <see cref="TenantResult"/> to an appropriate HTTP outcome.
    /// </summary>
    public static IResult ToHttpResult(this TenantResult result, HttpContext httpContext)
    {
        if (result.IsSuccess && result.Tenant is not null)
        {
            return Results.Ok(result.Tenant);
        }

        return CreateProblem(
            httpContext,
            result.StatusCode,
            GetStatusTitle(result.StatusCode),
            result.ErrorMessage ?? "Tenant operation failed.",
            result.ErrorCode);
    }

    /// <summary>
    /// Maps a <see cref="TenantLifecycleResult"/> to an appropriate HTTP outcome.
    /// </summary>
    public static IResult ToHttpResult(this TenantLifecycleResult result, HttpContext httpContext)
    {
        if (result.IsSuccess && result.Response is not null)
        {
            return Results.Ok(result.Response);
        }

        return CreateProblem(
            httpContext,
            result.StatusCode,
            GetStatusTitle(result.StatusCode),
            result.ErrorMessage ?? "Tenant lifecycle operation failed.",
            result.ErrorCode);
    }

    /// <summary>
    /// Maps a <see cref="TenantMembershipResult"/> to an appropriate HTTP outcome.
    /// </summary>
    public static IResult ToHttpResult(this TenantMembershipResult result, HttpContext httpContext)
    {
        if (result.IsSuccess && result.Membership is not null)
        {
            return Results.Ok(result.Membership);
        }

        return CreateProblem(
            httpContext,
            result.StatusCode,
            GetStatusTitle(result.StatusCode),
            result.ErrorMessage ?? "Tenant membership operation failed.",
            result.ErrorCode);
    }

    private static string GetStatusTitle(int statusCode) => statusCode switch
    {
        StatusCodes.Status400BadRequest => "Bad Request",
        StatusCodes.Status401Unauthorized => "Unauthorized",
        StatusCodes.Status403Forbidden => "Forbidden",
        StatusCodes.Status404NotFound => "Not Found",
        StatusCodes.Status409Conflict => "Conflict",
        StatusCodes.Status429TooManyRequests => "Too Many Requests",
        _ => "Internal Server Error"
    };
}

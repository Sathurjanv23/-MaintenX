namespace MaintenX.Api.Application.Tenancy.Resolution;

using MaintenX.Api.Application.Tenancy.Context;

/// <summary>
/// Result of a tenant resolution attempt containing either a verified <see cref="ITenantContext"/>
/// or failure information for RFC 7807 Problem Details generation.
/// </summary>
public sealed class TenantResolutionResult
{
    /// <summary>
    /// Indicates whether the tenant resolution and membership verification succeeded.
    /// </summary>
    public bool IsSuccess { get; }

    /// <summary>
    /// The verified, request-scoped tenant context when successful; otherwise null.
    /// </summary>
    public ITenantContext? Context { get; }

    /// <summary>
    /// The HTTP status code appropriate for the resolution outcome (e.g., 200, 400, 401, 403, 404).
    /// </summary>
    public int StatusCode { get; }

    /// <summary>
    /// Standardized title for error responses.
    /// </summary>
    public string? ErrorTitle { get; }

    /// <summary>
    /// Detailed diagnostic explanation for error responses.
    /// </summary>
    public string? ErrorDetail { get; }

    private TenantResolutionResult(bool isSuccess, ITenantContext? context, int statusCode, string? errorTitle, string? errorDetail)
    {
        IsSuccess = isSuccess;
        Context = context;
        StatusCode = statusCode;
        ErrorTitle = errorTitle;
        ErrorDetail = errorDetail;
    }

    /// <summary>
    /// Creates a successful resolution result.
    /// </summary>
    public static TenantResolutionResult Success(ITenantContext context)
    {
        ArgumentNullException.ThrowIfNull(context);
        return new TenantResolutionResult(true, context, 200, null, null);
    }

    /// <summary>
    /// Creates a failed resolution result with explicit status code and Problem Details information.
    /// </summary>
    public static TenantResolutionResult Failure(int statusCode, string title, string detail)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(title);
        ArgumentException.ThrowIfNullOrWhiteSpace(detail);
        return new TenantResolutionResult(false, null, statusCode, title, detail);
    }
}

namespace MaintenX.Api.Application.Tenancy.Models;

using MaintenX.Api.Application.Tenancy.Contracts;

/// <summary>
/// Application-layer outcome for tenant retrieval and settings modification.
/// </summary>
public sealed class TenantResult
{
    public bool IsSuccess { get; }
    public TenantResponse? Tenant { get; }
    public int StatusCode { get; }
    public string? ErrorCode { get; }
    public string? ErrorMessage { get; }

    private TenantResult(bool isSuccess, TenantResponse? tenant, int statusCode, string? errorCode, string? errorMessage)
    {
        IsSuccess = isSuccess;
        Tenant = tenant;
        StatusCode = statusCode;
        ErrorCode = errorCode;
        ErrorMessage = errorMessage;
    }

    public static TenantResult Success(TenantResponse tenant)
    {
        ArgumentNullException.ThrowIfNull(tenant);
        return new TenantResult(true, tenant, 200, null, null);
    }

    public static TenantResult NotFound(string message = "The requested tenant organization was not found.", string errorCode = "TENANT_NOT_FOUND") =>
        new(false, null, 404, errorCode, message);

    public static TenantResult Forbidden(string message = "Access to the requested tenant organization is denied.", string errorCode = "FORBIDDEN") =>
        new(false, null, 403, errorCode, message);

    public static TenantResult ValidationFailed(string message, string errorCode = "VALIDATION_FAILED") =>
        new(false, null, 400, errorCode, message);

    public static TenantResult Conflict(string message, string errorCode = "CONCURRENCY_CONFLICT") =>
        new(false, null, 409, errorCode, message);
}

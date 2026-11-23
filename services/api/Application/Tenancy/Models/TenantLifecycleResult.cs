namespace MaintenX.Api.Application.Tenancy.Models;

using MaintenX.Api.Application.Tenancy.Contracts;

/// <summary>
/// Application-layer outcome for tenant lifecycle operations (activation, suspension, deactivation).
/// </summary>
public sealed class TenantLifecycleResult
{
    public bool IsSuccess { get; }
    public TenantLifecycleResponse? Response { get; }
    public int StatusCode { get; }
    public string? ErrorCode { get; }
    public string? ErrorMessage { get; }

    private TenantLifecycleResult(bool isSuccess, TenantLifecycleResponse? response, int statusCode, string? errorCode, string? errorMessage)
    {
        IsSuccess = isSuccess;
        Response = response;
        StatusCode = statusCode;
        ErrorCode = errorCode;
        ErrorMessage = errorMessage;
    }

    public static TenantLifecycleResult Success(TenantLifecycleResponse response)
    {
        ArgumentNullException.ThrowIfNull(response);
        return new TenantLifecycleResult(true, response, 200, null, null);
    }

    public static TenantLifecycleResult NotFound(string message = "The requested tenant organization was not found.", string errorCode = "TENANT_NOT_FOUND") =>
        new(false, null, 404, errorCode, message);

    public static TenantLifecycleResult Forbidden(string message = "Access to perform tenant lifecycle operations is denied.", string errorCode = "FORBIDDEN") =>
        new(false, null, 403, errorCode, message);

    public static TenantLifecycleResult InvalidState(string message, string errorCode = "INVALID_LIFECYCLE_TRANSITION") =>
        new(false, null, 400, errorCode, message);

    public static TenantLifecycleResult Conflict(string message, string errorCode = "CONCURRENCY_CONFLICT") =>
        new(false, null, 409, errorCode, message);
}

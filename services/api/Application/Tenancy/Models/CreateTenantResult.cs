namespace MaintenX.Api.Application.Tenancy.Models;

using MaintenX.Api.Application.Tenancy.Contracts;

/// <summary>
/// Application-layer outcome for tenant creation and initial onboarding.
/// </summary>
public sealed class CreateTenantResult
{
    public bool IsSuccess { get; }
    public CreateTenantResponse? Response { get; }
    public int StatusCode { get; }
    public string? ErrorCode { get; }
    public string? ErrorMessage { get; }

    private CreateTenantResult(bool isSuccess, CreateTenantResponse? response, int statusCode, string? errorCode, string? errorMessage)
    {
        IsSuccess = isSuccess;
        Response = response;
        StatusCode = statusCode;
        ErrorCode = errorCode;
        ErrorMessage = errorMessage;
    }

    public static CreateTenantResult Success(CreateTenantResponse response)
    {
        ArgumentNullException.ThrowIfNull(response);
        return new CreateTenantResult(true, response, 201, null, null);
    }

    public static CreateTenantResult Conflict(string message, string errorCode = "TENANT_SLUG_CONFLICT") =>
        new(false, null, 409, errorCode, message);

    public static CreateTenantResult ValidationFailed(string message, string errorCode = "VALIDATION_FAILED") =>
        new(false, null, 400, errorCode, message);

    public static CreateTenantResult Unauthorized(string message = "Unauthorized", string errorCode = "UNAUTHORIZED") =>
        new(false, null, 401, errorCode, message);

    public static CreateTenantResult Forbidden(string message = "Access to perform tenant onboarding is denied.", string errorCode = "FORBIDDEN") =>
        new(false, null, 403, errorCode, message);
}

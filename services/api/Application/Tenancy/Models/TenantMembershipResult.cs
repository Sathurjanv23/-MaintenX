namespace MaintenX.Api.Application.Tenancy.Models;

using MaintenX.Api.Application.Tenancy.Contracts;

/// <summary>
/// Application-layer outcome for single tenant membership queries and operations.
/// </summary>
public sealed class TenantMembershipResult
{
    public bool IsSuccess { get; }
    public TenantMembershipResponse? Membership { get; }
    public int StatusCode { get; }
    public string? ErrorCode { get; }
    public string? ErrorMessage { get; }

    private TenantMembershipResult(bool isSuccess, TenantMembershipResponse? membership, int statusCode, string? errorCode, string? errorMessage)
    {
        IsSuccess = isSuccess;
        Membership = membership;
        StatusCode = statusCode;
        ErrorCode = errorCode;
        ErrorMessage = errorMessage;
    }

    public static TenantMembershipResult Success(TenantMembershipResponse membership)
    {
        ArgumentNullException.ThrowIfNull(membership);
        return new TenantMembershipResult(true, membership, 200, null, null);
    }

    public static TenantMembershipResult NotFound(string message = "The requested membership was not found.", string errorCode = "MEMBERSHIP_NOT_FOUND") =>
        new(false, null, 404, errorCode, message);

    public static TenantMembershipResult Forbidden(string message = "Access to the requested membership is denied.", string errorCode = "FORBIDDEN") =>
        new(false, null, 403, errorCode, message);

    public static TenantMembershipResult ValidationFailed(string message, string errorCode = "VALIDATION_FAILED") =>
        new(false, null, 400, errorCode, message);

    public static TenantMembershipResult Conflict(string message, string errorCode = "MEMBERSHIP_CONFLICT") =>
        new(false, null, 409, errorCode, message);
}

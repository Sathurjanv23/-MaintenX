namespace MaintenX.Api.Application.Auth.Models;

/// <summary>
/// Result of user session logout. Idempotent by design.
/// </summary>
public sealed record LogoutResult(
    bool IsSuccess,
    string? Message)
{
    public static LogoutResult Success() =>
        new(true, "Successfully logged out.");

    public static LogoutResult Failed(string message) =>
        new(false, message);
}

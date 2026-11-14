namespace MaintenX.Api.Application.Auth.Models;

/// <summary>
/// Result of password mutation (password change, authorized reset, administrative reset).
/// </summary>
public sealed record PasswordMutationResult(
    bool IsSuccess,
    string? ErrorMessage)
{
    public static PasswordMutationResult Success() =>
        new(true, null);

    public static PasswordMutationResult Failed(string message) =>
        new(false, message);
}

namespace MaintenX.Api.Application.Auth.Contracts;

/// <summary>
/// Response payload for password mutation operations.
/// </summary>
/// <param name="Message">Informational message confirming password change and session invalidation.</param>
public sealed record PasswordMutationResponse(string Message)
{
    public const string DefaultMessage = "Password changed successfully. All active sessions have been revoked.";

    public static PasswordMutationResponse Success() => new(DefaultMessage);
}

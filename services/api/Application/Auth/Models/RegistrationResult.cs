namespace MaintenX.Api.Application.Auth.Models;

/// <summary>
/// Result of user registration. Returns a uniform message regardless of whether the email is newly registered
/// or already exists, completely eliminating account enumeration side-channels.
/// </summary>
public sealed record RegistrationResult(
    bool IsSuccess,
    string Message)
{
    public const string DefaultGenericMessage =
        "If the email address is eligible, an account initialization has been processed.";

    public static RegistrationResult GenericSuccess() =>
        new(true, DefaultGenericMessage);

    public static RegistrationResult Failed(string message) =>
        new(false, message);
}

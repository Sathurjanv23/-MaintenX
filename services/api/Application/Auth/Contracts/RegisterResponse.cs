namespace MaintenX.Api.Application.Auth.Contracts;

/// <summary>
/// Response payload for user registration. Returns a generic neutral message to prevent account enumeration.
/// </summary>
/// <param name="Message">Generic informational message regarding account creation.</param>
public sealed record RegisterResponse(string Message)
{
    public const string DefaultMessage = "If the email address is eligible, an account initialization has been processed.";

    public static RegisterResponse Generic() => new(DefaultMessage);
}

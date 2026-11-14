namespace MaintenX.Api.Application.Auth.Models;

/// <summary>
/// Result of user authentication. Distinguishes success, invalid credentials, and account lockout.
/// </summary>
public sealed record LoginResult(
    bool IsSuccess,
    AuthTokenResult? Tokens,
    bool IsLockedOut,
    DateTime? LockoutEndUtc,
    string? ErrorMessage)
{
    public static LoginResult Success(AuthTokenResult tokens) =>
        new(true, tokens, false, null, null);

    public static LoginResult InvalidCredentials() =>
        new(false, null, false, null, "Invalid email or password.");

    public static LoginResult LockedOut(DateTime lockoutEndUtc) =>
        new(false, null, true, lockoutEndUtc, $"Account is temporarily locked out until {lockoutEndUtc:O} due to repeated failed login attempts.");

    public static LoginResult Failed(string message) =>
        new(false, null, false, null, message);

    /// <summary>
    /// Redacts tokens and secret details from string representation.
    /// </summary>
    public override string ToString() =>
        $"LoginResult [IsSuccess={IsSuccess}, IsLockedOut={IsLockedOut}, LockoutEndUtc={LockoutEndUtc:O}, ErrorMessage={ErrorMessage}]";
}

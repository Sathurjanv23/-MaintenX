namespace MaintenX.Api.Application.Auth.Contracts;

/// <summary>
/// Request payload for updating the authenticated user's password.
/// </summary>
/// <param name="CurrentPassword">The user's current plaintext password for verification.</param>
/// <param name="NewPassword">The proposed new password meeting length and complexity rules.</param>
public sealed record ChangePasswordRequest(string CurrentPassword, string NewPassword)
{
    /// <summary>
    /// Redacts passwords in string representations and logs.
    /// </summary>
    public override string ToString() =>
        "ChangePasswordRequest [CurrentPassword=[REDACTED], NewPassword=[REDACTED]]";
}

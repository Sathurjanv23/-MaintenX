namespace MaintenX.Api.Application.Auth.Contracts;

/// <summary>
/// Request payload for user login.
/// </summary>
/// <param name="Email">Normalized user email address.</param>
/// <param name="Password">Plaintext account password.</param>
public sealed record LoginRequest(string Email, string Password)
{
    /// <summary>
    /// Redacts password in string representations and logs.
    /// </summary>
    public override string ToString() =>
        $"LoginRequest [Email={Email}, Password=[REDACTED]]";
}

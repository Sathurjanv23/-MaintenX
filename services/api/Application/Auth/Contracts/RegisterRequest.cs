namespace MaintenX.Api.Application.Auth.Contracts;

/// <summary>
/// Request payload for user registration.
/// </summary>
/// <param name="Email">Raw email address of the user.</param>
/// <param name="Password">Plaintext password string meeting complexity and length constraints.</param>
public sealed record RegisterRequest(string Email, string Password)
{
    /// <summary>
    /// Redacts password in string representations and logs.
    /// </summary>
    public override string ToString() =>
        $"RegisterRequest [Email={Email}, Password=[REDACTED]]";
}

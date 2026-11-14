namespace MaintenX.Api.Application.Auth.Validation;

/// <summary>
/// Enforces password complexity, length, and safe validation rules without disclosing input characters.
/// </summary>
public static class PasswordValidation
{
    public const int MinPasswordLength = 12;
    public const int MaxPasswordLength = 128;

    /// <summary>
    /// Validates password length and format invariants without echoing the provided password.
    /// </summary>
    /// <param name="password">Plaintext password string.</param>
    /// <exception cref="ArgumentException">Thrown when password is null, whitespace, or outside length constraints.</exception>
    public static void Validate(string? password)
    {
        if (string.IsNullOrWhiteSpace(password))
        {
            throw new ArgumentException("Password cannot be empty or consist solely of whitespace.", nameof(password));
        }

        if (password.Length < MinPasswordLength || password.Length > MaxPasswordLength)
        {
            throw new ArgumentException(
                $"Password length must be between {MinPasswordLength} and {MaxPasswordLength} characters.",
                nameof(password));
        }
    }
}

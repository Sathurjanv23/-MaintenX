namespace MaintenX.Api.Common.Security;

using MaintenX.Api.Domain.Auth;
using Microsoft.AspNetCore.Identity;

/// <summary>
/// Thread-safe implementation of <see cref="IPasswordSecurityService"/> utilizing ASP.NET Core's
/// <see cref="IPasswordHasher{User}"/> with timing-attack mitigation.
/// </summary>
public sealed class PasswordSecurityService : IPasswordSecurityService
{
    private readonly IPasswordHasher<User> _passwordHasher;
    private readonly User _dummyUser;
    private readonly string _dummyHash;

    /// <summary>
    /// Gets the precomputed dummy password hash used for nonexistent user timing attack mitigation.
    /// </summary>
    public string DummyHash => _dummyHash;

    public PasswordSecurityService(IPasswordHasher<User> passwordHasher)
    {
        _passwordHasher = passwordHasher ?? throw new ArgumentNullException(nameof(passwordHasher));
        _dummyUser = new User();

        // Precompute a valid PBKDF2 hash using the configured hasher so nonexistent user authentication
        // can execute the exact same cryptographic iterations without throwing format exceptions.
        _dummyHash = _passwordHasher.HashPassword(_dummyUser, "MaintenX-ConstantTime-DummyHash-Password-Seed-2026!");
    }

    /// <inheritdoc />
    public string HashPassword(User user, string password)
    {
        ArgumentNullException.ThrowIfNull(user);
        ArgumentException.ThrowIfNullOrWhiteSpace(password);

        return _passwordHasher.HashPassword(user, password);
    }

    /// <inheritdoc />
    public PasswordVerificationResult VerifyHashedPassword(User user, string hashedPassword, string providedPassword)
    {
        ArgumentNullException.ThrowIfNull(user);

        if (string.IsNullOrWhiteSpace(hashedPassword) || string.IsNullOrWhiteSpace(providedPassword))
        {
            return PasswordVerificationResult.Failed;
        }

        return _passwordHasher.VerifyHashedPassword(user, hashedPassword.Trim(), providedPassword);
    }

    /// <inheritdoc />
    public bool NeedsRehash(PasswordVerificationResult result)
    {
        return result == PasswordVerificationResult.SuccessRehashNeeded;
    }

    /// <inheritdoc />
    public void VerifyDummyPassword(string providedPassword)
    {
        // Execute the exact password verification algorithm against the precomputed dummy hash.
        // Even if providedPassword is null or empty, provide a fallback non-empty string so PBKDF2 executes.
        var passwordToVerify = string.IsNullOrEmpty(providedPassword) ? "dummy" : providedPassword;
        _passwordHasher.VerifyHashedPassword(_dummyUser, _dummyHash, passwordToVerify);
    }

    /// <summary>
    /// Redacts secret material from diagnostic string representation.
    /// </summary>
    public override string ToString() => "PasswordSecurityService [ASP.NET Core Identity PasswordHasher]";
}

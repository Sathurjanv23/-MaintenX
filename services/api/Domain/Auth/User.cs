namespace MaintenX.Api.Domain.Auth;

using System.Security.Cryptography;
using System.Text.RegularExpressions;

/// <summary>
/// User identity entity managing credentials, security stamp, lockout lifecycle, and account status.
/// Independent of EF Core and ASP.NET Core infrastructure.
/// </summary>
public sealed class User
{
    private static readonly Regex EmailFormatRegex = new(
        @"^[^@\s]+@[^@\s]+\.[^@\s]+$",
        RegexOptions.Compiled | RegexOptions.CultureInvariant);

    /// <summary>
    /// Unique UUID primary key for the user.
    /// </summary>
    public Guid Id { get; set; }

    /// <summary>
    /// Normalized unique email address (trimmed, lowercase invariant).
    /// </summary>
    public string Email { get; set; } = string.Empty;

    /// <summary>
    /// Cryptographic password hash (e.g. Argon2id / PBKDF2). Never exposed via public representations.
    /// </summary>
    public string PasswordHash { get; set; } = string.Empty;

    /// <summary>
    /// Random security stamp rotated upon credential mutations or account suspension to invalidate active sessions and tokens.
    /// </summary>
    public string SecurityStamp { get; set; } = string.Empty;

    /// <summary>
    /// Operational status of the user account.
    /// </summary>
    public UserStatus Status { get; set; } = UserStatus.PendingVerification;

    /// <summary>
    /// Counter tracking consecutive failed authentication attempts within the current lockout evaluation window.
    /// </summary>
    public int FailedLoginAttempts { get; set; }

    /// <summary>
    /// UTC timestamp marking the expiration of an active account lockout, or null if the account is not locked out.
    /// </summary>
    public DateTime? LockoutEndUtc { get; set; }

    /// <summary>
    /// UTC timestamp of the most recent successful login, or null if the user has never logged in.
    /// </summary>
    public DateTime? LastLoginAtUtc { get; set; }

    /// <summary>
    /// UTC timestamp of entity creation.
    /// </summary>
    public DateTime CreatedAtUtc { get; set; }

    /// <summary>
    /// UTC timestamp of the most recent update.
    /// </summary>
    public DateTime UpdatedAtUtc { get; set; }

    /// <summary>
    /// Optimistic concurrency token tracking row mutations.
    /// </summary>
    public long Version { get; set; }

    /// <summary>
    /// Parameterless constructor required by EF Core.
    /// </summary>
    public User()
    {
    }

    /// <summary>
    /// Generates a cryptographically strong random string suitable for a security stamp.
    /// </summary>
    public static string GenerateSecurityStamp()
    {
        var bytes = new byte[32];
        RandomNumberGenerator.Fill(bytes);
        return Convert.ToHexString(bytes).ToLowerInvariant();
    }

    /// <summary>
    /// Normalizes and validates an email string.
    /// Invariants: Non-empty, trimmed, lowercase invariant, maximum 256 characters, valid RFC format with local and domain parts.
    /// </summary>
    /// <param name="email">Raw email address input.</param>
    /// <returns>Normalized lowercase email string.</returns>
    /// <exception cref="ArgumentException">Thrown when the email is null, whitespace, exceeds 256 characters, or violates format.</exception>
    public static string NormalizeAndValidateEmail(string email)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(email);

        var trimmed = email.Trim();
        if (string.IsNullOrWhiteSpace(trimmed))
        {
            throw new ArgumentException("Email address cannot be empty or whitespace.", nameof(email));
        }

        var normalized = trimmed.ToLowerInvariant();

        if (normalized.Length > 256)
        {
            throw new ArgumentException(
                $"Email address cannot exceed 256 characters in length. Supplied length was {normalized.Length}.",
                nameof(email));
        }

        if (normalized.Contains(' '))
        {
            throw new ArgumentException("Email address cannot contain whitespace.", nameof(email));
        }

        var atIndex = normalized.IndexOf('@');
        if (atIndex <= 0 || atIndex != normalized.LastIndexOf('@') || atIndex == normalized.Length - 1)
        {
            throw new ArgumentException($"Email address '{email}' is invalid. Must contain exactly one '@' character between local and domain parts.", nameof(email));
        }

        var localPart = normalized[..atIndex];
        var domainPart = normalized[(atIndex + 1)..];

        if (localPart.Length > 64)
        {
            throw new ArgumentException($"Email local part cannot exceed 64 characters. Supplied length was {localPart.Length}.", nameof(email));
        }

        if (!domainPart.Contains('.') || domainPart.StartsWith('.') || domainPart.EndsWith('.'))
        {
            throw new ArgumentException($"Email domain part '{domainPart}' is invalid. Must contain a valid top-level domain.", nameof(email));
        }

        if (!EmailFormatRegex.IsMatch(normalized))
        {
            throw new ArgumentException($"Email address '{email}' does not conform to valid email address syntax.", nameof(email));
        }

        return normalized;
    }

    /// <summary>
    /// Factory method for creating a new User instance with validated invariants.
    /// </summary>
    /// <param name="email">Email address.</param>
    /// <param name="passwordHash">Cryptographic password hash.</param>
    /// <param name="status">Initial user status (defaults to Active).</param>
    /// <param name="utcNow">Optional creation timestamp; defaults to DateTime.UtcNow if not supplied.</param>
    /// <returns>A validated User instance.</returns>
    public static User Create(
        string email,
        string passwordHash,
        UserStatus status = UserStatus.Active,
        DateTime? utcNow = null)
    {
        var normalizedEmail = NormalizeAndValidateEmail(email);
        ArgumentException.ThrowIfNullOrWhiteSpace(passwordHash);

        var now = utcNow ?? DateTime.UtcNow;

        return new User
        {
            Id = Guid.NewGuid(),
            Email = normalizedEmail,
            PasswordHash = passwordHash.Trim(),
            SecurityStamp = GenerateSecurityStamp(),
            Status = status,
            FailedLoginAttempts = 0,
            LockoutEndUtc = null,
            LastLoginAtUtc = null,
            CreatedAtUtc = now,
            UpdatedAtUtc = now,
            Version = 1
        };
    }

    /// <summary>
    /// Determines whether the account is currently locked out as of the supplied UTC timestamp.
    /// </summary>
    public bool IsLockedOut(DateTime utcNow)
    {
        return LockoutEndUtc.HasValue && LockoutEndUtc.Value > utcNow;
    }

    /// <summary>
    /// Determines whether the user account is eligible to authenticate (must be Active and not locked out).
    /// </summary>
    public bool CanAuthenticate(DateTime utcNow)
    {
        return Status == UserStatus.Active && !IsLockedOut(utcNow);
    }

    /// <summary>
    /// Records a failed authentication attempt. Increments failed login count and triggers lockout if threshold is reached.
    /// Inactive or suspended accounts do not update lockout state.
    /// </summary>
    /// <param name="utcNow">Current UTC timestamp.</param>
    /// <param name="maxFailedAttempts">Threshold before account lockout is applied (defaults to 5).</param>
    /// <param name="lockoutDuration">Duration of account lockout (defaults to 15 minutes).</param>
    public void RecordFailedLogin(
        DateTime utcNow,
        int maxFailedAttempts = 5,
        TimeSpan? lockoutDuration = null)
    {
        if (Status != UserStatus.Active)
        {
            return;
        }

        FailedLoginAttempts++;

        if (FailedLoginAttempts >= maxFailedAttempts)
        {
            var duration = lockoutDuration ?? TimeSpan.FromMinutes(15);
            LockoutEndUtc = utcNow.Add(duration);
        }

        UpdatedAtUtc = utcNow;
        Version++;
    }

    /// <summary>
    /// Records a successful authentication event. Resets failed login counters and updates last login timestamp.
    /// </summary>
    /// <param name="utcNow">Current UTC timestamp.</param>
    /// <exception cref="InvalidOperationException">Thrown if the user cannot authenticate (e.g. suspended, deactivated, or locked out).</exception>
    public void RecordSuccessfulLogin(DateTime utcNow)
    {
        if (!CanAuthenticate(utcNow))
        {
            throw new InvalidOperationException($"Cannot record successful login for user '{Id}' with status '{Status}' (LockedOut={IsLockedOut(utcNow)}).");
        }

        FailedLoginAttempts = 0;
        LockoutEndUtc = null;
        LastLoginAtUtc = utcNow;
        UpdatedAtUtc = utcNow;
        Version++;
    }

    /// <summary>
    /// Resets failed login counters and clears active lockout.
    /// </summary>
    /// <param name="utcNow">Current UTC timestamp.</param>
    public void ResetFailedLogin(DateTime utcNow)
    {
        FailedLoginAttempts = 0;
        LockoutEndUtc = null;
        UpdatedAtUtc = utcNow;
        Version++;
    }

    /// <summary>
    /// Updates the user's password hash and automatically rotates the security stamp to invalidate all prior sessions.
    /// Resets failed login counters and active lockout.
    /// </summary>
    /// <param name="newPasswordHash">New password hash.</param>
    /// <param name="utcNow">Current UTC timestamp.</param>
    /// <exception cref="InvalidOperationException">Thrown if the user account is not active.</exception>
    public void UpdatePassword(string newPasswordHash, DateTime utcNow)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(newPasswordHash);

        if (Status != UserStatus.Active)
        {
            throw new InvalidOperationException($"Cannot update password for user '{Id}' with status '{Status}'. Only active accounts can change passwords.");
        }

        PasswordHash = newPasswordHash.Trim();
        SecurityStamp = GenerateSecurityStamp();
        FailedLoginAttempts = 0;
        LockoutEndUtc = null;
        UpdatedAtUtc = utcNow;
        Version++;
    }

    /// <summary>
    /// Rotates the security stamp to invalidate all active sessions and refresh tokens without modifying credentials.
    /// </summary>
    /// <param name="utcNow">Current UTC timestamp.</param>
    public void RotateSecurityStamp(DateTime utcNow)
    {
        SecurityStamp = GenerateSecurityStamp();
        UpdatedAtUtc = utcNow;
        Version++;
    }

    /// <summary>
    /// Transitions account status to Active (e.g. from PendingVerification).
    /// </summary>
    /// <param name="utcNow">Current UTC timestamp.</param>
    /// <exception cref="InvalidOperationException">Thrown if the account is permanently deactivated.</exception>
    public void Activate(DateTime utcNow)
    {
        if (Status == UserStatus.Deactivated)
        {
            throw new InvalidOperationException($"Permanently deactivated user '{Id}' cannot be activated.");
        }

        Status = UserStatus.Active;
        UpdatedAtUtc = utcNow;
        Version++;
    }

    /// <summary>
    /// Administratively suspends the account, rotating the security stamp to invalidate existing sessions.
    /// </summary>
    /// <param name="utcNow">Current UTC timestamp.</param>
    /// <exception cref="InvalidOperationException">Thrown if the account is permanently deactivated.</exception>
    public void Suspend(DateTime utcNow)
    {
        if (Status == UserStatus.Deactivated)
        {
            throw new InvalidOperationException($"Permanently deactivated user '{Id}' cannot be suspended.");
        }

        Status = UserStatus.Suspended;
        SecurityStamp = GenerateSecurityStamp();
        UpdatedAtUtc = utcNow;
        Version++;
    }

    /// <summary>
    /// Reactivates a suspended user account, rotating the security stamp.
    /// </summary>
    /// <param name="utcNow">Current UTC timestamp.</param>
    /// <exception cref="InvalidOperationException">Thrown if the account is not currently suspended.</exception>
    public void Reactivate(DateTime utcNow)
    {
        if (Status != UserStatus.Suspended)
        {
            throw new InvalidOperationException($"User '{Id}' is not suspended (current status: '{Status}'). Only suspended accounts can be reactivated.");
        }

        Status = UserStatus.Active;
        SecurityStamp = GenerateSecurityStamp();
        FailedLoginAttempts = 0;
        LockoutEndUtc = null;
        UpdatedAtUtc = utcNow;
        Version++;
    }

    /// <summary>
    /// Permanently deactivates the user account and rotates the security stamp.
    /// Deactivation is a terminal lifecycle state.
    /// </summary>
    /// <param name="utcNow">Current UTC timestamp.</param>
    public void Deactivate(DateTime utcNow)
    {
        Status = UserStatus.Deactivated;
        SecurityStamp = GenerateSecurityStamp();
        UpdatedAtUtc = utcNow;
        Version++;
    }

    /// <summary>
    /// Returns a string representation of the user entity strictly omitting password hash and security stamp.
    /// </summary>
    public override string ToString()
    {
        return $"User [Id={Id}, Email={Email}, Status={Status}, FailedAttempts={FailedLoginAttempts}, IsLockedOut={LockoutEndUtc.HasValue}]";
    }
}

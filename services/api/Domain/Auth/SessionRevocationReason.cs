namespace MaintenX.Api.Domain.Auth;

using System.Collections.Frozen;

/// <summary>
/// Strongly typed enum corresponding to approved session revocation reasons.
/// </summary>
public enum SessionRevocationReasonType
{
    UserLogout = 1,
    PasswordChanged = 2,
    SecurityStampMismatch = 3,
    AccountSuspended = 4,
    AccountDeactivated = 5,
    TokenReplayDetected = 6,
    AdminRevoked = 7,
    Expired = 8
}

/// <summary>
/// Standardized reasons for user session revocation across the platform.
/// Enforces a closed, genuinely immutable set of permitted revocation reasons.
/// </summary>
public static class SessionRevocationReason
{
    public const string UserLogout = "UserLogout";
    public const string PasswordChanged = "PasswordChanged";
    public const string SecurityStampMismatch = "SecurityStampMismatch";
    public const string AccountSuspended = "AccountSuspended";
    public const string AccountDeactivated = "AccountDeactivated";
    public const string TokenReplayDetected = "TokenReplayDetected";
    public const string AdminRevoked = "AdminRevoked";
    public const string Expired = "Expired";

    /// <summary>
    /// Genuinely immutable set of permitted revocation reasons.
    /// Exposes a FrozenSet to guarantee immunity against casting mutations.
    /// </summary>
    public static readonly FrozenSet<string> AllowedReasons = new[]
    {
        UserLogout,
        PasswordChanged,
        SecurityStampMismatch,
        AccountSuspended,
        AccountDeactivated,
        TokenReplayDetected,
        AdminRevoked,
        Expired
    }.ToFrozenSet(StringComparer.Ordinal);

    /// <summary>
    /// Checks whether the supplied reason string belongs to the controlled set of approved revocation reasons.
    /// Case-sensitive check against the immutable set.
    /// </summary>
    public static bool IsValid(string? reason)
    {
        return !string.IsNullOrWhiteSpace(reason) && AllowedReasons.Contains(reason.Trim());
    }

    /// <summary>
    /// Validates and normalizes a session revocation reason string against approved platform values.
    /// </summary>
    /// <param name="reason">Supplied reason string.</param>
    /// <returns>Normalized canonical reason string.</returns>
    /// <exception cref="ArgumentException">Thrown when reason is null, whitespace, or not in the controlled allowed set.</exception>
    public static string ValidateAndNormalize(string reason)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(reason);

        var trimmed = reason.Trim();
        if (!AllowedReasons.Contains(trimmed))
        {
            throw new ArgumentException(
                "Session revocation reason is not approved.",
                nameof(reason));
        }

        return trimmed;
    }
}

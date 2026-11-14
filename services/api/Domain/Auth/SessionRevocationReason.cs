namespace MaintenX.Api.Domain.Auth;

/// <summary>
/// Standardized reasons for user session revocation across the platform.
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
}

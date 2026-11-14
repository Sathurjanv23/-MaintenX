namespace MaintenX.Api.Common.Security;

/// <summary>
/// Validates user security stamps using an in-memory cache with a 60-second absolute TTL,
/// falling back to PostgreSQL database lookup on cache misses.
/// Invalidates cached entries when user credentials, status, or security stamps mutate.
/// </summary>
public interface ISecurityStampValidator
{
    /// <summary>
    /// Validates whether the supplied security stamp matches the user's current security stamp
    /// and verifies that the user account is Active and not suspended or deactivated.
    /// </summary>
    /// <param name="userId">Unique user ID.</param>
    /// <param name="securityStamp">Security stamp presented in the JWT access token claim (sst).</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>True if the security stamp matches and user is active; otherwise false.</returns>
    Task<bool> ValidateAsync(Guid userId, string securityStamp, CancellationToken cancellationToken = default);

    /// <summary>
    /// Evicts the cached security stamp for the given user, forcing subsequent validations to query the database.
    /// Should be invoked upon password change, account suspension/reactivation/deactivation, or explicit stamp rotation.
    /// </summary>
    /// <param name="userId">Unique user ID.</param>
    void Invalidate(Guid userId);
}

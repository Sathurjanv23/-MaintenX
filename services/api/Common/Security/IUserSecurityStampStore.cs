namespace MaintenX.Api.Common.Security;

using MaintenX.Api.Domain.Auth;

/// <summary>
/// Abstraction for retrieving user security stamps and status from the persistence store.
/// Decouples cache and validation logic from EF Core database access.
/// </summary>
public interface IUserSecurityStampStore
{
    /// <summary>
    /// Retrieves the current security stamp and status for the specified user from the database.
    /// </summary>
    /// <param name="userId">Unique user ID.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>A <see cref="UserSecurityStampRecord"/> if found; otherwise null.</returns>
    Task<UserSecurityStampRecord?> GetSecurityStampAsync(Guid userId, CancellationToken cancellationToken = default);
}

/// <summary>
/// Record containing security stamp and account status for authentication validation.
/// </summary>
public sealed record UserSecurityStampRecord(
    string SecurityStamp,
    UserStatus Status)
{
    /// <summary>
    /// Redacts security stamp from string representation.
    /// </summary>
    public override string ToString() => $"UserSecurityStampRecord [Status={Status}, SecurityStamp=[REDACTED]]";
}

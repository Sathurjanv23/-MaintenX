namespace MaintenX.Api.Application.Auth.Persistence;

using MaintenX.Api.Domain.Auth;
using MaintenX.Api.Infrastructure.Persistence;
using Microsoft.EntityFrameworkCore;

/// <summary>
/// Row-level locking extensions implementing explicit PostgreSQL 'SELECT ... FOR UPDATE' queries.
/// Ensures serialization of concurrent authentication state updates without table locks.
/// </summary>
public static class AuthLockingExtensions
{
    /// <summary>
    /// Acquires an exclusive row lock on the specified user record within the active PostgreSQL transaction.
    /// </summary>
    public static Task<User?> LockUserForUpdateAsync(
        this MaintenXDbContext context,
        Guid userId,
        CancellationToken cancellationToken = default)
    {
        return context.Users
            .FromSqlInterpolated($"SELECT * FROM platform.users WHERE id = {userId} FOR UPDATE")
            .SingleOrDefaultAsync(cancellationToken);
    }

    /// <summary>
    /// Acquires an exclusive row lock on the specified user session within the active PostgreSQL transaction.
    /// </summary>
    public static Task<UserSession?> LockSessionForUpdateAsync(
        this MaintenXDbContext context,
        Guid sessionId,
        CancellationToken cancellationToken = default)
    {
        return context.UserSessions
            .FromSqlInterpolated($"SELECT * FROM platform.user_sessions WHERE id = {sessionId} FOR UPDATE")
            .SingleOrDefaultAsync(cancellationToken);
    }

    /// <summary>
    /// Acquires an exclusive row lock on the specified refresh token within the active PostgreSQL transaction.
    /// </summary>
    public static Task<RefreshToken?> LockRefreshTokenForUpdateAsync(
        this MaintenXDbContext context,
        Guid tokenId,
        CancellationToken cancellationToken = default)
    {
        return context.RefreshTokens
            .FromSqlInterpolated($"SELECT * FROM platform.refresh_tokens WHERE id = {tokenId} FOR UPDATE")
            .SingleOrDefaultAsync(cancellationToken);
    }

    /// <summary>
    /// Acquires exclusive row locks on all unrevoked sessions for a user using deterministic primary key ordering
    /// to eliminate deadlock vulnerabilities across concurrent session operations.
    /// </summary>
    public static Task<List<UserSession>> LockActiveSessionsForUserAsync(
        this MaintenXDbContext context,
        Guid userId,
        CancellationToken cancellationToken = default)
    {
        return context.UserSessions
            .FromSqlInterpolated($"SELECT * FROM platform.user_sessions WHERE user_id = {userId} AND revoked_at_utc IS NULL ORDER BY id FOR UPDATE")
            .ToListAsync(cancellationToken);
    }

    /// <summary>
    /// Bulk revokes all active child refresh tokens for a specific session within the active transaction.
    /// </summary>
    public static Task<int> RevokeActiveRefreshTokensForSessionAsync(
        this MaintenXDbContext context,
        Guid sessionId,
        DateTime utcNow,
        CancellationToken cancellationToken = default)
    {
        return context.Database.ExecuteSqlInterpolatedAsync(
            $"UPDATE platform.refresh_tokens SET revoked_at_utc = {utcNow} WHERE session_id = {sessionId} AND revoked_at_utc IS NULL",
            cancellationToken);
    }

    /// <summary>
    /// Bulk revokes all active child refresh tokens across all sessions owned by the specified user.
    /// </summary>
    public static Task<int> RevokeActiveRefreshTokensForUserAsync(
        this MaintenXDbContext context,
        Guid userId,
        DateTime utcNow,
        CancellationToken cancellationToken = default)
    {
        return context.Database.ExecuteSqlInterpolatedAsync(
            $"UPDATE platform.refresh_tokens SET revoked_at_utc = {utcNow} WHERE session_id IN (SELECT id FROM platform.user_sessions WHERE user_id = {userId}) AND revoked_at_utc IS NULL",
            cancellationToken);
    }
}

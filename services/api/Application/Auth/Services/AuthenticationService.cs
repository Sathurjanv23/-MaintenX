namespace MaintenX.Api.Application.Auth.Services;

using System.Data;
using MaintenX.Api.Application.Auth.Models;
using MaintenX.Api.Application.Auth.Persistence;
using MaintenX.Api.Application.Auth.Validation;
using MaintenX.Api.Common.Security;
using MaintenX.Api.Domain.Auth;
using MaintenX.Api.Infrastructure.Persistence;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging;
using Npgsql;

/// <summary>
/// Production implementation of <see cref="IAuthenticationService"/> orchestrating transactional
/// PostgreSQL row-locking, out-of-lock password hashing, single-flight token rotation, and durable audit logs.
/// </summary>
public sealed class AuthenticationService : IAuthenticationService
{
    private readonly MaintenXDbContext _dbContext;
    private readonly IPasswordSecurityService _passwordSecurityService;
    private readonly IJwtTokenService _jwtTokenService;
    private readonly IRefreshTokenService _refreshTokenService;
    private readonly ISecurityStampValidator _securityStampValidator;
    private readonly TimeProvider _timeProvider;
    private readonly ILogger<AuthenticationService> _logger;

    public AuthenticationService(
        MaintenXDbContext dbContext,
        IPasswordSecurityService passwordSecurityService,
        IJwtTokenService jwtTokenService,
        IRefreshTokenService refreshTokenService,
        ISecurityStampValidator securityStampValidator,
        TimeProvider? timeProvider = null,
        ILogger<AuthenticationService>? logger = null)
    {
        _dbContext = dbContext ?? throw new ArgumentNullException(nameof(dbContext));
        _passwordSecurityService = passwordSecurityService ?? throw new ArgumentNullException(nameof(passwordSecurityService));
        _jwtTokenService = jwtTokenService ?? throw new ArgumentNullException(nameof(jwtTokenService));
        _refreshTokenService = refreshTokenService ?? throw new ArgumentNullException(nameof(refreshTokenService));
        _securityStampValidator = securityStampValidator ?? throw new ArgumentNullException(nameof(securityStampValidator));
        _timeProvider = timeProvider ?? TimeProvider.System;
        _logger = logger ?? Microsoft.Extensions.Logging.Abstractions.NullLogger<AuthenticationService>.Instance;
    }

    /// <inheritdoc />
    public async Task<RegistrationResult> RegisterAsync(
        string email,
        string password,
        string? clientIp = null,
        CancellationToken cancellationToken = default)
    {
        var normalizedEmail = User.NormalizeAndValidateEmail(email);
        PasswordValidation.Validate(password);

        var utcNow = _timeProvider.GetUtcNow().UtcDateTime;

        // Timing-attack mitigation: Hash password BEFORE checking database existence so both new
        // and duplicate registrations incur the exact same computational work.
        var dummyUser = new User();
        var passwordHash = _passwordSecurityService.HashPassword(dummyUser, password);

        // Check if normalized email exists
        var exists = await _dbContext.Users
            .AnyAsync(u => u.Email == normalizedEmail, cancellationToken);

        if (exists)
        {
            // Record registration attempt without storing or echoing candidate email
            var auditEvent = SecurityAuditEvent.Create(
                SecurityAuditEventType.UserRegistered,
                utcNow,
                userId: null,
                sessionId: null,
                clientIp,
                SecurityAuditMetadata.Create(
                    SecurityAuditMetadata.Reasons.UserRegistration,
                    null,
                    SecurityAuditMetadata.Actions.Deny));

            _dbContext.SecurityAuditEvents.Add(auditEvent);
            await _dbContext.SaveChangesAsync(cancellationToken);

            return RegistrationResult.GenericSuccess();
        }

        var user = User.Create(normalizedEmail, passwordHash, UserStatus.Active, utcNow);
        var permitAudit = SecurityAuditEvent.Create(
            SecurityAuditEventType.UserRegistered,
            utcNow,
            user.Id,
            sessionId: null,
            clientIp,
            SecurityAuditMetadata.Create(
                SecurityAuditMetadata.Reasons.UserRegistration,
                null,
                SecurityAuditMetadata.Actions.Permit));

        _dbContext.Users.Add(user);
        _dbContext.SecurityAuditEvents.Add(permitAudit);

        try
        {
            await _dbContext.SaveChangesAsync(cancellationToken);
        }
        catch (DbUpdateException ex) when (IsUniqueEmailViolation(ex))
        {
            // Concurrent duplicate registration race captured safely by the unique database index
            _logger.LogInformation("Concurrent duplicate registration captured on index ix_users_email.");
            return RegistrationResult.GenericSuccess();
        }

        return RegistrationResult.GenericSuccess();
    }

    /// <inheritdoc />
    public async Task<LoginResult> LoginAsync(
        string email,
        string password,
        string? clientIp = null,
        CancellationToken cancellationToken = default)
    {
        var normalizedEmail = User.NormalizeAndValidateEmail(email);
        var utcNow = _timeProvider.GetUtcNow().UtcDateTime;

        // 1. Snapshot query
        var snapshot = await _dbContext.Users
            .AsNoTracking()
            .Where(u => u.Email == normalizedEmail)
            .Select(u => new
            {
                u.Id,
                u.PasswordHash,
                u.SecurityStamp,
                u.Status,
                u.LockoutEndUtc,
                u.FailedLoginAttempts,
                u.FailedLoginWindowStartedAtUtc,
                u.Version
            })
            .SingleOrDefaultAsync(cancellationToken);

        // 2. Nonexistent user handling: Execute dummy hash to consume identical CPU work
        if (snapshot == null)
        {
            _passwordSecurityService.VerifyDummyPassword(password);

            var audit = SecurityAuditEvent.Create(
                SecurityAuditEventType.LoginFailed,
                utcNow,
                userId: null,
                sessionId: null,
                clientIp,
                SecurityAuditMetadata.Create(
                    SecurityAuditMetadata.Reasons.InvalidCredentials,
                    null,
                    SecurityAuditMetadata.Actions.Deny));

            _dbContext.SecurityAuditEvents.Add(audit);
            await _dbContext.SaveChangesAsync(cancellationToken);

            return LoginResult.InvalidCredentials();
        }

        // 3. Check existing lockout
        if (snapshot.LockoutEndUtc.HasValue && snapshot.LockoutEndUtc.Value > utcNow)
        {
            _passwordSecurityService.VerifyDummyPassword(password);

            var audit = SecurityAuditEvent.Create(
                SecurityAuditEventType.LoginFailed,
                utcNow,
                snapshot.Id,
                sessionId: null,
                clientIp,
                SecurityAuditMetadata.Create(
                    SecurityAuditMetadata.Reasons.AccountLocked,
                    null,
                    SecurityAuditMetadata.Actions.Deny));

            _dbContext.SecurityAuditEvents.Add(audit);
            await _dbContext.SaveChangesAsync(cancellationToken);

            return LoginResult.LockedOut(snapshot.LockoutEndUtc.Value);
        }

        // 4. Verify password strictly OUTSIDE database transaction and row locks
        var verification = _passwordSecurityService.VerifyHashedPassword(new User(), snapshot.PasswordHash, password);

        // 5. Verification Failed Workflow
        if (verification == Microsoft.AspNetCore.Identity.PasswordVerificationResult.Failed)
        {
            await using var failTx = await _dbContext.Database.BeginTransactionAsync(IsolationLevel.ReadCommitted, cancellationToken);

            var lockedUser = await _dbContext.LockUserForUpdateAsync(snapshot.Id, cancellationToken);
            if (lockedUser == null)
            {
                await failTx.RollbackAsync(cancellationToken);
                return LoginResult.InvalidCredentials();
            }

            // Only apply failure count if user is active and password has not been changed concurrently
            if (lockedUser.Status == UserStatus.Active &&
                string.Equals(lockedUser.PasswordHash, snapshot.PasswordHash, StringComparison.Ordinal))
            {
                if (lockedUser.IsLockedOut(utcNow))
                {
                    await failTx.RollbackAsync(cancellationToken);
                    return LoginResult.LockedOut(lockedUser.LockoutEndUtc!.Value);
                }

                lockedUser.RecordFailedLogin(
                    utcNow,
                    maxFailedAttempts: 5,
                    lockoutDuration: TimeSpan.FromMinutes(15),
                    windowDuration: TimeSpan.FromMinutes(15));

                if (lockedUser.IsLockedOut(utcNow))
                {
                    var lockoutAudit = SecurityAuditEvent.Create(
                        SecurityAuditEventType.AccountLockedOut,
                        utcNow,
                        lockedUser.Id,
                        sessionId: null,
                        clientIp,
                        SecurityAuditMetadata.Create(
                            SecurityAuditMetadata.Reasons.AccountLocked,
                            null,
                            SecurityAuditMetadata.Actions.LockoutApplied));

                    _dbContext.SecurityAuditEvents.Add(lockoutAudit);
                }
                else
                {
                    var failAudit = SecurityAuditEvent.Create(
                        SecurityAuditEventType.LoginFailed,
                        utcNow,
                        lockedUser.Id,
                        sessionId: null,
                        clientIp,
                        SecurityAuditMetadata.Create(
                            SecurityAuditMetadata.Reasons.InvalidCredentials,
                            null,
                            SecurityAuditMetadata.Actions.Deny));

                    _dbContext.SecurityAuditEvents.Add(failAudit);
                }

                await _dbContext.SaveChangesAsync(cancellationToken);
                await failTx.CommitAsync(cancellationToken);

                if (lockedUser.IsLockedOut(utcNow))
                {
                    return LoginResult.LockedOut(lockedUser.LockoutEndUtc!.Value);
                }
            }
            else
            {
                await failTx.RollbackAsync(cancellationToken);
            }

            return LoginResult.InvalidCredentials();
        }

        // Precompute transparent password rehash OUTSIDE the database transaction and row lock
        string? precomputedRehash = null;
        if (_passwordSecurityService.NeedsRehash(verification))
        {
            precomputedRehash = _passwordSecurityService.HashPassword(new User(), password);
        }

        // 6. Verification Succeeded Workflow
        await using var successTx = await _dbContext.Database.BeginTransactionAsync(IsolationLevel.ReadCommitted, cancellationToken);

        var user = await _dbContext.LockUserForUpdateAsync(snapshot.Id, cancellationToken);
        if (user == null)
        {
            await successTx.RollbackAsync(cancellationToken);
            return LoginResult.InvalidCredentials();
        }

        // Revalidate snapshot inside row lock to prevent stale credentials or concurrent mutations from applying rehash or issuing tokens
        if (user.Status != UserStatus.Active ||
            user.IsLockedOut(utcNow) ||
            user.Version != snapshot.Version ||
            !string.Equals(user.SecurityStamp, snapshot.SecurityStamp, StringComparison.Ordinal) ||
            !string.Equals(user.PasswordHash, snapshot.PasswordHash, StringComparison.Ordinal))
        {
            await successTx.RollbackAsync(cancellationToken);
            return LoginResult.InvalidCredentials();
        }

        // Reset failed login state
        user.RecordSuccessfulLogin(utcNow);

        // Apply precomputed transparent rehash if required (preserves existing security stamp)
        if (!string.IsNullOrWhiteSpace(precomputedRehash))
        {
            user.RehashPassword(precomputedRehash, utcNow);
        }

        // Create 30-day absolute session
        var session = UserSession.Create(user.Id, utcNow, TimeSpan.FromDays(30));
        _dbContext.UserSessions.Add(session);

        // Generate 7-day refresh token capped at session boundary
        var generatedRefresh = _refreshTokenService.GenerateToken();
        var refreshTokenEntity = _refreshTokenService.CreateRefreshTokenEntity(session, generatedRefresh.TokenHash, utcNow);
        _dbContext.RefreshTokens.Add(refreshTokenEntity);

        // Security audit
        var loginAudit = SecurityAuditEvent.Create(
            SecurityAuditEventType.LoginSuccess,
            utcNow,
            user.Id,
            session.Id,
            clientIp,
            SecurityAuditMetadata.Create(
                SecurityAuditMetadata.Reasons.StandardLogin,
                SecurityAuditMetadata.Lineages.RootSession,
                SecurityAuditMetadata.Actions.SessionCreated));

        _dbContext.SecurityAuditEvents.Add(loginAudit);

        await _dbContext.SaveChangesAsync(cancellationToken);
        await successTx.CommitAsync(cancellationToken);

        // Issue 15-minute access JWT using committed session and current security stamp
        var accessJwt = _jwtTokenService.GenerateAccessToken(user.Id, session.Id, user.SecurityStamp);
        var tokenResult = new AuthTokenResult(
            accessJwt.Token,
            generatedRefresh.RawToken,
            accessJwt.ExpiresAtUtc,
            refreshTokenEntity.ExpiresAtUtc,
            session.Id);

        return LoginResult.Success(tokenResult);
    }

    /// <inheritdoc />
    public async Task<RefreshTokenResult> RefreshTokenAsync(
        string rawRefreshToken,
        string? clientIp = null,
        CancellationToken cancellationToken = default)
    {
        if (string.IsNullOrWhiteSpace(rawRefreshToken))
        {
            return RefreshTokenResult.Failed("Refresh token cannot be empty.");
        }

        var incomingHash = _refreshTokenService.HashToken(rawRefreshToken);
        var utcNow = _timeProvider.GetUtcNow().UtcDateTime;

        await using var tx = await _dbContext.Database.BeginTransactionAsync(IsolationLevel.ReadCommitted, cancellationToken);

        // 1. Locate refresh token record
        var tokenRecord = await _dbContext.RefreshTokens
            .AsNoTracking()
            .Where(t => t.TokenHash == incomingHash)
            .Select(t => new { t.Id, t.SessionId })
            .SingleOrDefaultAsync(cancellationToken);

        if (tokenRecord == null)
        {
            await tx.RollbackAsync(cancellationToken);
            return RefreshTokenResult.Failed("Invalid refresh token.");
        }

        // 2. Strict hierarchical lock ordering: Lock parent session first, then refresh token
        var session = await _dbContext.LockSessionForUpdateAsync(tokenRecord.SessionId, cancellationToken);
        var token = await _dbContext.LockRefreshTokenForUpdateAsync(tokenRecord.Id, cancellationToken);

        if (session == null || token == null)
        {
            await tx.RollbackAsync(cancellationToken);
            return RefreshTokenResult.Failed("Session or token not found.");
        }

        // 3. MANDATORY CRITICAL PRECEDENCE: Check replay attack BEFORE ordinary revoked/expired checks
        if (token.IsRotated)
        {
            // Replay detected: Revoke affected session family and active child tokens
            if (!session.IsRevoked)
            {
                session.Revoke(SessionRevocationReason.TokenReplayDetected, utcNow);
                await _dbContext.RevokeActiveRefreshTokensForSessionAsync(session.Id, utcNow, cancellationToken);
                _securityStampValidator.Invalidate(session.UserId);
            }

            var replayAudit = SecurityAuditEvent.Create(
                SecurityAuditEventType.TokenReplayDetected,
                utcNow,
                session.UserId,
                session.Id,
                clientIp,
                SecurityAuditMetadata.Create(
                    SecurityAuditMetadata.Reasons.TokenReplay,
                    SecurityAuditMetadata.Lineages.ReplayDetected,
                    SecurityAuditMetadata.Actions.SessionRevoked));

            _dbContext.SecurityAuditEvents.Add(replayAudit);
            await _dbContext.SaveChangesAsync(cancellationToken);
            await tx.CommitAsync(cancellationToken);

            return RefreshTokenResult.ReplayDetected();
        }

        // 4. Normal revocation and expiration checks
        if (session.IsRevoked)
        {
            await tx.RollbackAsync(cancellationToken);
            return RefreshTokenResult.Failed("Session has been revoked.");
        }

        if (session.IsExpired(utcNow))
        {
            await tx.RollbackAsync(cancellationToken);
            return RefreshTokenResult.Failed("Session has expired.");
        }

        if (token.IsRevoked)
        {
            await tx.RollbackAsync(cancellationToken);
            return RefreshTokenResult.Failed("Refresh token has been revoked.");
        }

        if (token.IsExpired(utcNow))
        {
            await tx.RollbackAsync(cancellationToken);
            return RefreshTokenResult.Failed("Refresh token has expired.");
        }

        // 5. Query user state directly from database (do NOT rely on cache for refresh authorization)
        var user = await _dbContext.Users
            .AsNoTracking()
            .Where(u => u.Id == session.UserId)
            .Select(u => new { u.Id, u.Status, u.SecurityStamp })
            .SingleOrDefaultAsync(cancellationToken);

        if (user == null || user.Status != UserStatus.Active)
        {
            await tx.RollbackAsync(cancellationToken);
            return RefreshTokenResult.Failed("User account is inactive or disabled.");
        }

        // 6. Execute atomic rotation
        session.RecordActivity(utcNow);

        var newGenerated = _refreshTokenService.GenerateToken();
        token.Rotate(newGenerated.TokenHash, utcNow);

        var newRefreshToken = _refreshTokenService.CreateRefreshTokenEntity(session, newGenerated.TokenHash, utcNow);
        _dbContext.RefreshTokens.Add(newRefreshToken);

        var refreshAudit = SecurityAuditEvent.Create(
            SecurityAuditEventType.TokenRefreshed,
            utcNow,
            session.UserId,
            session.Id,
            clientIp,
            SecurityAuditMetadata.Create(
                SecurityAuditMetadata.Reasons.TokenRefreshed,
                SecurityAuditMetadata.Lineages.SuccessorIssued,
                SecurityAuditMetadata.Actions.TokenRotated));

        _dbContext.SecurityAuditEvents.Add(refreshAudit);

        await _dbContext.SaveChangesAsync(cancellationToken);
        await tx.CommitAsync(cancellationToken);

        // Issue new access JWT
        var newAccessJwt = _jwtTokenService.GenerateAccessToken(user.Id, session.Id, user.SecurityStamp);
        var tokenResult = new AuthTokenResult(
            newAccessJwt.Token,
            newGenerated.RawToken,
            newAccessJwt.ExpiresAtUtc,
            newRefreshToken.ExpiresAtUtc,
            session.Id);

        return RefreshTokenResult.Success(tokenResult);
    }

    /// <inheritdoc />
    public async Task<LogoutResult> LogoutAsync(
        Guid sessionId,
        Guid? callerUserId = null,
        string? clientIp = null,
        CancellationToken cancellationToken = default)
    {
        if (sessionId == Guid.Empty)
        {
            return LogoutResult.Failed("Session ID cannot be empty.");
        }

        var utcNow = _timeProvider.GetUtcNow().UtcDateTime;

        await using var tx = await _dbContext.Database.BeginTransactionAsync(IsolationLevel.ReadCommitted, cancellationToken);

        var session = await _dbContext.LockSessionForUpdateAsync(sessionId, cancellationToken);
        if (session == null)
        {
            await tx.RollbackAsync(cancellationToken);
            return LogoutResult.Success(); // Idempotent
        }

        // Caller ownership verification
        if (callerUserId.HasValue && callerUserId.Value != Guid.Empty && session.UserId != callerUserId.Value)
        {
            await tx.RollbackAsync(cancellationToken);
            return LogoutResult.Failed("Unauthorized: session belongs to another identity.");
        }

        if (session.IsRevoked)
        {
            await tx.RollbackAsync(cancellationToken);
            return LogoutResult.Success(); // Idempotent
        }

        session.Revoke(SessionRevocationReason.UserLogout, utcNow);
        await _dbContext.RevokeActiveRefreshTokensForSessionAsync(session.Id, utcNow, cancellationToken);
        _securityStampValidator.Invalidate(session.UserId);

        var audit = SecurityAuditEvent.Create(
            SecurityAuditEventType.SessionRevoked,
            utcNow,
            session.UserId,
            session.Id,
            clientIp,
            SecurityAuditMetadata.Create(
                SecurityAuditMetadata.Reasons.UserLogout,
                null,
                SecurityAuditMetadata.Actions.SessionRevoked));

        _dbContext.SecurityAuditEvents.Add(audit);
        await _dbContext.SaveChangesAsync(cancellationToken);
        await tx.CommitAsync(cancellationToken);

        return LogoutResult.Success();
    }

    /// <inheritdoc />
    public async Task<PasswordMutationResult> ChangePasswordAsync(
        Guid userId,
        string currentPassword,
        string newPassword,
        string? clientIp = null,
        CancellationToken cancellationToken = default)
    {
        if (userId == Guid.Empty)
        {
            return PasswordMutationResult.Failed("User ID cannot be empty.");
        }

        PasswordValidation.Validate(newPassword);
        var utcNow = _timeProvider.GetUtcNow().UtcDateTime;

        // 1. Snapshot query
        var snapshot = await _dbContext.Users
            .AsNoTracking()
            .Where(u => u.Id == userId)
            .Select(u => new { u.Id, u.PasswordHash, u.SecurityStamp, u.Status, u.Version })
            .SingleOrDefaultAsync(cancellationToken);

        if (snapshot == null || snapshot.Status != UserStatus.Active)
        {
            _passwordSecurityService.VerifyDummyPassword(currentPassword);
            return PasswordMutationResult.Failed("User not found or inactive.");
        }

        // 2. Verify current password OUTSIDE row lock
        var verification = _passwordSecurityService.VerifyHashedPassword(new User(), snapshot.PasswordHash, currentPassword);
        if (verification == Microsoft.AspNetCore.Identity.PasswordVerificationResult.Failed)
        {
            return PasswordMutationResult.Failed("Current password is incorrect.");
        }

        // 3. Hash new password OUTSIDE row lock
        var newPasswordHash = _passwordSecurityService.HashPassword(new User(), newPassword);

        // 4. Begin READ COMMITTED transaction and lock user
        await using var tx = await _dbContext.Database.BeginTransactionAsync(IsolationLevel.ReadCommitted, cancellationToken);

        var user = await _dbContext.LockUserForUpdateAsync(userId, cancellationToken);
        if (user == null || user.Status != UserStatus.Active || user.Version != snapshot.Version ||
            !string.Equals(user.PasswordHash, snapshot.PasswordHash, StringComparison.Ordinal))
        {
            await tx.RollbackAsync(cancellationToken);
            return PasswordMutationResult.Failed("User state has changed concurrently.");
        }

        // Update password (automatically rotates security stamp and clears failed login attempts)
        user.UpdatePassword(newPasswordHash, utcNow);

        // Revoke all active sessions deterministically
        var activeSessions = await _dbContext.LockActiveSessionsForUserAsync(userId, cancellationToken);
        foreach (var sess in activeSessions)
        {
            sess.Revoke(SessionRevocationReason.PasswordChanged, utcNow);
        }

        await _dbContext.RevokeActiveRefreshTokensForUserAsync(userId, utcNow, cancellationToken);
        _securityStampValidator.Invalidate(user.Id);

        var audit = SecurityAuditEvent.Create(
            SecurityAuditEventType.PasswordChanged,
            utcNow,
            user.Id,
            sessionId: null,
            clientIp,
            SecurityAuditMetadata.Create(
                SecurityAuditMetadata.Reasons.PasswordChanged,
                null,
                SecurityAuditMetadata.Actions.SecurityStampRotated));

        _dbContext.SecurityAuditEvents.Add(audit);

        await _dbContext.SaveChangesAsync(cancellationToken);
        await tx.CommitAsync(cancellationToken);

        return PasswordMutationResult.Success();
    }

    /// <inheritdoc />
    /// <remarks>
    /// Enforces domain invariants and ensures target user is not deactivated.
    /// Caller authorization (e.g. <c>[Authorize(Roles = "Admin")]</c>) must be strictly enforced at the T6 API controller boundary.
    /// </remarks>
    public async Task<PasswordMutationResult> AuthorizedResetPasswordAsync(
        Guid userId,
        string newPassword,
        string? clientIp = null,
        CancellationToken cancellationToken = default)
    {
        if (userId == Guid.Empty)
        {
            return PasswordMutationResult.Failed("User ID cannot be empty.");
        }

        PasswordValidation.Validate(newPassword);
        var utcNow = _timeProvider.GetUtcNow().UtcDateTime;

        // Hash new password outside lock
        var newPasswordHash = _passwordSecurityService.HashPassword(new User(), newPassword);

        await using var tx = await _dbContext.Database.BeginTransactionAsync(IsolationLevel.ReadCommitted, cancellationToken);

        var user = await _dbContext.LockUserForUpdateAsync(userId, cancellationToken);
        if (user == null || user.Status == UserStatus.Deactivated)
        {
            await tx.RollbackAsync(cancellationToken);
            return PasswordMutationResult.Failed("User not found or permanently deactivated.");
        }

        user.UpdatePassword(newPasswordHash, utcNow);

        var activeSessions = await _dbContext.LockActiveSessionsForUserAsync(userId, cancellationToken);
        foreach (var sess in activeSessions)
        {
            sess.Revoke(SessionRevocationReason.PasswordChanged, utcNow);
        }

        await _dbContext.RevokeActiveRefreshTokensForUserAsync(userId, utcNow, cancellationToken);
        _securityStampValidator.Invalidate(user.Id);

        var audit = SecurityAuditEvent.Create(
            SecurityAuditEventType.PasswordChanged,
            utcNow,
            user.Id,
            sessionId: null,
            clientIp,
            SecurityAuditMetadata.Create(
                SecurityAuditMetadata.Reasons.AdminAction,
                null,
                SecurityAuditMetadata.Actions.SecurityStampRotated));

        _dbContext.SecurityAuditEvents.Add(audit);

        await _dbContext.SaveChangesAsync(cancellationToken);
        await tx.CommitAsync(cancellationToken);

        return PasswordMutationResult.Success();
    }

    private static bool IsUniqueEmailViolation(DbUpdateException ex)
    {
        return ex.InnerException is PostgresException pgEx &&
               pgEx.SqlState == PostgresErrorCodes.UniqueViolation &&
               pgEx.ConstraintName == "ix_users_email";
    }
}

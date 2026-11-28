namespace MaintenX.Api.Application.Authorization.Services;

using System.Data;
using MaintenX.Api.Application.Authorization.Contracts;
using MaintenX.Api.Domain.Auth;
using MaintenX.Api.Domain.Authorization;
using MaintenX.Api.Infrastructure.Persistence;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging;

/// <summary>
/// Authoritative application service for managing platform role grants.
/// Coordinates grant revocation using PostgreSQL advisory locks (<see cref="PlatformAuthorizationCoordination.AdvisoryLockId"/>),
/// revalidates caller authority and remaining distinct active administrators within the transaction,
/// and enforces atomic persistence of the grant mutation alongside its durable security audit event.
/// </summary>
public sealed class PlatformGrantService : IPlatformGrantService
{
    private readonly MaintenXDbContext _dbContext;
    private readonly IPlatformGrantResolver _grantResolver;
    private readonly TimeProvider _timeProvider;
    private readonly ILogger<PlatformGrantService> _logger;

    public PlatformGrantService(
        MaintenXDbContext dbContext,
        IPlatformGrantResolver grantResolver,
        TimeProvider timeProvider,
        ILogger<PlatformGrantService> logger)
    {
        _dbContext = dbContext ?? throw new ArgumentNullException(nameof(dbContext));
        _grantResolver = grantResolver ?? throw new ArgumentNullException(nameof(grantResolver));
        _timeProvider = timeProvider ?? throw new ArgumentNullException(nameof(timeProvider));
        _logger = logger ?? throw new ArgumentNullException(nameof(logger));
    }

    /// <inheritdoc />
    public async Task<PlatformGrantRevocationResult> RevokeGrantAsync(
        PlatformGrantRevocationRequest request,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(request);
        cancellationToken.ThrowIfCancellationRequested();

        if (request.GrantId == Guid.Empty)
        {
            return PlatformGrantRevocationResult.Failure(
                PlatformGrantRevocationOutcome.GrantNotFound,
                "Grant ID cannot be empty.");
        }

        var trimmedReason = request.Reason?.Trim() ?? string.Empty;
        if (trimmedReason.Length < PlatformRoleGrant.MinRevocationReasonLength ||
            trimmedReason.Length > PlatformRoleGrant.MaxRevocationReasonLength)
        {
            return PlatformGrantRevocationResult.Failure(
                PlatformGrantRevocationOutcome.TargetIneligible,
                $"Revocation reason must be between {PlatformRoleGrant.MinRevocationReasonLength} and {PlatformRoleGrant.MaxRevocationReasonLength} characters.",
                grantId: request.GrantId);
        }

        // 1. Initial caller authority check via IPlatformGrantResolver
        var callerResolution = await _grantResolver.ResolveAsync(null, cancellationToken);
        if (!callerResolution.IsAllowed || !callerResolution.UserId.HasValue)
        {
            _logger.LogWarning("Platform grant revocation denied: caller is not an active, authoritative platform administrator.");
            return PlatformGrantRevocationResult.Failure(
                PlatformGrantRevocationOutcome.Unauthorized,
                callerResolution.DenialReason ?? "Caller does not hold authoritative platform administration privileges.",
                grantId: request.GrantId);
        }

        var callerUserId = callerResolution.UserId.Value;

        // 2. Execute under EF Core execution strategy and shared PostgreSQL advisory lock
        try
        {
            var strategy = _dbContext.Database.CreateExecutionStrategy();
            return await strategy.ExecuteAsync(async () =>
            {
                await using var tx = await _dbContext.Database.BeginTransactionAsync(IsolationLevel.ReadCommitted, cancellationToken);

                // Acquire the global platform authorization coordination advisory lock
                await _dbContext.Database.ExecuteSqlRawAsync(
                    $"SELECT pg_advisory_xact_lock({PlatformAuthorizationCoordination.AdvisoryLockId});",
                    cancellationToken);

                // 3. Re-verify caller grant inside the coordinated transaction
                var callerGrant = await _dbContext.PlatformRoleGrants
                    .AsNoTracking()
                    .FirstOrDefaultAsync(g => g.UserId == callerUserId
                                           && g.Role == PlatformRole.PlatformAdministrator
                                           && g.Status == PlatformRoleGrantStatus.Active,
                        cancellationToken);

                if (callerGrant is null)
                {
                    await tx.RollbackAsync(cancellationToken);
                    _logger.LogWarning("Platform grant revocation denied: caller's active grant was revoked or modified prior to acquiring coordination lock.");
                    return PlatformGrantRevocationResult.Failure(
                        PlatformGrantRevocationOutcome.Unauthorized,
                        "Caller's platform administrator privileges are no longer active.",
                        grantId: request.GrantId);
                }

                // 4. Fetch target grant for update
                var targetGrant = await _dbContext.PlatformRoleGrants
                    .FirstOrDefaultAsync(g => g.Id == request.GrantId, cancellationToken);

                if (targetGrant is null)
                {
                    await tx.RollbackAsync(cancellationToken);
                    return PlatformGrantRevocationResult.Failure(
                        PlatformGrantRevocationOutcome.GrantNotFound,
                        "Platform role grant was not found.",
                        grantId: request.GrantId);
                }

                // 5. Idempotent check: if already revoked, return no-op
                if (targetGrant.Status == PlatformRoleGrantStatus.Revoked)
                {
                    await tx.RollbackAsync(cancellationToken);
                    return PlatformGrantRevocationResult.AlreadyRevokedNoOp(targetGrant.Id, targetGrant.UserId);
                }

                // 6. Conservative self-revocation policy: denial to prevent accidental administrative lockouts
                if (targetGrant.UserId == callerUserId)
                {
                    await tx.RollbackAsync(cancellationToken);
                    _logger.LogWarning("Platform grant revocation denied: self-revocation is prohibited for User {UserId}.", callerUserId);
                    return PlatformGrantRevocationResult.Failure(
                        PlatformGrantRevocationOutcome.SelfRevocationDenied,
                        "Self-revocation of platform administrator grants is denied. Another active platform administrator must perform this operation.",
                        grantId: targetGrant.Id,
                        targetUserId: targetGrant.UserId);
                }

                // 7. Concurrency token verification
                if (request.ExpectedVersion.HasValue && targetGrant.Version != request.ExpectedVersion.Value)
                {
                    await tx.RollbackAsync(cancellationToken);
                    return PlatformGrantRevocationResult.Failure(
                        PlatformGrantRevocationOutcome.ConcurrencyConflict,
                        $"Concurrency conflict: expected version {request.ExpectedVersion.Value} does not match current grant version {targetGrant.Version}.",
                        grantId: targetGrant.Id,
                        targetUserId: targetGrant.UserId);
                }

                // 8. Last distinct eligible administrator protection
                // Query all active grants with target users
                var allActiveGrantsWithUsers = await (
                    from g in _dbContext.PlatformRoleGrants
                    join u in _dbContext.Users on g.UserId equals u.Id
                    where g.Role == PlatformRole.PlatformAdministrator
                          && g.Status == PlatformRoleGrantStatus.Active
                    select new { g.UserId, UserStatus = u.Status }
                ).ToListAsync(cancellationToken);

                // Distinct active eligible administrators excluding the target user
                var remainingEligibleCount = allActiveGrantsWithUsers
                    .Where(x => x.UserId != targetGrant.UserId && x.UserStatus == UserStatus.Active)
                    .Select(x => x.UserId)
                    .Distinct()
                    .Count();

                if (remainingEligibleCount < 1)
                {
                    await tx.RollbackAsync(cancellationToken);
                    _logger.LogWarning(
                        "Platform grant revocation denied: revoking Grant {GrantId} for User {UserId} would remove the last active platform administrator.",
                        targetGrant.Id, targetGrant.UserId);

                    return PlatformGrantRevocationResult.Failure(
                        PlatformGrantRevocationOutcome.LastAdministratorProtected,
                        "Cannot revoke the last active eligible Platform Administrator.",
                        grantId: targetGrant.Id,
                        targetUserId: targetGrant.UserId);
                }

                // 9. Mutate grant and write durable security audit event atomically
                var utcNow = _timeProvider.GetUtcNow().UtcDateTime;
                targetGrant.Revoke(callerUserId, trimmedReason, utcNow);

                var auditEvent = SecurityAuditEvent.Create(
                    SecurityAuditEventType.SessionRevoked,
                    utcNow,
                    userId: targetGrant.UserId,
                    sessionId: null,
                    clientIp: null,
                    reason: SecurityAuditMetadata.Reasons.AdminAction,
                    detectedLineage: $"grant_{targetGrant.Id:N}",
                    actionTaken: SecurityAuditMetadata.Actions.SessionRevoked);

                _dbContext.SecurityAuditEvents.Add(auditEvent);

                await _dbContext.SaveChangesAsync(cancellationToken);
                await tx.CommitAsync(cancellationToken);

                _logger.LogInformation(
                    "Platform Administrator grant {GrantId} for User {TargetUserId} revoked by User {CallerUserId}. Reason: {Reason}",
                    targetGrant.Id, targetGrant.UserId, callerUserId, trimmedReason);

                return PlatformGrantRevocationResult.RevokedSuccess(
                    targetGrant.Id,
                    targetGrant.UserId,
                    auditEvent.Id);
            });
        }
        catch (OperationCanceledException)
        {
            _dbContext.ChangeTracker.Clear();
            throw;
        }
        catch (DbUpdateConcurrencyException ex)
        {
            _dbContext.ChangeTracker.Clear();
            _logger.LogWarning(ex, "Concurrency conflict during platform grant revocation.");
            return PlatformGrantRevocationResult.Failure(
                PlatformGrantRevocationOutcome.ConcurrencyConflict,
                "The platform grant was modified by another operation.",
                grantId: request.GrantId);
        }
        catch (Exception ex)
        {
            _dbContext.ChangeTracker.Clear();
            _logger.LogError(ex, "Unexpected infrastructure failure during platform grant revocation.");
            return PlatformGrantRevocationResult.Failure(
                PlatformGrantRevocationOutcome.InfrastructureFailure,
                "An unexpected error occurred during grant revocation.",
                grantId: request.GrantId);
        }
    }
}

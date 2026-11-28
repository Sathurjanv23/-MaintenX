namespace MaintenX.Api.Application.Authorization.Services;

using MaintenX.Api.Application.Authorization.Contracts;
using MaintenX.Api.Domain.Auth;
using MaintenX.Api.Domain.Authorization;
using MaintenX.Api.Infrastructure.Persistence;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging;

/// <summary>
/// Implements globally coordinated, idempotent, atomic initial Platform Administrator provisioning.
/// Uses PostgreSQL transaction-scoped advisory locking (<c>pg_advisory_xact_lock</c>) to serialize
/// concurrent bootstrap attempts across distinct target users.
/// </summary>
public sealed class PlatformAdminBootstrapService : IPlatformAdminBootstrapService
{
    private const long BootstrapAdvisoryLockId = PlatformAuthorizationCoordination.AdvisoryLockId;

    private readonly MaintenXDbContext _dbContext;
    private readonly IBootstrapOperatorAuthorizationProvider _operatorAuthProvider;
    private readonly TimeProvider _timeProvider;
    private readonly ILogger<PlatformAdminBootstrapService> _logger;

    public PlatformAdminBootstrapService(
        MaintenXDbContext dbContext,
        IBootstrapOperatorAuthorizationProvider operatorAuthProvider,
        TimeProvider timeProvider,
        ILogger<PlatformAdminBootstrapService> logger)
    {
        _dbContext = dbContext ?? throw new ArgumentNullException(nameof(dbContext));
        _operatorAuthProvider = operatorAuthProvider ?? throw new ArgumentNullException(nameof(operatorAuthProvider));
        _timeProvider = timeProvider ?? throw new ArgumentNullException(nameof(timeProvider));
        _logger = logger ?? throw new ArgumentNullException(nameof(logger));
    }

    public async Task<PlatformAdminBootstrapResult> BootstrapAsync(
        PlatformAdminBootstrapRequest request,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(request);
        cancellationToken.ThrowIfCancellationRequested();

        // 1. Verify server-side operational authorization boundary
        var operatorAuth = await _operatorAuthProvider.AuthorizeAsync(cancellationToken);
        if (!operatorAuth.IsAuthorized || string.IsNullOrWhiteSpace(operatorAuth.OperatorIdentity))
        {
            _logger.LogWarning("Platform administrator bootstrap rejected: unauthorized operational execution.");
            return PlatformAdminBootstrapResult.Failure(
                PlatformAdminBootstrapOutcome.UnauthorizedOperation,
                operatorAuth.DenialReason ?? "Operational bootstrap is not authorized.");
        }

        // 2. Validate request target and reason
        if (!TryValidateRequest(request, out var normalizedEmail, out var trimmedReason, out var validationError))
        {
            return PlatformAdminBootstrapResult.Failure(
                PlatformAdminBootstrapOutcome.TargetIneligible,
                validationError!);
        }

        try
        {
            var strategy = _dbContext.Database.CreateExecutionStrategy();
            return await strategy.ExecuteAsync(async ct =>
            {
                await using var tx = await _dbContext.Database.BeginTransactionAsync(ct);

                // Acquire PostgreSQL transaction-scoped advisory lock for global bootstrap serialization
                if (_dbContext.Database.IsNpgsql())
                {
                    await _dbContext.Database.ExecuteSqlRawAsync(
                        $"SELECT pg_advisory_xact_lock({BootstrapAdvisoryLockId});",
                        ct);
                }

                // 3. Resolve target user inside the serialized transaction
                User? targetUser;
                if (request.TargetUserId.HasValue)
                {
                    targetUser = await _dbContext.Users
                        .AsNoTracking()
                        .FirstOrDefaultAsync(u => u.Id == request.TargetUserId.Value, ct);
                }
                else
                {
                    targetUser = await _dbContext.Users
                        .AsNoTracking()
                        .FirstOrDefaultAsync(u => u.Email == normalizedEmail, ct);
                }

                if (targetUser is null)
                {
                    await tx.RollbackAsync(ct);
                    return PlatformAdminBootstrapResult.Failure(
                        PlatformAdminBootstrapOutcome.TargetNotFound,
                        "Target user account was not found.");
                }

                if (targetUser.Status != UserStatus.Active)
                {
                    await tx.RollbackAsync(ct);
                    return PlatformAdminBootstrapResult.Failure(
                        PlatformAdminBootstrapOutcome.TargetIneligible,
                        "Target user account is not Active and cannot be promoted.",
                        targetUser.Id);
                }

                // 4. Revalidate first-bootstrap eligibility (active + historical grants)
                var existingPlatformGrants = await _dbContext.PlatformRoleGrants
                    .AsNoTracking()
                    .Where(g => g.Role == PlatformRole.PlatformAdministrator)
                    .Select(g => new { g.Id, g.UserId, g.Status, g.GrantedByActorKind })
                    .ToListAsync(ct);

                var activeGrants = existingPlatformGrants
                    .Where(g => g.Status == PlatformRoleGrantStatus.Active)
                    .ToList();

                if (activeGrants.Count == 1 &&
                    activeGrants[0].UserId == targetUser.Id &&
                    activeGrants[0].GrantedByActorKind == GrantActorKind.DeploymentOperator)
                {
                    await tx.RollbackAsync(ct);
                    return PlatformAdminBootstrapResult.AlreadyProvisionedForSameUser(
                        activeGrants[0].Id,
                        targetUser.Id,
                        operatorAuth.OperatorIdentity);
                }

                if (activeGrants.Count > 0)
                {
                    await tx.RollbackAsync(ct);
                    return PlatformAdminBootstrapResult.Failure(
                        PlatformAdminBootstrapOutcome.BootstrapUnavailable,
                        "Initial bootstrap is unavailable because an active Platform Administrator already exists.",
                        targetUser.Id);
                }

                if (existingPlatformGrants.Count > 0)
                {
                    await tx.RollbackAsync(ct);
                    return PlatformAdminBootstrapResult.Failure(
                        PlatformAdminBootstrapOutcome.BootstrapUnavailable,
                        "Initial bootstrap is unavailable because the platform was previously initialized.",
                        targetUser.Id);
                }

                // 5. Persist grant and durable security audit event atomically
                var utcNow = _timeProvider.GetUtcNow().UtcDateTime;
                var grant = PlatformRoleGrant.CreateForBootstrap(
                    targetUser.Id,
                    PlatformRole.PlatformAdministrator,
                    operatorAuth.OperatorIdentity,
                    utcNow);

                var auditMetadata = SecurityAuditMetadata.ForBootstrap(grant.Id);
                var auditEvent = SecurityAuditEvent.Create(
                    SecurityAuditEventType.PlatformAdministratorBootstrapped,
                    utcNow,
                    userId: targetUser.Id,
                    sessionId: null,
                    clientIp: null,
                    metadata: auditMetadata);

                _dbContext.PlatformRoleGrants.Add(grant);
                _dbContext.SecurityAuditEvents.Add(auditEvent);

                await _dbContext.SaveChangesAsync(ct);
                await tx.CommitAsync(ct);

                _logger.LogInformation(
                    "Initial Platform Administrator grant {GrantId} provisioned for User {UserId} by {OperatorIdentity}.",
                    grant.Id, targetUser.Id, operatorAuth.OperatorIdentity);

                return PlatformAdminBootstrapResult.Created(
                    grant.Id,
                    auditEvent.Id,
                    targetUser.Id,
                    operatorAuth.OperatorIdentity);
            }, cancellationToken);
        }
        catch (OperationCanceledException)
        {
            _dbContext.ChangeTracker.Clear();
            throw;
        }
        catch (Exception ex)
        {
            _dbContext.ChangeTracker.Clear();
            _logger.LogError(ex, "Platform administrator bootstrap failed due to an infrastructure error.");
            return PlatformAdminBootstrapResult.Failure(
                PlatformAdminBootstrapOutcome.InfrastructureFailure,
                "Platform administrator bootstrap failed due to an infrastructure error.");
        }
    }

    private static bool TryValidateRequest(
        PlatformAdminBootstrapRequest request,
        out string? normalizedEmail,
        out string trimmedReason,
        out string? error)
    {
        normalizedEmail = null;
        trimmedReason = string.Empty;
        error = null;

        var hasId = request.TargetUserId.HasValue;
        var hasEmail = !string.IsNullOrWhiteSpace(request.TargetEmail);

        if (hasId == hasEmail)
        {
            error = "Specify exactly one target identifier: TargetUserId or TargetEmail.";
            return false;
        }

        if (hasId && request.TargetUserId!.Value == Guid.Empty)
        {
            error = "TargetUserId cannot be empty.";
            return false;
        }

        if (hasEmail)
        {
            try
            {
                normalizedEmail = User.NormalizeAndValidateEmail(request.TargetEmail!);
            }
            catch (ArgumentException ex)
            {
                error = ex.Message;
                return false;
            }
        }

        if (string.IsNullOrWhiteSpace(request.Reason))
        {
            error = "Bootstrap reason must be provided.";
            return false;
        }

        trimmedReason = request.Reason.Trim();
        if (trimmedReason.Length < PlatformRoleGrant.MinRevocationReasonLength ||
            trimmedReason.Length > PlatformRoleGrant.MaxRevocationReasonLength)
        {
            error = $"Bootstrap reason must be between {PlatformRoleGrant.MinRevocationReasonLength} and {PlatformRoleGrant.MaxRevocationReasonLength} characters.";
            return false;
        }

        return true;
    }
}

namespace MaintenX.Api.Application.Authorization.Contracts;

/// <summary>
/// Operational request to revoke an active <see cref="Domain.Authorization.PlatformRoleGrant"/>.
/// </summary>
public sealed record PlatformGrantRevocationRequest(
    Guid GrantId,
    string Reason,
    long? ExpectedVersion = null);

/// <summary>
/// Explicit outcome of a platform grant revocation attempt.
/// </summary>
public enum PlatformGrantRevocationOutcome
{
    Revoked = 1,
    AlreadyRevoked = 2,
    GrantNotFound = 3,
    Unauthorized = 4,
    SelfRevocationDenied = 5,
    LastAdministratorProtected = 6,
    ConcurrencyConflict = 7,
    TargetIneligible = 8,
    InfrastructureFailure = 9
}

/// <summary>
/// Immutable outcome of a platform role grant revocation attempt.
/// </summary>
public sealed record PlatformGrantRevocationResult
{
    public PlatformGrantRevocationOutcome Outcome { get; }
    public Guid? GrantId { get; }
    public Guid? TargetUserId { get; }
    public Guid? AuditEventId { get; }
    public string Message { get; }

    public bool IsSuccess => Outcome is PlatformGrantRevocationOutcome.Revoked or PlatformGrantRevocationOutcome.AlreadyRevoked;

    private PlatformGrantRevocationResult(
        PlatformGrantRevocationOutcome outcome,
        Guid? grantId,
        Guid? targetUserId,
        Guid? auditEventId,
        string message)
    {
        Outcome = outcome;
        GrantId = grantId;
        TargetUserId = targetUserId;
        AuditEventId = auditEventId;
        Message = message;
    }

    public static PlatformGrantRevocationResult RevokedSuccess(
        Guid grantId,
        Guid targetUserId,
        Guid auditEventId) =>
        new(PlatformGrantRevocationOutcome.Revoked, grantId, targetUserId, auditEventId,
            "Platform administrator grant was revoked successfully and audited.");

    public static PlatformGrantRevocationResult AlreadyRevokedNoOp(
        Guid grantId,
        Guid targetUserId) =>
        new(PlatformGrantRevocationOutcome.AlreadyRevoked, grantId, targetUserId, null,
            "Platform administrator grant was already revoked (idempotent no-op).");

    public static PlatformGrantRevocationResult Failure(
        PlatformGrantRevocationOutcome outcome,
        string message,
        Guid? grantId = null,
        Guid? targetUserId = null) =>
        new(outcome, grantId, targetUserId, null, message);
}

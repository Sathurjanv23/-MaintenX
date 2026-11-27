namespace MaintenX.Api.Application.Authorization.Contracts;

/// <summary>
/// Operational request to provision the initial Platform Administrator for an uninitialized platform.
/// </summary>
public sealed record PlatformAdminBootstrapRequest(
    Guid? TargetUserId,
    string? TargetEmail,
    string Reason);

/// <summary>
/// Explicit outcome of an initial Platform Administrator bootstrap attempt.
/// </summary>
public enum PlatformAdminBootstrapOutcome
{
    Created = 1,
    AlreadyProvisionedForSameUser = 2,
    BootstrapUnavailable = 3,
    TargetNotFound = 4,
    TargetIneligible = 5,
    UnauthorizedOperation = 6,
    InfrastructureFailure = 7
}

/// <summary>
/// Immutable result returned by <see cref="Services.IPlatformAdminBootstrapService"/>.
/// </summary>
public sealed record PlatformAdminBootstrapResult
{
    public PlatformAdminBootstrapOutcome Outcome { get; }
    public Guid? GrantId { get; }
    public Guid? AuditEventId { get; }
    public Guid? TargetUserId { get; }
    public string? OperatorIdentity { get; }
    public string Message { get; }

    public bool IsSuccess => Outcome is PlatformAdminBootstrapOutcome.Created or PlatformAdminBootstrapOutcome.AlreadyProvisionedForSameUser;

    private PlatformAdminBootstrapResult(
        PlatformAdminBootstrapOutcome outcome,
        Guid? grantId,
        Guid? auditEventId,
        Guid? targetUserId,
        string? operatorIdentity,
        string message)
    {
        Outcome = outcome;
        GrantId = grantId;
        AuditEventId = auditEventId;
        TargetUserId = targetUserId;
        OperatorIdentity = operatorIdentity;
        Message = message;
    }

    internal static PlatformAdminBootstrapResult Created(
        Guid grantId,
        Guid auditEventId,
        Guid targetUserId,
        string operatorIdentity) =>
        new(PlatformAdminBootstrapOutcome.Created, grantId, auditEventId, targetUserId, operatorIdentity,
            "Initial Platform Administrator grant provisioned atomically.");

    internal static PlatformAdminBootstrapResult AlreadyProvisionedForSameUser(
        Guid grantId,
        Guid targetUserId,
        string operatorIdentity) =>
        new(PlatformAdminBootstrapOutcome.AlreadyProvisionedForSameUser, grantId, null, targetUserId, operatorIdentity,
            "Initial Platform Administrator is already provisioned for this user (idempotent no-op).");

    internal static PlatformAdminBootstrapResult Failure(
        PlatformAdminBootstrapOutcome outcome,
        string message,
        Guid? targetUserId = null) =>
        new(outcome, null, null, targetUserId, null, message);
}

/// <summary>
/// Server-derived operational authorization result for deployment-operator bootstrap.
/// </summary>
public sealed record BootstrapOperatorAuthorizationResult
{
    public bool IsAuthorized { get; }
    public string? OperatorIdentity { get; }
    public string? DenialReason { get; }

    private BootstrapOperatorAuthorizationResult(bool isAuthorized, string? operatorIdentity, string? denialReason)
    {
        IsAuthorized = isAuthorized;
        OperatorIdentity = operatorIdentity;
        DenialReason = denialReason;
    }

    internal static BootstrapOperatorAuthorizationResult Authorized(string operatorIdentity) =>
        new(true, operatorIdentity, null);

    internal static BootstrapOperatorAuthorizationResult Denied(string reason) =>
        new(false, null, reason);
}

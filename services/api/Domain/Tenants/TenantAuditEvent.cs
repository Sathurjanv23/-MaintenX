namespace MaintenX.Api.Domain.Tenants;

/// <summary>
/// Immutable audit event recording tenant organization lifecycle state changes and administrative modifications.
/// Persisted in the dedicated 'platform' schema ('platform.tenant_audit_events').
/// Follows append-only audit trail invariants with zero cascading foreign keys.
/// </summary>
public sealed class TenantAuditEvent
{
    /// <summary>
    /// Unique UUID primary key for the tenant audit event.
    /// </summary>
    public Guid Id { get; private set; }

    /// <summary>
    /// Identifier of the target tenant organization.
    /// </summary>
    public Guid TenantId { get; private set; }

    /// <summary>
    /// Identifier of the administrator or system actor who triggered the operation.
    /// </summary>
    public Guid ActorUserId { get; private set; }

    /// <summary>
    /// Categorized action name (e.g. "TenantActivated", "TenantSuspended", "TenantDeactivated").
    /// </summary>
    public string Action { get; private set; } = string.Empty;

    /// <summary>
    /// Operational status of the tenant prior to the transition.
    /// </summary>
    public string PreviousStatus { get; private set; } = string.Empty;

    /// <summary>
    /// Operational status of the tenant following the transition.
    /// </summary>
    public string NewStatus { get; private set; } = string.Empty;

    /// <summary>
    /// Validated administrative justification or reason for the lifecycle transition.
    /// Never contains credentials, tokens, or sensitive personal information.
    /// </summary>
    public string? Reason { get; private set; }

    /// <summary>
    /// UTC timestamp marking when the event was recorded.
    /// </summary>
    public DateTime CreatedAtUtc { get; private set; }

    /// <summary>
    /// Parameterless constructor reserved exclusively for EF Core materialization.
    /// </summary>
    private TenantAuditEvent()
    {
    }

    /// <summary>
    /// Factory method instantiating a validated, immutable <see cref="TenantAuditEvent"/> record.
    /// </summary>
    public static TenantAuditEvent Create(
        Guid tenantId,
        Guid actorUserId,
        string action,
        string previousStatus,
        string newStatus,
        string? reason,
        DateTime utcNow)
    {
        if (tenantId == Guid.Empty)
        {
            throw new ArgumentException("Tenant identifier cannot be empty.", nameof(tenantId));
        }

        if (actorUserId == Guid.Empty)
        {
            throw new ArgumentException("Actor user identifier cannot be empty.", nameof(actorUserId));
        }

        ArgumentException.ThrowIfNullOrWhiteSpace(action);
        ArgumentException.ThrowIfNullOrWhiteSpace(previousStatus);
        ArgumentException.ThrowIfNullOrWhiteSpace(newStatus);

        return new TenantAuditEvent
        {
            Id = Guid.NewGuid(),
            TenantId = tenantId,
            ActorUserId = actorUserId,
            Action = action.Trim(),
            PreviousStatus = previousStatus.Trim(),
            NewStatus = newStatus.Trim(),
            Reason = string.IsNullOrWhiteSpace(reason) ? null : reason.Trim(),
            CreatedAtUtc = utcNow
        };
    }
}

namespace MaintenX.Api.Domain.Tenants;

/// <summary>
/// Tenant membership aggregate representing a user's association, role, and lifecycle status
/// within a specific tenant organization.
/// Implements <see cref="ITenantEntity"/> to enforce tenant-scoped isolation.
/// Pure domain model independent of EF Core, HTTP, JWT, and infrastructure concerns.
/// </summary>
public sealed class TenantMembership : ITenantEntity
{
    /// <summary>
    /// Unique identifier for the membership record.
    /// </summary>
    public Guid Id { get; private set; }

    /// <summary>
    /// Identifier of the tenant organization to which the user belongs.
    /// </summary>
    public Guid TenantId { get; private set; }

    /// <summary>
    /// Identifier of the user holding this membership.
    /// </summary>
    public Guid UserId { get; private set; }

    /// <summary>
    /// Foundational organizational role of the user within this tenant.
    /// </summary>
    public TenantMembershipRole Role { get; private set; }

    /// <summary>
    /// Current operational and access status of the membership.
    /// </summary>
    public TenantMembershipStatus Status { get; private set; }

    /// <summary>
    /// UTC timestamp when the membership was created.
    /// </summary>
    public DateTime CreatedAtUtc { get; private set; }

    /// <summary>
    /// UTC timestamp of the most recent update to the membership.
    /// </summary>
    public DateTime UpdatedAtUtc { get; private set; }

    /// <summary>
    /// UTC timestamp when the membership was deactivated (suspended or revoked), or null if active.
    /// </summary>
    public DateTime? DeactivatedAtUtc { get; private set; }

    /// <summary>
    /// Optimistic concurrency token tracking row mutations.
    /// </summary>
    public long Version { get; private set; }

    /// <summary>
    /// Indicates whether the membership is currently active and authorized for tenant access.
    /// </summary>
    public bool IsActive => Status == TenantMembershipStatus.Active;

    /// <summary>
    /// Parameterless constructor required by EF Core for entity materialization.
    /// </summary>
    public TenantMembership()
    {
    }

    /// <summary>
    /// Factory method for creating a validated tenant membership.
    /// </summary>
    /// <param name="tenantId">Identifier of the target tenant organization.</param>
    /// <param name="userId">Identifier of the user.</param>
    /// <param name="role">Assigned organizational role.</param>
    /// <param name="initialStatus">Initial membership status (defaults to Active).</param>
    /// <param name="utcNow">Optional creation timestamp; defaults to current UTC time.</param>
    /// <returns>A validated TenantMembership instance.</returns>
    /// <exception cref="ArgumentException">Thrown when tenantId or userId is empty, or enums are undefined.</exception>
    public static TenantMembership Create(
        Guid tenantId,
        Guid userId,
        TenantMembershipRole role,
        TenantMembershipStatus initialStatus = TenantMembershipStatus.Active,
        DateTime? utcNow = null)
    {
        if (tenantId == Guid.Empty)
        {
            throw new ArgumentException("TenantId cannot be empty.", nameof(tenantId));
        }

        if (userId == Guid.Empty)
        {
            throw new ArgumentException("UserId cannot be empty.", nameof(userId));
        }

        if (!Enum.IsDefined(typeof(TenantMembershipRole), role))
        {
            throw new ArgumentException($"Invalid TenantMembershipRole: '{role}'.", nameof(role));
        }

        if (!Enum.IsDefined(typeof(TenantMembershipStatus), initialStatus))
        {
            throw new ArgumentException($"Invalid TenantMembershipStatus: '{initialStatus}'.", nameof(initialStatus));
        }

        if (initialStatus == TenantMembershipStatus.Revoked)
        {
            throw new ArgumentException("Cannot create a membership directly in Revoked status.", nameof(initialStatus));
        }

        var now = utcNow ?? DateTime.UtcNow;

        return new TenantMembership
        {
            Id = Guid.NewGuid(),
            TenantId = tenantId,
            UserId = userId,
            Role = role,
            Status = initialStatus,
            CreatedAtUtc = now,
            UpdatedAtUtc = now,
            DeactivatedAtUtc = initialStatus == TenantMembershipStatus.Suspended ? now : null,
            Version = 1
        };
    }

    /// <summary>
    /// Activates the membership from Pending or Suspended state.
    /// </summary>
    /// <param name="utcNow">UTC timestamp of activation.</param>
    /// <exception cref="InvalidOperationException">Thrown if the membership is permanently revoked.</exception>
    public void Activate(DateTime utcNow)
    {
        if (Status == TenantMembershipStatus.Revoked)
        {
            throw new InvalidOperationException(
                $"Cannot activate membership '{Id}' because it has been permanently revoked. A new membership must be created.");
        }

        if (Status == TenantMembershipStatus.Active)
        {
            return; // Idempotent
        }

        Status = TenantMembershipStatus.Active;
        DeactivatedAtUtc = null;
        UpdatedAtUtc = utcNow;
        Version++;
    }

    /// <summary>
    /// Suspends an active membership, immediately revoking access to tenant resources.
    /// </summary>
    /// <param name="utcNow">UTC timestamp of suspension.</param>
    /// <exception cref="InvalidOperationException">Thrown if the membership is revoked or pending.</exception>
    public void Suspend(DateTime utcNow)
    {
        if (Status == TenantMembershipStatus.Revoked)
        {
            throw new InvalidOperationException($"Cannot suspend membership '{Id}' because it is permanently revoked.");
        }

        if (Status == TenantMembershipStatus.Pending)
        {
            throw new InvalidOperationException($"Cannot suspend pending membership '{Id}'. A pending membership must be activated first or revoked.");
        }

        if (Status == TenantMembershipStatus.Suspended)
        {
            return; // Idempotent
        }

        Status = TenantMembershipStatus.Suspended;
        DeactivatedAtUtc = utcNow;
        UpdatedAtUtc = utcNow;
        Version++;
    }

    /// <summary>
    /// Revokes the membership permanently. This is a terminal lifecycle state.
    /// </summary>
    /// <param name="utcNow">UTC timestamp of revocation.</param>
    public void Revoke(DateTime utcNow)
    {
        if (Status == TenantMembershipStatus.Revoked)
        {
            return; // Idempotent
        }

        Status = TenantMembershipStatus.Revoked;
        DeactivatedAtUtc = utcNow;
        UpdatedAtUtc = utcNow;
        Version++;
    }

    /// <summary>
    /// Modifies the organizational role of the membership.
    /// </summary>
    /// <param name="newRole">The new organizational role.</param>
    /// <param name="utcNow">UTC timestamp of the role change.</param>
    /// <exception cref="ArgumentException">Thrown if newRole is not a defined enum value.</exception>
    /// <exception cref="InvalidOperationException">Thrown if the membership is revoked.</exception>
    public void ChangeRole(TenantMembershipRole newRole, DateTime utcNow)
    {
        if (!Enum.IsDefined(typeof(TenantMembershipRole), newRole))
        {
            throw new ArgumentException($"Invalid TenantMembershipRole: '{newRole}'.", nameof(newRole));
        }

        if (Status == TenantMembershipStatus.Revoked)
        {
            throw new InvalidOperationException($"Cannot change the role of revoked membership '{Id}'.");
        }

        if (Role == newRole)
        {
            return; // Idempotent
        }

        Role = newRole;
        UpdatedAtUtc = utcNow;
        Version++;
    }

    /// <inheritdoc />
    public override string ToString() =>
        $"TenantMembership [Id={Id}, TenantId={TenantId}, UserId={UserId}, Role={Role}, Status={Status}]";
}

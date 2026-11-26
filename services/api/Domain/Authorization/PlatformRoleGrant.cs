namespace MaintenX.Api.Domain.Authorization;

/// <summary>
/// Domain aggregate representing an authoritative, global platform-role assignment for a verified user.
/// <para>
/// Strictly scoped to <see cref="AuthorizationScopeKind.Platform"/> with no <c>TenantId</c>.
/// A constructed domain grant represents persisted/domain state only and must never by itself
/// establish an authenticated HTTP actor without server-side identity and session verification.
/// </para>
/// </summary>
public sealed class PlatformRoleGrant
{
    public const int MinRevocationReasonLength = 3;
    public const int MaxRevocationReasonLength = 500;

    /// <summary>
    /// Unique identifier of this platform role grant.
    /// </summary>
    public Guid Id { get; private set; }

    /// <summary>
    /// Identifier of the user holding this platform role grant. Immutable.
    /// </summary>
    public Guid UserId { get; private set; }

    /// <summary>
    /// Assigned global platform role.
    /// </summary>
    public PlatformRole Role { get; private set; }

    /// <summary>
    /// Current lifecycle status of the grant.
    /// </summary>
    public PlatformRoleGrantStatus Status { get; private set; }

    /// <summary>
    /// UTC timestamp when the grant was issued.
    /// </summary>
    public DateTime GrantedAtUtc { get; private set; }

    /// <summary>
    /// Identifier of the verified actor or bootstrap operator that issued the grant.
    /// </summary>
    public Guid GrantedByUserId { get; private set; }

    /// <summary>
    /// UTC timestamp when the grant was revoked, or <c>null</c> if active.
    /// </summary>
    public DateTime? RevokedAtUtc { get; private set; }

    /// <summary>
    /// Identifier of the verified actor that revoked the grant, or <c>null</c> if active.
    /// </summary>
    public Guid? RevokedByUserId { get; private set; }

    /// <summary>
    /// Validated administrative justification for revocation, or <c>null</c> if active.
    /// </summary>
    public string? RevocationReason { get; private set; }

    /// <summary>
    /// Optimistic concurrency token incremented on meaningful state mutations.
    /// </summary>
    public long Version { get; private set; }

    /// <summary>
    /// Indicates whether this grant is currently active.
    /// </summary>
    public bool IsActive => Status == PlatformRoleGrantStatus.Active;

    private PlatformRoleGrant()
    {
    }

    /// <summary>
    /// Creates a new active <see cref="PlatformRoleGrant"/> with validated identity, role, and UTC timestamp invariants.
    /// </summary>
    public static PlatformRoleGrant Create(
        Guid userId,
        PlatformRole role,
        Guid grantedByUserId,
        DateTime utcNow)
    {
        if (userId == Guid.Empty)
        {
            throw new ArgumentException("Target UserId cannot be empty.", nameof(userId));
        }

        if (grantedByUserId == Guid.Empty)
        {
            throw new ArgumentException("GrantedByUserId cannot be empty.", nameof(grantedByUserId));
        }

        if (!Enum.IsDefined(role))
        {
            throw new ArgumentException($"Invalid PlatformRole: '{role}'.", nameof(role));
        }

        if (utcNow.Kind != DateTimeKind.Utc)
        {
            throw new ArgumentException("Grant timestamp must be in UTC.", nameof(utcNow));
        }

        return new PlatformRoleGrant
        {
            Id = Guid.NewGuid(),
            UserId = userId,
            Role = role,
            Status = PlatformRoleGrantStatus.Active,
            GrantedAtUtc = utcNow,
            GrantedByUserId = grantedByUserId,
            RevokedAtUtc = null,
            RevokedByUserId = null,
            RevocationReason = null,
            Version = 1
        };
    }

    /// <summary>
    /// Permanently revokes an active platform role grant. Terminal transition; repeated calls are idempotent.
    /// </summary>
    public void Revoke(Guid revokedByUserId, string reason, DateTime utcNow)
    {
        if (revokedByUserId == Guid.Empty)
        {
            throw new ArgumentException("RevokedByUserId cannot be empty.", nameof(revokedByUserId));
        }

        if (string.IsNullOrWhiteSpace(reason))
        {
            throw new ArgumentException("Revocation reason must be provided.", nameof(reason));
        }

        var trimmedReason = reason.Trim();
        if (trimmedReason.Length < MinRevocationReasonLength || trimmedReason.Length > MaxRevocationReasonLength)
        {
            throw new ArgumentException(
                $"Revocation reason must be between {MinRevocationReasonLength} and {MaxRevocationReasonLength} characters.",
                nameof(reason));
        }

        if (utcNow.Kind != DateTimeKind.Utc)
        {
            throw new ArgumentException("Revocation timestamp must be in UTC.", nameof(utcNow));
        }

        if (utcNow < GrantedAtUtc)
        {
            throw new ArgumentException("Revocation timestamp cannot precede GrantedAtUtc.", nameof(utcNow));
        }

        if (Status == PlatformRoleGrantStatus.Revoked)
        {
            return; // Idempotent: preserve original revocation metadata and Version
        }

        Status = PlatformRoleGrantStatus.Revoked;
        RevokedAtUtc = utcNow;
        RevokedByUserId = revokedByUserId;
        RevocationReason = trimmedReason;
        Version++;
    }

    public override string ToString() =>
        $"PlatformRoleGrant [Id={Id}, UserId={UserId}, Role={Role}, Status={Status}, Version={Version}]";
}

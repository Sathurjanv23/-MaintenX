namespace MaintenX.Api.Domain.Auth;

/// <summary>
/// User session entity tracking login session lifecycle, absolute expiration, and revocation status.
/// Independent of EF Core and ASP.NET Core infrastructure.
/// </summary>
public sealed class UserSession
{
    /// <summary>
    /// Unique UUID primary key for the session.
    /// </summary>
    public Guid Id { get; private set; }

    /// <summary>
    /// Foreign key identifier of the owning user.
    /// </summary>
    public Guid UserId { get; private set; }

    /// <summary>
    /// UTC timestamp marking when the session was created.
    /// </summary>
    public DateTime CreatedAtUtc { get; private set; }

    /// <summary>
    /// UTC timestamp marking absolute session expiration. The session cannot be extended beyond this boundary.
    /// </summary>
    public DateTime ExpiresAtUtc { get; private set; }

    /// <summary>
    /// UTC timestamp when the session was revoked, or null if still unrevoked.
    /// </summary>
    public DateTime? RevokedAtUtc { get; private set; }

    /// <summary>
    /// Standardized reason for revocation, or null if the session has not been revoked.
    /// </summary>
    public string? RevocationReason { get; private set; }

    /// <summary>
    /// Optimistic concurrency token tracking session mutations.
    /// </summary>
    public long Version { get; private set; }

    /// <summary>
    /// Indicates whether the session has been explicitly revoked.
    /// </summary>
    public bool IsRevoked => RevokedAtUtc.HasValue;

    /// <summary>
    /// Parameterless constructor required by EF Core for entity materialization.
    /// </summary>
    public UserSession()
    {
    }

    /// <summary>
    /// Evaluates whether the session has passed its absolute expiry timestamp.
    /// </summary>
    /// <param name="utcNow">Current UTC timestamp.</param>
    public bool IsExpired(DateTime utcNow)
    {
        return utcNow >= ExpiresAtUtc;
    }

    /// <summary>
    /// Determines whether the session is currently active (neither revoked nor expired).
    /// </summary>
    /// <param name="utcNow">Current UTC timestamp.</param>
    public bool IsActive(DateTime utcNow)
    {
        return !IsRevoked && !IsExpired(utcNow);
    }

    /// <summary>
    /// Factory method for instantiating a new UserSession with validated lifecycle invariants.
    /// </summary>
    /// <param name="userId">Owning user ID.</param>
    /// <param name="utcNow">Creation timestamp in UTC.</param>
    /// <param name="absoluteLifetime">Absolute session duration (must be strictly positive).</param>
    /// <returns>A validated UserSession instance.</returns>
    /// <exception cref="ArgumentException">Thrown when userId is empty or lifetime is not positive.</exception>
    public static UserSession Create(Guid userId, DateTime utcNow, TimeSpan absoluteLifetime)
    {
        if (userId == Guid.Empty)
        {
            throw new ArgumentException("Session must be associated with a valid, non-empty UserId.", nameof(userId));
        }

        if (absoluteLifetime <= TimeSpan.Zero)
        {
            throw new ArgumentException("Session absolute lifetime must be greater than zero.", nameof(absoluteLifetime));
        }

        return new UserSession
        {
            Id = Guid.NewGuid(),
            UserId = userId,
            CreatedAtUtc = utcNow,
            ExpiresAtUtc = utcNow.Add(absoluteLifetime),
            RevokedAtUtc = null,
            RevocationReason = null,
            Version = 1
        };
    }

    /// <summary>
    /// Revokes the session with an approved audit reason from the controlled revocation set.
    /// If the session is already revoked, repeated revocation is a no-op to prevent state corruption.
    /// </summary>
    /// <param name="reason">Revocation reason (must be one of the approved SessionRevocationReason values).</param>
    /// <param name="utcNow">Current UTC timestamp.</param>
    /// <returns>True if the session was transitioned from active to revoked; false if already revoked.</returns>
    /// <exception cref="ArgumentException">Thrown when reason is null, whitespace, or not in the controlled approved set.</exception>
    public bool Revoke(string reason, DateTime utcNow)
    {
        var validatedReason = SessionRevocationReason.ValidateAndNormalize(reason);

        if (IsRevoked)
        {
            return false;
        }

        RevokedAtUtc = utcNow;
        RevocationReason = validatedReason;
        Version++;
        return true;
    }

    /// <summary>
    /// Revokes the session using a strongly typed <see cref="SessionRevocationReasonType"/>.
    /// </summary>
    /// <param name="reasonType">Approved typed revocation reason.</param>
    /// <param name="utcNow">Current UTC timestamp.</param>
    /// <returns>True if the session was transitioned from active to revoked; false if already revoked.</returns>
    /// <exception cref="ArgumentOutOfRangeException">Thrown when an undefined enum value is provided.</exception>
    public bool Revoke(SessionRevocationReasonType reasonType, DateTime utcNow)
    {
        if (!Enum.IsDefined(typeof(SessionRevocationReasonType), reasonType))
        {
            throw new ArgumentOutOfRangeException(
                nameof(reasonType),
                reasonType,
                $"Supplied revocation reason type '{(int)reasonType}' is not a valid SessionRevocationReasonType enum value.");
        }

        return Revoke(reasonType.ToString(), utcNow);
    }

    /// <summary>
    /// Returns a string representation of the session entity omitting sensitive details.
    /// </summary>
    public override string ToString()
    {
        return $"UserSession [Id={Id}, UserId={UserId}, ExpiresAtUtc={ExpiresAtUtc:O}, IsRevoked={IsRevoked}, Reason={RevocationReason ?? "Active"}]";
    }
}

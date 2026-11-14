namespace MaintenX.Api.Domain.Auth;

using System.Text.RegularExpressions;

/// <summary>
/// Refresh token entity storing SHA-256 hashes of issued refresh tokens.
/// Raw refresh tokens are never persisted.
/// Enforces rotation, replacement lineage, replay detection, and revocation invariants.
/// Independent of EF Core and ASP.NET Core infrastructure.
/// </summary>
public sealed class RefreshToken
{
    private static readonly Regex Sha256HexRegex = new(
        @"^[a-f0-9]{64}$",
        RegexOptions.Compiled | RegexOptions.CultureInvariant);

    /// <summary>
    /// Unique UUID primary key for the refresh token record.
    /// </summary>
    public Guid Id { get; set; }

    /// <summary>
    /// Foreign key identifier of the parent user session.
    /// </summary>
    public Guid SessionId { get; set; }

    /// <summary>
    /// SHA-256 hash of the refresh token (64 lowercase hex characters).
    /// Raw token strings must NEVER be stored in this entity or the database.
    /// </summary>
    public string TokenHash { get; set; } = string.Empty;

    /// <summary>
    /// UTC timestamp when the token was created.
    /// </summary>
    public DateTime CreatedAtUtc { get; set; }

    /// <summary>
    /// UTC timestamp when the refresh token expires.
    /// </summary>
    public DateTime ExpiresAtUtc { get; set; }

    /// <summary>
    /// UTC timestamp when the token was revoked or rotated, or null if active.
    /// </summary>
    public DateTime? RevokedAtUtc { get; set; }

    /// <summary>
    /// SHA-256 hash of the successor token issued when this token was rotated, or null if never rotated.
    /// Used to trace token lineage and detect token replay attacks.
    /// </summary>
    public string? ReplacedByTokenHash { get; set; }

    /// <summary>
    /// Indicates whether the token has been replaced through rotation.
    /// </summary>
    public bool IsRotated => !string.IsNullOrEmpty(ReplacedByTokenHash);

    /// <summary>
    /// Indicates whether the token has been revoked (either through rotation or explicit revocation).
    /// </summary>
    public bool IsRevoked => RevokedAtUtc.HasValue;

    /// <summary>
    /// Indicates whether presenting this token constitutes a replay attack.
    /// An already-rotated token (ReplacedByTokenHash != null) remains a replay indefinitely,
    /// even after original expiration, session termination, or account suspension.
    /// Normal revocation without rotation is NOT classified as a replay.
    /// </summary>
    public bool IsReplay => IsRotated;

    /// <summary>
    /// Parameterless constructor required by EF Core.
    /// </summary>
    public RefreshToken()
    {
    }

    /// <summary>
    /// Evaluates whether the refresh token has passed its expiry timestamp.
    /// </summary>
    /// <param name="utcNow">Current UTC timestamp.</param>
    public bool IsExpired(DateTime utcNow)
    {
        return utcNow >= ExpiresAtUtc;
    }

    /// <summary>
    /// Evaluates whether the token is currently active and eligible for rotation.
    /// A token is active only if it has not been rotated, not revoked, and not expired.
    /// </summary>
    /// <param name="utcNow">Current UTC timestamp.</param>
    public bool IsActive(DateTime utcNow)
    {
        return !IsRotated && !IsRevoked && !IsExpired(utcNow);
    }

    /// <summary>
    /// Validates and normalizes a SHA-256 token hash.
    /// Invariants: Non-empty, exactly 64 hexadecimal characters.
    /// </summary>
    /// <param name="tokenHash">Hexadecimal SHA-256 token hash string.</param>
    /// <returns>Normalized lowercase 64-character hex string.</returns>
    /// <exception cref="ArgumentException">Thrown when hash is null, whitespace, or not a valid 64-character SHA-256 hex string.</exception>
    public static string ValidateAndNormalizeHash(string tokenHash)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(tokenHash);

        var trimmed = tokenHash.Trim().ToLowerInvariant();

        if (trimmed.Length != 64 || !Sha256HexRegex.IsMatch(trimmed))
        {
            throw new ArgumentException(
                $"Token hash '{tokenHash}' is invalid. Refresh token hashes must be exactly 64 lowercase hexadecimal characters representing a SHA-256 digest.",
                nameof(tokenHash));
        }

        return trimmed;
    }

    /// <summary>
    /// Factory method for instantiating a new RefreshToken with validated invariants.
    /// </summary>
    /// <param name="sessionId">Parent session ID.</param>
    /// <param name="tokenHash">SHA-256 hash of the generated refresh token.</param>
    /// <param name="utcNow">Creation timestamp in UTC.</param>
    /// <param name="lifetime">Token duration (must be strictly positive).</param>
    /// <returns>A validated RefreshToken instance.</returns>
    /// <exception cref="ArgumentException">Thrown when sessionId is empty, hash is invalid, or lifetime is not positive.</exception>
    public static RefreshToken Create(
        Guid sessionId,
        string tokenHash,
        DateTime utcNow,
        TimeSpan lifetime)
    {
        if (sessionId == Guid.Empty)
        {
            throw new ArgumentException("Refresh token must be associated with a valid, non-empty SessionId.", nameof(sessionId));
        }

        var validatedHash = ValidateAndNormalizeHash(tokenHash);

        if (lifetime <= TimeSpan.Zero)
        {
            throw new ArgumentException("Refresh token lifetime must be greater than zero.", nameof(lifetime));
        }

        return new RefreshToken
        {
            Id = Guid.NewGuid(),
            SessionId = sessionId,
            TokenHash = validatedHash,
            CreatedAtUtc = utcNow,
            ExpiresAtUtc = utcNow.Add(lifetime),
            RevokedAtUtc = null,
            ReplacedByTokenHash = null
        };
    }

    /// <summary>
    /// Rotates the refresh token, marking it replaced by a successor token hash.
    /// </summary>
    /// <param name="successorTokenHash">SHA-256 hash of the newly issued successor refresh token.</param>
    /// <param name="utcNow">Current UTC timestamp.</param>
    /// <exception cref="ArgumentException">Thrown when successor hash is invalid.</exception>
    /// <exception cref="InvalidOperationException">Thrown when token has already been rotated or successor equals current token hash.</exception>
    public void Rotate(string successorTokenHash, DateTime utcNow)
    {
        var validatedSuccessor = ValidateAndNormalizeHash(successorTokenHash);

        if (string.Equals(TokenHash, validatedSuccessor, StringComparison.Ordinal))
        {
            throw new InvalidOperationException("Successor token hash cannot be identical to current token hash.");
        }

        if (IsRotated)
        {
            throw new InvalidOperationException(
                $"Refresh token '{Id}' has already been rotated by successor token hash and cannot be rotated again.");
        }

        ReplacedByTokenHash = validatedSuccessor;
        RevokedAtUtc ??= utcNow;
    }

    /// <summary>
    /// Revokes the refresh token without rotating it (e.g., during explicit logout or session revocation).
    /// </summary>
    /// <param name="utcNow">Current UTC timestamp.</param>
    /// <returns>True if the token was newly revoked; false if already revoked.</returns>
    public bool Revoke(DateTime utcNow)
    {
        if (IsRevoked)
        {
            return false;
        }

        RevokedAtUtc = utcNow;
        return true;
    }

    /// <summary>
    /// Returns a string representation of the refresh token entity strictly omitting sensitive token hashes.
    /// </summary>
    public override string ToString()
    {
        return $"RefreshToken [Id={Id}, SessionId={SessionId}, ExpiresAtUtc={ExpiresAtUtc:O}, IsActive={!IsRevoked && !IsRotated}, IsRotated={IsRotated}, IsRevoked={IsRevoked}]";
    }
}

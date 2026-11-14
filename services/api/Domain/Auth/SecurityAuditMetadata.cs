namespace MaintenX.Api.Domain.Auth;

using System.Text.RegularExpressions;

/// <summary>
/// Strictly structured, immutable safe metadata value object for security audit events.
/// Only explicitly approved fields ('Reason', 'DetectedLineage', 'ActionTaken') are supported.
/// Rejects arbitrary unapproved properties, passwords, password hashes, raw tokens, token hashes, and submitted email addresses.
/// Prevents unvalidated construction by encapsulating property setters and validating all public construction paths.
/// </summary>
public sealed class SecurityAuditMetadata : IEquatable<SecurityAuditMetadata>
{
    private static readonly Regex Sha256HexRegex = new(
        @"^[a-fA-F0-9]{64}$",
        RegexOptions.Compiled | RegexOptions.CultureInvariant);

    /// <summary>
    /// Explicit audit reason (e.g., 'invalid_credentials', 'token_replay', 'user_logout', 'concurrency_stale_snapshot').
    /// </summary>
    public string? Reason { get; private set; }

    /// <summary>
    /// Audit lineage identifier or depth tracing token replacement hierarchy (e.g., 'predecessor_rotated', 'root_session').
    /// Raw token hashes are strictly prohibited.
    /// </summary>
    public string? DetectedLineage { get; private set; }

    /// <summary>
    /// Action taken in response to the security event (e.g., 'lockout_applied', 'session_revoked', 'login_permitted').
    /// </summary>
    public string? ActionTaken { get; private set; }

    /// <summary>
    /// Non-public parameterless constructor reserved exclusively for EF Core entity materialization.
    /// Application callers cannot invoke this constructor or bypass domain validation.
    /// </summary>
    private SecurityAuditMetadata()
    {
    }

    /// <summary>
    /// Public constructor validating all supplied metadata fields against platform security invariants.
    /// </summary>
    /// <param name="reason">Safe reason identifier.</param>
    /// <param name="detectedLineage">Safe lineage identifier.</param>
    /// <param name="actionTaken">Safe action-taken identifier.</param>
    /// <exception cref="ArgumentException">Thrown if any supplied field violates safety rules or contains sensitive data.</exception>
    public SecurityAuditMetadata(
        string? reason = null,
        string? detectedLineage = null,
        string? actionTaken = null)
    {
        ValidateMetadataField(nameof(reason), reason);
        ValidateMetadataField(nameof(detectedLineage), detectedLineage);
        ValidateMetadataField(nameof(actionTaken), actionTaken);

        Reason = string.IsNullOrWhiteSpace(reason) ? null : reason.Trim();
        DetectedLineage = string.IsNullOrWhiteSpace(detectedLineage) ? null : detectedLineage.Trim();
        ActionTaken = string.IsNullOrWhiteSpace(actionTaken) ? null : actionTaken.Trim();
    }

    /// <summary>
    /// Factory method instantiating a validated, safe <see cref="SecurityAuditMetadata"/> instance.
    /// </summary>
    /// <param name="reason">Safe reason identifier.</param>
    /// <param name="detectedLineage">Safe lineage identifier.</param>
    /// <param name="actionTaken">Safe action-taken identifier.</param>
    /// <returns>A validated SecurityAuditMetadata instance.</returns>
    /// <exception cref="ArgumentException">Thrown if any supplied field violates safety rules or contains sensitive data.</exception>
    public static SecurityAuditMetadata Create(
        string? reason = null,
        string? detectedLineage = null,
        string? actionTaken = null)
    {
        return new SecurityAuditMetadata(reason, detectedLineage, actionTaken);
    }

    private static void ValidateMetadataField(string fieldName, string? value)
    {
        if (string.IsNullOrWhiteSpace(value))
        {
            return;
        }

        var trimmed = value.Trim();

        if (trimmed.Length > 200)
        {
            throw new ArgumentException(
                $"Metadata field '{fieldName}' cannot exceed 200 characters in length. Supplied length was {trimmed.Length}.",
                fieldName);
        }

        // Prohibit email addresses
        if (trimmed.Contains('@'))
        {
            throw new ArgumentException(
                $"Metadata field '{fieldName}' cannot contain email addresses. Personally identifiable information must not be stored in audit metadata.",
                fieldName);
        }

        // Prohibit password hashes (e.g. Argon2, PBKDF2, bcrypt, or UNIX crypt prefixes)
        if (trimmed.StartsWith('$') || trimmed.Contains("$argon2") || trimmed.Contains("$pbkdf2") || trimmed.Contains("$2"))
        {
            throw new ArgumentException(
                $"Metadata field '{fieldName}' cannot contain password hashes or credential fragments.",
                fieldName);
        }

        // Prohibit raw 64-character hexadecimal token hashes
        if (trimmed.Length == 64 && Sha256HexRegex.IsMatch(trimmed))
        {
            throw new ArgumentException(
                $"Metadata field '{fieldName}' cannot contain raw 64-character token hashes.",
                fieldName);
        }

        // Prohibit sensitive keywords
        var lower = trimmed.ToLowerInvariant();
        if (lower.Contains("password") || lower.Contains("bearer ") || lower.Contains("secret") || lower.Contains("securitystamp"))
        {
            throw new ArgumentException(
                $"Metadata field '{fieldName}' contains prohibited sensitive credential keyword.",
                fieldName);
        }
    }

    public bool Equals(SecurityAuditMetadata? other)
    {
        if (other is null)
        {
            return false;
        }

        if (ReferenceEquals(this, other))
        {
            return true;
        }

        return string.Equals(Reason, other.Reason, StringComparison.Ordinal)
            && string.Equals(DetectedLineage, other.DetectedLineage, StringComparison.Ordinal)
            && string.Equals(ActionTaken, other.ActionTaken, StringComparison.Ordinal);
    }

    public override bool Equals(object? obj) => Equals(obj as SecurityAuditMetadata);

    public override int GetHashCode() => HashCode.Combine(Reason, DetectedLineage, ActionTaken);

    public static bool operator ==(SecurityAuditMetadata? left, SecurityAuditMetadata? right)
    {
        if (left is null)
        {
            return right is null;
        }

        return left.Equals(right);
    }

    public static bool operator !=(SecurityAuditMetadata? left, SecurityAuditMetadata? right) => !(left == right);
}

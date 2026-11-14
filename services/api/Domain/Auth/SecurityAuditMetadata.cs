namespace MaintenX.Api.Domain.Auth;

using System.Text.RegularExpressions;

/// <summary>
/// Strictly structured, safe metadata value object for security audit events.
/// Only explicitly approved fields ('Reason', 'DetectedLineage', 'ActionTaken') are supported.
/// Rejects arbitrary unapproved properties, passwords, password hashes, raw tokens, token hashes, and submitted email addresses.
/// </summary>
public sealed record SecurityAuditMetadata
{
    private static readonly Regex Sha256HexRegex = new(
        @"^[a-fA-F0-9]{64}$",
        RegexOptions.Compiled | RegexOptions.CultureInvariant);

    /// <summary>
    /// Explicit audit reason (e.g., 'invalid_credentials', 'token_replay', 'user_logout', 'concurrency_stale_snapshot').
    /// </summary>
    public string? Reason { get; init; }

    /// <summary>
    /// Audit lineage identifier or depth tracing token replacement hierarchy (e.g., 'predecessor_rotated', 'root_session').
    /// Raw token hashes are strictly prohibited.
    /// </summary>
    public string? DetectedLineage { get; init; }

    /// <summary>
    /// Action taken in response to the security event (e.g., 'lockout_applied', 'session_revoked', 'login_permitted').
    /// </summary>
    public string? ActionTaken { get; init; }

    /// <summary>
    /// Parameterless constructor for deserialization and EF Core materialization.
    /// </summary>
    public SecurityAuditMetadata()
    {
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
        ValidateMetadataField(nameof(reason), reason);
        ValidateMetadataField(nameof(detectedLineage), detectedLineage);
        ValidateMetadataField(nameof(actionTaken), actionTaken);

        return new SecurityAuditMetadata
        {
            Reason = string.IsNullOrWhiteSpace(reason) ? null : reason.Trim(),
            DetectedLineage = string.IsNullOrWhiteSpace(detectedLineage) ? null : detectedLineage.Trim(),
            ActionTaken = string.IsNullOrWhiteSpace(actionTaken) ? null : actionTaken.Trim()
        };
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
}

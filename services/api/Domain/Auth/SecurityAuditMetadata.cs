namespace MaintenX.Api.Domain.Auth;

using System.Collections.Frozen;
using System.Text.RegularExpressions;

/// <summary>
/// Strictly structured, genuinely immutable safe metadata value object for security audit events.
/// Only explicitly allow-listed reasons, actions, and constrained lineage identifiers are permitted.
/// Arbitrary user-controlled text, credentials, phone numbers, and alternative tokens are strictly rejected.
/// </summary>
public sealed class SecurityAuditMetadata : IEquatable<SecurityAuditMetadata>
{
    private static readonly Regex LineageIdentifierRegex = new(
        @"^(lineage|generation|gen|depth|ancestor|predecessor|node)_[a-zA-Z0-9]{1,32}$",
        RegexOptions.Compiled | RegexOptions.CultureInvariant);

    public static class Reasons
    {
        public const string UserRegistration = "user_registration";
        public const string StandardLogin = "standard_login";
        public const string InvalidCredentials = "invalid_credentials";
        public const string AccountLocked = "account_locked";
        public const string AccountSuspended = "account_suspended";
        public const string AccountReactivated = "account_reactivated";
        public const string AccountDeactivated = "account_deactivated";
        public const string TokenRefreshed = "token_refreshed";
        public const string TokenReplay = "token_replay";
        public const string TokenExpired = "token_expired";
        public const string TokenRevoked = "token_revoked";
        public const string UserLogout = "user_logout";
        public const string PasswordChanged = "password_changed";
        public const string SecurityStampRotated = "security_stamp_rotated";
        public const string SessionRevoked = "session_revoked";
        public const string SessionExpired = "session_expired";
        public const string RateLimitExceeded = "rate_limit_exceeded";
        public const string ConcurrencyConflict = "concurrency_conflict";
        public const string AdminAction = "admin_action";
    }

    public static class Actions
    {
        public const string Permit = "permit";
        public const string Deny = "deny";
        public const string LockoutApplied = "lockout_applied";
        public const string LockoutCleared = "lockout_cleared";
        public const string SessionCreated = "session_created";
        public const string SessionRevoked = "session_revoked";
        public const string TokenRotated = "token_rotated";
        public const string TokenRevoked = "token_revoked";
        public const string AccountSuspended = "account_suspended";
        public const string AccountReactivated = "account_reactivated";
        public const string AccountDeactivated = "account_deactivated";
        public const string SecurityStampRotated = "security_stamp_rotated";
        public const string RateLimited = "rate_limited";
        public const string AuditLogged = "audit_logged";
    }

    public static class Lineages
    {
        public const string RootSession = "root_session";
        public const string PredecessorRotated = "predecessor_rotated";
        public const string AncestorRotated = "ancestor_rotated";
        public const string SuccessorIssued = "successor_issued";
        public const string ReplayDetected = "replay_detected";
        public const string DirectRotation = "direct_rotation";
        public const string TerminalNode = "terminal_node";
    }

    /// <summary>
    /// Genuinely immutable set of permitted audit reasons.
    /// </summary>
    public static readonly FrozenSet<string> ApprovedReasons = new[]
    {
        Reasons.UserRegistration,
        Reasons.StandardLogin,
        Reasons.InvalidCredentials,
        Reasons.AccountLocked,
        Reasons.AccountSuspended,
        Reasons.AccountReactivated,
        Reasons.AccountDeactivated,
        Reasons.TokenRefreshed,
        Reasons.TokenReplay,
        Reasons.TokenExpired,
        Reasons.TokenRevoked,
        Reasons.UserLogout,
        Reasons.PasswordChanged,
        Reasons.SecurityStampRotated,
        Reasons.SessionRevoked,
        Reasons.SessionExpired,
        Reasons.RateLimitExceeded,
        Reasons.ConcurrencyConflict,
        Reasons.AdminAction
    }.ToFrozenSet(StringComparer.Ordinal);

    /// <summary>
    /// Genuinely immutable set of permitted audit actions.
    /// </summary>
    public static readonly FrozenSet<string> ApprovedActions = new[]
    {
        Actions.Permit,
        Actions.Deny,
        Actions.LockoutApplied,
        Actions.LockoutCleared,
        Actions.SessionCreated,
        Actions.SessionRevoked,
        Actions.TokenRotated,
        Actions.TokenRevoked,
        Actions.AccountSuspended,
        Actions.AccountReactivated,
        Actions.AccountDeactivated,
        Actions.SecurityStampRotated,
        Actions.RateLimited,
        Actions.AuditLogged
    }.ToFrozenSet(StringComparer.Ordinal);

    /// <summary>
    /// Genuinely immutable set of approved lineage constant identifiers.
    /// </summary>
    public static readonly FrozenSet<string> ApprovedLineages = new[]
    {
        Lineages.RootSession,
        Lineages.PredecessorRotated,
        Lineages.AncestorRotated,
        Lineages.SuccessorIssued,
        Lineages.ReplayDetected,
        Lineages.DirectRotation,
        Lineages.TerminalNode
    }.ToFrozenSet(StringComparer.Ordinal);

    /// <summary>
    /// Explicit audit reason.
    /// </summary>
    public string? Reason { get; private set; }

    /// <summary>
    /// Audit lineage identifier or depth tracing token replacement hierarchy.
    /// </summary>
    public string? DetectedLineage { get; private set; }

    /// <summary>
    /// Action taken in response to the security event.
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
    /// Public constructor validating all supplied metadata fields against platform allow-lists.
    /// </summary>
    /// <param name="reason">Safe reason identifier from <see cref="ApprovedReasons"/>.</param>
    /// <param name="detectedLineage">Safe lineage identifier from <see cref="ApprovedLineages"/> or matching pattern.</param>
    /// <param name="actionTaken">Safe action-taken identifier from <see cref="ApprovedActions"/>.</param>
    /// <exception cref="ArgumentException">Thrown if any supplied field violates allow-lists or contains sensitive data.</exception>
    public SecurityAuditMetadata(
        string? reason = null,
        string? detectedLineage = null,
        string? actionTaken = null)
    {
        Reason = ValidateAndNormalizeReason(reason);
        DetectedLineage = ValidateAndNormalizeLineage(detectedLineage);
        ActionTaken = ValidateAndNormalizeAction(actionTaken);
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

    public static string? ValidateAndNormalizeReason(string? reason)
    {
        if (string.IsNullOrWhiteSpace(reason))
        {
            return null;
        }

        var trimmed = reason.Trim();
        if (!ApprovedReasons.Contains(trimmed))
        {
            throw new ArgumentException(
                "Audit reason is not an approved identifier.",
                nameof(reason));
        }

        return trimmed;
    }

    public static string? ValidateAndNormalizeAction(string? actionTaken)
    {
        if (string.IsNullOrWhiteSpace(actionTaken))
        {
            return null;
        }

        var trimmed = actionTaken.Trim();
        if (!ApprovedActions.Contains(trimmed))
        {
            throw new ArgumentException(
                "Audit action is not an approved identifier.",
                nameof(actionTaken));
        }

        return trimmed;
    }

    public static string? ValidateAndNormalizeLineage(string? lineage)
    {
        if (string.IsNullOrWhiteSpace(lineage))
        {
            return null;
        }

        var trimmed = lineage.Trim();
        if (ApprovedLineages.Contains(trimmed) || LineageIdentifierRegex.IsMatch(trimmed))
        {
            return trimmed;
        }

        throw new ArgumentException(
            "Audit lineage identifier has an invalid format.",
            nameof(lineage));
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

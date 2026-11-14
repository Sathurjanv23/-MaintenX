namespace MaintenX.Api.Domain.Auth;

using System.Net;

/// <summary>
/// Immutable security audit event recording authentication, authorization, session, and credential lifecycle events.
/// Never stores passwords, password hashes, raw tokens, token hashes, or submitted email addresses.
/// Enforces structured safe metadata and explicit IP address validation.
/// Independent of EF Core and ASP.NET Core infrastructure.
/// </summary>
public sealed class SecurityAuditEvent
{
    /// <summary>
    /// Unique UUID primary key for the audit event.
    /// </summary>
    public Guid Id { get; private set; }

    /// <summary>
    /// Categorized type of security event.
    /// </summary>
    public SecurityAuditEventType EventType { get; private set; }

    /// <summary>
    /// User identifier associated with the event, or null if unauthenticated or pre-identification.
    /// </summary>
    public Guid? UserId { get; private set; }

    /// <summary>
    /// Session identifier associated with the event, or null if no session context exists.
    /// </summary>
    public Guid? SessionId { get; private set; }

    /// <summary>
    /// Validated IPv4 or IPv6 client IP address string, or null if the client IP was unavailable.
    /// </summary>
    public string? ClientIp { get; private set; }

    /// <summary>
    /// Structured, validated metadata containing approved non-sensitive audit fields.
    /// </summary>
    public SecurityAuditMetadata? Metadata { get; private set; }

    /// <summary>
    /// Explicit audit reason from structured metadata.
    /// </summary>
    public string? Reason => Metadata?.Reason;

    /// <summary>
    /// Audit lineage identifier or depth tracing token replacement hierarchy.
    /// </summary>
    public string? DetectedLineage => Metadata?.DetectedLineage;

    /// <summary>
    /// Action taken in response to the security event.
    /// </summary>
    public string? ActionTaken => Metadata?.ActionTaken;

    /// <summary>
    /// UTC timestamp of event creation.
    /// </summary>
    public DateTime CreatedAtUtc { get; private set; }

    /// <summary>
    /// Parameterless constructor required by EF Core for entity materialization.
    /// </summary>
    public SecurityAuditEvent()
    {
    }

    /// <summary>
    /// Validates and normalizes an input client IP address string against IPv4 and IPv6 syntax rules.
    /// </summary>
    /// <param name="clientIp">Raw IP string input, or null if unavailable.</param>
    /// <returns>Canonical IP address string, or null if unavailable.</returns>
    /// <exception cref="ArgumentException">Thrown when an input string is provided but is not a valid IPv4 or IPv6 address.</exception>
    public static string? ValidateAndNormalizeClientIp(string? clientIp)
    {
        if (string.IsNullOrWhiteSpace(clientIp))
        {
            return null;
        }

        var trimmed = clientIp.Trim();
        if (!IPAddress.TryParse(trimmed, out var parsedIp))
        {
            throw new ArgumentException(
                $"Client IP address '{clientIp}' is invalid. Must be a valid IPv4 or IPv6 address.",
                nameof(clientIp));
        }

        return parsedIp.ToString();
    }

    /// <summary>
    /// Factory method for instantiating an immutable SecurityAuditEvent record with structured safe metadata.
    /// </summary>
    /// <param name="eventType">Categorized security event type.</param>
    /// <param name="utcNow">Creation timestamp in UTC.</param>
    /// <param name="userId">Optional associated user identifier.</param>
    /// <param name="sessionId">Optional associated session identifier.</param>
    /// <param name="clientIp">Optional client IP address (must be valid IPv4/IPv6 if supplied).</param>
    /// <param name="metadata">Optional structured safe metadata.</param>
    /// <returns>A validated SecurityAuditEvent instance.</returns>
    public static SecurityAuditEvent Create(
        SecurityAuditEventType eventType,
        DateTime utcNow,
        Guid? userId = null,
        Guid? sessionId = null,
        string? clientIp = null,
        SecurityAuditMetadata? metadata = null)
    {
        var validatedIp = ValidateAndNormalizeClientIp(clientIp);

        return new SecurityAuditEvent
        {
            Id = Guid.NewGuid(),
            EventType = eventType,
            UserId = userId == Guid.Empty ? null : userId,
            SessionId = sessionId == Guid.Empty ? null : sessionId,
            ClientIp = validatedIp,
            Metadata = metadata,
            CreatedAtUtc = utcNow
        };
    }

    /// <summary>
    /// Convenience factory method taking individual approved metadata fields.
    /// </summary>
    public static SecurityAuditEvent Create(
        SecurityAuditEventType eventType,
        DateTime utcNow,
        Guid? userId,
        Guid? sessionId,
        string? clientIp,
        string reason,
        string? detectedLineage = null,
        string? actionTaken = null)
    {
        var meta = SecurityAuditMetadata.Create(reason, detectedLineage, actionTaken);
        return Create(eventType, utcNow, userId, sessionId, clientIp, meta);
    }

    /// <summary>
    /// Returns a string representation of the security audit event safely omitting secret details.
    /// </summary>
    public override string ToString()
    {
        return $"SecurityAuditEvent [Id={Id}, EventType={EventType}, UserId={UserId?.ToString() ?? "Anonymous"}, SessionId={SessionId?.ToString() ?? "None"}, ClientIp={ClientIp ?? "Unavailable"}, Reason={Reason ?? "None"}, CreatedAtUtc={CreatedAtUtc:O}]";
    }
}

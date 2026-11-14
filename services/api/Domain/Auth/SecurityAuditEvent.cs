namespace MaintenX.Api.Domain.Auth;

/// <summary>
/// Immutable security audit event recording authentication, authorization, session, and credential lifecycle events.
/// Never stores passwords, raw tokens, or security stamps.
/// Independent of EF Core and ASP.NET Core infrastructure.
/// </summary>
public sealed class SecurityAuditEvent
{
    private static readonly string[] ProhibitedSensitiveKeywords =
    [
        "password",
        "secret",
        "token=",
        "bearer ",
        "securitystamp",
        "hash"
    ];

    /// <summary>
    /// Unique UUID primary key for the audit event.
    /// </summary>
    public Guid Id { get; set; }

    /// <summary>
    /// Type of security event.
    /// </summary>
    public SecurityAuditEventType EventType { get; set; }

    /// <summary>
    /// User identifier associated with the event, or null if the event is unauthenticated or pre-identification.
    /// </summary>
    public Guid? UserId { get; set; }

    /// <summary>
    /// Session identifier associated with the event, or null if no session context exists.
    /// </summary>
    public Guid? SessionId { get; set; }

    /// <summary>
    /// Client IP address from which the request originated (max 45 characters to accommodate IPv6 strings).
    /// </summary>
    public string? ClientIp { get; set; }

    /// <summary>
    /// Structured JSON or textual metadata containing safe, non-sensitive audit details.
    /// </summary>
    public string? Details { get; set; }

    /// <summary>
    /// UTC timestamp of event creation.
    /// </summary>
    public DateTime CreatedAtUtc { get; set; }

    /// <summary>
    /// Parameterless constructor required by EF Core.
    /// </summary>
    public SecurityAuditEvent()
    {
    }

    /// <summary>
    /// Validates that structured audit details do not contain sensitive secrets or prohibited keywords.
    /// </summary>
    /// <param name="details">Audit details string to validate.</param>
    /// <exception cref="ArgumentException">Thrown if details contain obvious secret values or prohibited patterns.</exception>
    public static void ValidateDetails(string? details)
    {
        if (string.IsNullOrWhiteSpace(details))
        {
            return;
        }

        var lower = details.ToLowerInvariant();
        foreach (var keyword in ProhibitedSensitiveKeywords)
        {
            if (lower.Contains(keyword))
            {
                throw new ArgumentException(
                    $"Audit details contain prohibited sensitive keyword '{keyword}'. Sensitive credentials, password hashes, and raw tokens must never be logged.",
                    nameof(details));
            }
        }
    }

    /// <summary>
    /// Factory method for instantiating an immutable SecurityAuditEvent record with safety validations.
    /// </summary>
    /// <param name="eventType">Categorized security event type.</param>
    /// <param name="utcNow">Creation timestamp in UTC.</param>
    /// <param name="userId">Optional associated user identifier.</param>
    /// <param name="sessionId">Optional associated session identifier.</param>
    /// <param name="clientIp">Optional client IP address.</param>
    /// <param name="details">Optional structured non-sensitive details.</param>
    /// <returns>A validated SecurityAuditEvent instance.</returns>
    public static SecurityAuditEvent Create(
        SecurityAuditEventType eventType,
        DateTime utcNow,
        Guid? userId = null,
        Guid? sessionId = null,
        string? clientIp = null,
        string? details = null)
    {
        ValidateDetails(details);

        string? sanitizedIp = null;
        if (!string.IsNullOrWhiteSpace(clientIp))
        {
            sanitizedIp = clientIp.Trim();
            if (sanitizedIp.Length > 45)
            {
                sanitizedIp = sanitizedIp[..45];
            }
        }

        return new SecurityAuditEvent
        {
            Id = Guid.NewGuid(),
            EventType = eventType,
            UserId = userId == Guid.Empty ? null : userId,
            SessionId = sessionId == Guid.Empty ? null : sessionId,
            ClientIp = sanitizedIp,
            Details = string.IsNullOrWhiteSpace(details) ? null : details.Trim(),
            CreatedAtUtc = utcNow
        };
    }

    /// <summary>
    /// Returns a string representation of the security audit event safely omitting secret details.
    /// </summary>
    public override string ToString()
    {
        return $"SecurityAuditEvent [Id={Id}, EventType={EventType}, UserId={UserId?.ToString() ?? "Anonymous"}, SessionId={SessionId?.ToString() ?? "None"}, ClientIp={ClientIp ?? "Unknown"}, CreatedAtUtc={CreatedAtUtc:O}]";
    }
}

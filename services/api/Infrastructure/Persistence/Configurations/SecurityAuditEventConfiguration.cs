namespace MaintenX.Api.Infrastructure.Persistence.Configurations;

using System.Text;
using System.Text.Json;
using MaintenX.Api.Domain.Auth;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata.Builders;
using Microsoft.EntityFrameworkCore.Storage.ValueConversion;

/// <summary>
/// Entity configuration for SecurityAuditEvent.
/// Maps to 'platform.security_audit_events' with JSONB metadata serialization,
/// explicit indexes for security queries, and zero foreign key constraints to ensure
/// immutable, non-cascading audit trail persistence.
/// </summary>
public sealed class SecurityAuditEventConfiguration : IEntityTypeConfiguration<SecurityAuditEvent>
{
    private static readonly ValueConverter<SecurityAuditMetadata?, string?> MetadataConverter =
        new(
            v => SerializeMetadata(v),
            v => DeserializeMetadata(v));

    public void Configure(EntityTypeBuilder<SecurityAuditEvent> builder)
    {
        // 1. Table and Schema Mapping
        builder.ToTable("security_audit_events", "platform");

        // 2. Primary Key
        builder.HasKey(e => e.Id)
            .HasName("pk_security_audit_events");

        builder.Property(e => e.Id)
            .HasColumnName("id")
            .ValueGeneratedNever();

        // 3. Categorized Event Type
        builder.Property(e => e.EventType)
            .HasColumnName("event_type")
            .HasMaxLength(50)
            .HasConversion<string>()
            .IsRequired();

        // 4. Nullable User and Session References (No FKs - Append-only durability)
        builder.Property(e => e.UserId)
            .HasColumnName("user_id")
            .IsRequired(false);

        builder.Property(e => e.SessionId)
            .HasColumnName("session_id")
            .IsRequired(false);

        // 5. Client IP Address (IPv4 / IPv6, max 45 chars)
        builder.Property(e => e.ClientIp)
            .HasColumnName("client_ip")
            .HasMaxLength(45)
            .IsRequired(false);

        // 6. Structured Safe Metadata (PostgreSQL JSONB)
        builder.Property(e => e.Metadata)
            .HasColumnName("details_json")
            .HasColumnType("jsonb")
            .HasConversion(MetadataConverter)
            .IsRequired(false);

        // 7. Event Creation Timestamp
        builder.Property(e => e.CreatedAtUtc)
            .HasColumnName("created_at_utc")
            .HasColumnType("timestamp with time zone")
            .IsRequired();

        // 8. Ignore Domain Computed Properties
        builder.Ignore(e => e.Reason);
        builder.Ignore(e => e.DetectedLineage);
        builder.Ignore(e => e.ActionTaken);

        // 9. Indexes for Timeline, User, and Session Investigations
        builder.HasIndex(e => e.CreatedAtUtc)
            .HasDatabaseName("ix_security_audit_events_created_at_utc");

        builder.HasIndex(e => e.UserId)
            .HasDatabaseName("ix_security_audit_events_user_id");

        builder.HasIndex(e => e.SessionId)
            .HasDatabaseName("ix_security_audit_events_session_id");

        // 10. Database Check Constraints
        builder.ToTable(t =>
        {
            t.HasCheckConstraint(
                "ck_security_audit_events_event_type",
                "event_type IN ('UserRegistered', 'LoginSuccess', 'LoginFailed', 'AccountLockedOut', 'TokenRefreshed', 'TokenReplayDetected', 'SessionRevoked', 'PasswordChanged', 'SecurityStampRotated', 'UserSuspended', 'UserReactivated', 'UserDeactivated')");
        });
    }

    public static string? SerializeMetadata(SecurityAuditMetadata? metadata)
    {
        if (metadata is null)
        {
            return null;
        }

        using var stream = new MemoryStream();
        using (var writer = new Utf8JsonWriter(stream))
        {
            writer.WriteStartObject();
            if (metadata.Reason != null)
            {
                writer.WriteString("reason", metadata.Reason);
            }
            else
            {
                writer.WriteNull("reason");
            }

            if (metadata.DetectedLineage != null)
            {
                writer.WriteString("detectedLineage", metadata.DetectedLineage);
            }
            else
            {
                writer.WriteNull("detectedLineage");
            }

            if (metadata.ActionTaken != null)
            {
                writer.WriteString("actionTaken", metadata.ActionTaken);
            }
            else
            {
                writer.WriteNull("actionTaken");
            }

            writer.WriteEndObject();
        }

        return Encoding.UTF8.GetString(stream.ToArray());
    }

    public static SecurityAuditMetadata? DeserializeMetadata(string? json)
    {
        if (string.IsNullOrWhiteSpace(json))
        {
            return null;
        }

        using var doc = JsonDocument.Parse(json);
        var root = doc.RootElement;
        if (root.ValueKind != JsonValueKind.Object)
        {
            throw new InvalidOperationException("Audit metadata JSON must be an object.");
        }

        string? reason = root.TryGetProperty("reason", out var r) && r.ValueKind == JsonValueKind.String ? r.GetString() : null;
        string? lineage = root.TryGetProperty("detectedLineage", out var l) && l.ValueKind == JsonValueKind.String ? l.GetString() : null;
        string? action = root.TryGetProperty("actionTaken", out var a) && a.ValueKind == JsonValueKind.String ? a.GetString() : null;

        return SecurityAuditMetadata.Create(reason, lineage, action);
    }
}

namespace MaintenX.Api.Infrastructure.Persistence.Configurations;

using MaintenX.Api.Domain.Tenants;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata.Builders;

/// <summary>
/// Entity configuration for TenantAuditEvent.
/// Maps to 'platform.tenant_audit_events' with explicit indexes and zero foreign keys
/// to guarantee append-only durability and non-cascading persistence.
/// </summary>
public sealed class TenantAuditEventConfiguration : IEntityTypeConfiguration<TenantAuditEvent>
{
    public void Configure(EntityTypeBuilder<TenantAuditEvent> builder)
    {
        // 1. Table and Schema Mapping
        builder.ToTable("tenant_audit_events", "platform");

        // 2. Primary Key
        builder.HasKey(e => e.Id)
            .HasName("pk_tenant_audit_events");

        builder.Property(e => e.Id)
            .HasColumnName("id")
            .ValueGeneratedNever();

        // 3. Tenant and Actor References (No FKs - Append-only durability)
        builder.Property(e => e.TenantId)
            .HasColumnName("tenant_id")
            .IsRequired();

        builder.Property(e => e.ActorUserId)
            .HasColumnName("actor_user_id")
            .IsRequired();

        // 4. Action and Status Properties
        builder.Property(e => e.Action)
            .HasColumnName("action")
            .HasMaxLength(50)
            .IsRequired();

        builder.Property(e => e.PreviousStatus)
            .HasColumnName("previous_status")
            .HasMaxLength(50)
            .IsRequired();

        builder.Property(e => e.NewStatus)
            .HasColumnName("new_status")
            .HasMaxLength(50)
            .IsRequired();

        // 5. Reason (Nullable, Max 500)
        builder.Property(e => e.Reason)
            .HasColumnName("reason")
            .HasMaxLength(500)
            .IsRequired(false);

        // 6. Timestamps (UTC with time zone)
        builder.Property(e => e.CreatedAtUtc)
            .HasColumnName("created_at_utc")
            .HasColumnType("timestamp with time zone")
            .IsRequired();

        // 7. Explicit Indexes for Security and Compliance Audits
        builder.HasIndex(e => e.TenantId)
            .HasDatabaseName("ix_tenant_audit_events_tenant_id");

        builder.HasIndex(e => e.ActorUserId)
            .HasDatabaseName("ix_tenant_audit_events_actor_user_id");

        builder.HasIndex(e => e.CreatedAtUtc)
            .HasDatabaseName("ix_tenant_audit_events_created_at_utc");
    }
}

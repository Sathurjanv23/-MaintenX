namespace MaintenX.Api.Infrastructure.Persistence.Configurations;

using MaintenX.Api.Domain.Auth;
using MaintenX.Api.Domain.Tenants;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata.Builders;

/// <summary>
/// Entity configuration for TenantMembership.
/// Maps to 'platform.tenant_memberships' with foreign keys to 'platform.tenants' and 'platform.users',
/// cascade deletion, partial unique index enforcing at most one non-revoked membership per tenant-user pair,
/// and optimistic concurrency versioning.
/// </summary>
public sealed class TenantMembershipConfiguration : IEntityTypeConfiguration<TenantMembership>
{
    public void Configure(EntityTypeBuilder<TenantMembership> builder)
    {
        // 1. Table and Schema Mapping
        builder.ToTable("tenant_memberships", "platform");

        // 2. Primary Key
        builder.HasKey(m => m.Id)
            .HasName("pk_tenant_memberships");

        builder.Property(m => m.Id)
            .HasColumnName("id")
            .ValueGeneratedNever();

        // 3. Foreign Key to Tenant (Cascade Deletion)
        builder.Property(m => m.TenantId)
            .HasColumnName("tenant_id")
            .IsRequired();

        builder.HasOne<Tenant>()
            .WithMany()
            .HasForeignKey(m => m.TenantId)
            .HasConstraintName("fk_tenant_memberships_tenants_tenant_id")
            .OnDelete(DeleteBehavior.Cascade);

        // 4. Foreign Key to User (Cascade Deletion)
        builder.Property(m => m.UserId)
            .HasColumnName("user_id")
            .IsRequired();

        builder.HasOne<User>()
            .WithMany()
            .HasForeignKey(m => m.UserId)
            .HasConstraintName("fk_tenant_memberships_users_user_id")
            .OnDelete(DeleteBehavior.Cascade);

        // 5. Organizational Role (Enum stored as string with Check Constraint)
        builder.Property(m => m.Role)
            .HasColumnName("role")
            .HasMaxLength(50)
            .HasConversion<string>()
            .IsRequired();

        // 6. Operational Status (Enum stored as string with Check Constraint)
        builder.Property(m => m.Status)
            .HasColumnName("status")
            .HasMaxLength(50)
            .HasConversion<string>()
            .IsRequired();

        // 7. Audit and Lifecycle Timestamps
        builder.Property(m => m.CreatedAtUtc)
            .HasColumnName("created_at_utc")
            .HasColumnType("timestamp with time zone")
            .IsRequired();

        builder.Property(m => m.UpdatedAtUtc)
            .HasColumnName("updated_at_utc")
            .HasColumnType("timestamp with time zone")
            .IsRequired();

        builder.Property(m => m.DeactivatedAtUtc)
            .HasColumnName("deactivated_at_utc")
            .HasColumnType("timestamp with time zone")
            .IsRequired(false);

        // 8. Optimistic Concurrency Token
        builder.Property(m => m.Version)
            .HasColumnName("version")
            .IsConcurrencyToken()
            .IsRequired();

        // 9. Ignore Domain Computed Properties
        builder.Ignore(m => m.IsActive);

        // 10. Partial Unique Index: At most one non-revoked membership per (TenantId, UserId)
        // Historical revoked memberships are preserved without violating uniqueness,
        // allowing subsequent re-invitation with a new membership entity.
        builder.HasIndex(m => new { m.TenantId, m.UserId })
            .IsUnique()
            .HasFilter("status != 'Revoked'")
            .HasDatabaseName("ix_tenant_memberships_tenant_id_user_id_non_revoked");

        // 11. Lookup Indexes
        builder.HasIndex(m => m.TenantId)
            .HasDatabaseName("ix_tenant_memberships_tenant_id");

        builder.HasIndex(m => m.UserId)
            .HasDatabaseName("ix_tenant_memberships_user_id");

        builder.HasIndex(m => m.Status)
            .HasDatabaseName("ix_tenant_memberships_status");

        // 12. Database Check Constraints
        builder.ToTable(t =>
        {
            t.HasCheckConstraint(
                "ck_tenant_memberships_role",
                "role IN ('Owner', 'Administrator', 'Member')");

            t.HasCheckConstraint(
                "ck_tenant_memberships_status",
                "status IN ('Pending', 'Active', 'Suspended', 'Revoked')");
        });
    }
}

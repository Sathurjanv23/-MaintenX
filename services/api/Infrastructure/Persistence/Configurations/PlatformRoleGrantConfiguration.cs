namespace MaintenX.Api.Infrastructure.Persistence.Configurations;

using MaintenX.Api.Domain.Auth;
using MaintenX.Api.Domain.Authorization;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata.Builders;

/// <summary>
/// EF Core entity configuration for <see cref="PlatformRoleGrant"/>.
/// Maps to <c>platform.platform_role_grants</c> as a global authorization table (not tenant-scoped)
/// with restrictive user foreign key, strict lifecycle check constraints, and partial active-grant uniqueness.
/// </summary>
public sealed class PlatformRoleGrantConfiguration : IEntityTypeConfiguration<PlatformRoleGrant>
{
    public void Configure(EntityTypeBuilder<PlatformRoleGrant> builder)
    {
        // 1. Table and Schema Mapping
        builder.ToTable("platform_role_grants", "platform");

        // 2. Primary Key
        builder.HasKey(g => g.Id)
            .HasName("pk_platform_role_grants");

        builder.Property(g => g.Id)
            .HasColumnName("id")
            .ValueGeneratedNever();

        // 3. Target User Foreign Key (Restrictive deletion preserves historical privilege audit trail)
        builder.Property(g => g.UserId)
            .HasColumnName("user_id")
            .IsRequired();

        builder.HasOne<User>()
            .WithMany()
            .HasForeignKey(g => g.UserId)
            .HasConstraintName("fk_platform_role_grants_users_user_id")
            .OnDelete(DeleteBehavior.Restrict);

        // 4. Role & Status (Enums stored as canonical strings)
        builder.Property(g => g.Role)
            .HasColumnName("role")
            .HasMaxLength(50)
            .HasConversion<string>()
            .IsRequired();

        builder.Property(g => g.Status)
            .HasColumnName("status")
            .HasMaxLength(50)
            .HasConversion<string>()
            .IsRequired();

        // 5. Grant Attribution & Timestamps
        builder.Property(g => g.GrantedAtUtc)
            .HasColumnName("granted_at_utc")
            .HasColumnType("timestamp with time zone")
            .IsRequired();

        builder.Property(g => g.GrantedByUserId)
            .HasColumnName("granted_by_user_id")
            .IsRequired();

        // 6. Revocation Attribution & Timestamps (Nullable for Active grants)
        builder.Property(g => g.RevokedAtUtc)
            .HasColumnName("revoked_at_utc")
            .HasColumnType("timestamp with time zone")
            .IsRequired(false);

        builder.Property(g => g.RevokedByUserId)
            .HasColumnName("revoked_by_user_id")
            .IsRequired(false);

        builder.Property(g => g.RevocationReason)
            .HasColumnName("revocation_reason")
            .HasMaxLength(PlatformRoleGrant.MaxRevocationReasonLength)
            .IsRequired(false);

        // 7. Optimistic Concurrency Token
        builder.Property(g => g.Version)
            .HasColumnName("version")
            .IsConcurrencyToken()
            .IsRequired();

        // 8. Ignore Derived Domain Property
        builder.Ignore(g => g.IsActive);

        // 9. Partial Unique Index: At most one Active grant per (UserId, Role) while preserving Revoked history
        builder.HasIndex(g => new { g.UserId, g.Role })
            .IsUnique()
            .HasFilter("status = 'Active'")
            .HasDatabaseName("ix_platform_role_grants_user_id_role_active");

        // 10. Lookup Indexes
        builder.HasIndex(g => g.UserId)
            .HasDatabaseName("ix_platform_role_grants_user_id");

        builder.HasIndex(g => g.Status)
            .HasDatabaseName("ix_platform_role_grants_status");

        // 11. Database Check Constraints
        builder.ToTable(t =>
        {
            t.HasCheckConstraint(
                "ck_platform_role_grants_id_non_empty",
                "id <> '00000000-0000-0000-0000-000000000000'");

            t.HasCheckConstraint(
                "ck_platform_role_grants_user_id_non_empty",
                "user_id <> '00000000-0000-0000-0000-000000000000'");

            t.HasCheckConstraint(
                "ck_platform_role_grants_granted_by_non_empty",
                "granted_by_user_id <> '00000000-0000-0000-0000-000000000000'");

            t.HasCheckConstraint(
                "ck_platform_role_grants_role",
                "role IN ('PlatformAdministrator')");

            t.HasCheckConstraint(
                "ck_platform_role_grants_status",
                "status IN ('Active', 'Revoked')");

            t.HasCheckConstraint(
                "ck_platform_role_grants_version_positive",
                "version >= 1");

            t.HasCheckConstraint(
                "ck_platform_role_grants_revocation_consistency",
                "(status = 'Active' AND revoked_at_utc IS NULL AND revoked_by_user_id IS NULL AND revocation_reason IS NULL) OR " +
                "(status = 'Revoked' AND revoked_at_utc IS NOT NULL AND revoked_by_user_id IS NOT NULL AND revoked_by_user_id <> '00000000-0000-0000-0000-000000000000' AND revoked_at_utc >= granted_at_utc AND revocation_reason IS NOT NULL AND char_length(btrim(revocation_reason, chr(32) || chr(9) || chr(10) || chr(13) || chr(11) || chr(12) || chr(160) || chr(5760) || chr(8192) || chr(8193) || chr(8194) || chr(8195) || chr(8196) || chr(8197) || chr(8198) || chr(8199) || chr(8200) || chr(8201) || chr(8202) || chr(8232) || chr(8233) || chr(8239) || chr(8287) || chr(12288))) >= 3 AND char_length(revocation_reason) <= 500)");
        });
    }
}

namespace MaintenX.Api.Infrastructure.Persistence.Configurations;

using MaintenX.Api.Domain.Auth;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata.Builders;

/// <summary>
/// Entity configuration for the User identity entity.
/// Maps to 'platform.users' with strict constraints, case-insensitive email index, and optimistic concurrency.
/// </summary>
public sealed class UserConfiguration : IEntityTypeConfiguration<User>
{
    public void Configure(EntityTypeBuilder<User> builder)
    {
        // 1. Table and Schema Mapping
        builder.ToTable("users", "platform");

        // 2. Primary Key
        builder.HasKey(u => u.Id)
            .HasName("pk_users");

        builder.Property(u => u.Id)
            .HasColumnName("id")
            .ValueGeneratedNever();

        // 3. Email (Normalized, Lowercase, Required, Max Length 256, Unique Index)
        builder.Property(u => u.Email)
            .HasColumnName("email")
            .HasMaxLength(256)
            .IsRequired();

        builder.HasIndex(u => u.Email)
            .IsUnique()
            .HasDatabaseName("ix_users_email");

        // 4. Password Hash (Required, Max Length 500)
        builder.Property(u => u.PasswordHash)
            .HasColumnName("password_hash")
            .HasMaxLength(500)
            .IsRequired();

        // 5. Security Stamp (Required, Fixed/Max Length 64)
        builder.Property(u => u.SecurityStamp)
            .HasColumnName("security_stamp")
            .HasMaxLength(64)
            .IsRequired();

        // 6. Status (Enum stored as string with Check Constraint)
        builder.Property(u => u.Status)
            .HasColumnName("status")
            .HasMaxLength(50)
            .HasConversion<string>()
            .IsRequired();

        // 7. Failed Login Attempts Counter
        builder.Property(u => u.FailedLoginAttempts)
            .HasColumnName("failed_login_attempts")
            .HasDefaultValue(0)
            .IsRequired();

        // 8. Rolling Window & Lockout Timestamps
        builder.Property(u => u.FailedLoginWindowStartedAtUtc)
            .HasColumnName("failed_login_window_started_at_utc")
            .HasColumnType("timestamp with time zone")
            .IsRequired(false);

        builder.Property(u => u.LockoutEndUtc)
            .HasColumnName("lockout_end_utc")
            .HasColumnType("timestamp with time zone")
            .IsRequired(false);

        builder.Property(u => u.LastLoginAtUtc)
            .HasColumnName("last_login_at_utc")
            .HasColumnType("timestamp with time zone")
            .IsRequired(false);

        // 9. Audit Timestamps
        builder.Property(u => u.CreatedAtUtc)
            .HasColumnName("created_at_utc")
            .HasColumnType("timestamp with time zone")
            .IsRequired();

        builder.Property(u => u.UpdatedAtUtc)
            .HasColumnName("updated_at_utc")
            .HasColumnType("timestamp with time zone")
            .IsRequired();

        // 10. Optimistic Concurrency Token
        builder.Property(u => u.Version)
            .HasColumnName("version")
            .IsConcurrencyToken()
            .IsRequired();

        // 11. Database Check Constraints
        builder.ToTable(t =>
        {
            t.HasCheckConstraint(
                "ck_users_status",
                "status IN ('Active', 'Suspended', 'Deactivated')");

            t.HasCheckConstraint(
                "ck_users_email_lowercase",
                "email = lower(email)");

            t.HasCheckConstraint(
                "ck_users_failed_login_attempts",
                "failed_login_attempts >= 0");
        });
    }
}

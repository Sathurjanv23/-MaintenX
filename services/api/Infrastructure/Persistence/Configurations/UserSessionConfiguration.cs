namespace MaintenX.Api.Infrastructure.Persistence.Configurations;

using MaintenX.Api.Domain.Auth;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata.Builders;

/// <summary>
/// Entity configuration for UserSession.
/// Maps to 'platform.user_sessions' with foreign key to 'platform.users', cascade deletion,
/// activity tracking, and lifecycle indexes.
/// </summary>
public sealed class UserSessionConfiguration : IEntityTypeConfiguration<UserSession>
{
    public void Configure(EntityTypeBuilder<UserSession> builder)
    {
        // 1. Table and Schema Mapping
        builder.ToTable("user_sessions", "platform");

        // 2. Primary Key
        builder.HasKey(s => s.Id)
            .HasName("pk_user_sessions");

        builder.Property(s => s.Id)
            .HasColumnName("id")
            .ValueGeneratedNever();

        // 3. Foreign Key to User (Cascade Deletion)
        builder.Property(s => s.UserId)
            .HasColumnName("user_id")
            .IsRequired();

        builder.HasOne<User>()
            .WithMany()
            .HasForeignKey(s => s.UserId)
            .HasConstraintName("fk_user_sessions_users_user_id")
            .OnDelete(DeleteBehavior.Cascade);

        // 4. Session Lifecycle Timestamps
        builder.Property(s => s.CreatedAtUtc)
            .HasColumnName("created_at_utc")
            .HasColumnType("timestamp with time zone")
            .IsRequired();

        builder.Property(s => s.LastUsedAtUtc)
            .HasColumnName("last_used_at_utc")
            .HasColumnType("timestamp with time zone")
            .IsRequired();

        builder.Property(s => s.ExpiresAtUtc)
            .HasColumnName("expires_at_utc")
            .HasColumnType("timestamp with time zone")
            .IsRequired();

        builder.Property(s => s.RevokedAtUtc)
            .HasColumnName("revoked_at_utc")
            .HasColumnType("timestamp with time zone")
            .IsRequired(false);

        // 5. Revocation Reason
        builder.Property(s => s.RevocationReason)
            .HasColumnName("revocation_reason")
            .HasMaxLength(100)
            .IsRequired(false);

        // 6. Optimistic Concurrency Token
        builder.Property(s => s.Version)
            .HasColumnName("version")
            .IsConcurrencyToken()
            .IsRequired();

        // 7. Ignore Domain Computed Properties
        builder.Ignore(s => s.IsRevoked);

        // 8. Indexes
        builder.HasIndex(s => s.UserId)
            .HasDatabaseName("ix_user_sessions_user_id");

        builder.HasIndex(s => s.ExpiresAtUtc)
            .HasDatabaseName("ix_user_sessions_expires_at_utc");

        // 9. Database Check Constraints
        builder.ToTable(t =>
        {
            t.HasCheckConstraint(
                "ck_user_sessions_revocation_reason",
                "revocation_reason IS NULL OR revocation_reason IN ('UserLogout', 'PasswordChanged', 'SecurityStampMismatch', 'AccountSuspended', 'AccountDeactivated', 'TokenReplayDetected', 'AdminRevoked', 'Expired')");
        });
    }
}

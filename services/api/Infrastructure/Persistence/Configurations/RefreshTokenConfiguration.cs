namespace MaintenX.Api.Infrastructure.Persistence.Configurations;

using MaintenX.Api.Domain.Auth;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata.Builders;

/// <summary>
/// Entity configuration for RefreshToken.
/// Maps to 'platform.refresh_tokens' with foreign key to 'platform.user_sessions', cascade deletion,
/// SHA-256 token hash indexing, and rotation lineage tracking.
/// </summary>
public sealed class RefreshTokenConfiguration : IEntityTypeConfiguration<RefreshToken>
{
    public void Configure(EntityTypeBuilder<RefreshToken> builder)
    {
        // 1. Table and Schema Mapping
        builder.ToTable("refresh_tokens", "platform");

        // 2. Primary Key
        builder.HasKey(r => r.Id)
            .HasName("pk_refresh_tokens");

        builder.Property(r => r.Id)
            .HasColumnName("id")
            .ValueGeneratedNever();

        // 3. Foreign Key to UserSession (Cascade Deletion)
        builder.Property(r => r.SessionId)
            .HasColumnName("session_id")
            .IsRequired();

        builder.HasOne<UserSession>()
            .WithMany()
            .HasForeignKey(r => r.SessionId)
            .HasConstraintName("fk_refresh_tokens_user_sessions_session_id")
            .OnDelete(DeleteBehavior.Cascade);

        // 4. SHA-256 Token Hashes (64 hex characters)
        builder.Property(r => r.TokenHash)
            .HasColumnName("token_hash")
            .HasMaxLength(64)
            .IsFixedLength()
            .IsRequired();

        builder.Property(r => r.ReplacedByTokenHash)
            .HasColumnName("replaced_by_token_hash")
            .HasMaxLength(64)
            .IsFixedLength()
            .IsRequired(false);

        // 5. Lifecycle Timestamps
        builder.Property(r => r.CreatedAtUtc)
            .HasColumnName("created_at_utc")
            .HasColumnType("timestamp with time zone")
            .IsRequired();

        builder.Property(r => r.ExpiresAtUtc)
            .HasColumnName("expires_at_utc")
            .HasColumnType("timestamp with time zone")
            .IsRequired();

        builder.Property(r => r.RevokedAtUtc)
            .HasColumnName("revoked_at_utc")
            .HasColumnType("timestamp with time zone")
            .IsRequired(false);

        // 6. Ignore Domain Computed Properties
        builder.Ignore(r => r.IsRotated);
        builder.Ignore(r => r.IsRevoked);
        builder.Ignore(r => r.IsReplay);

        // 7. Indexes
        builder.HasIndex(r => r.TokenHash)
            .IsUnique()
            .HasDatabaseName("ix_refresh_tokens_token_hash");

        builder.HasIndex(r => r.SessionId)
            .HasDatabaseName("ix_refresh_tokens_session_id");

        builder.HasIndex(r => r.ExpiresAtUtc)
            .HasDatabaseName("ix_refresh_tokens_expires_at_utc");

        // 8. Database Check Constraints
        builder.ToTable(t =>
        {
            t.HasCheckConstraint(
                "ck_refresh_tokens_token_hash",
                "token_hash ~ '^[a-f0-9]{64}$'");

            t.HasCheckConstraint(
                "ck_refresh_tokens_replaced_by_token_hash",
                "replaced_by_token_hash IS NULL OR replaced_by_token_hash ~ '^[a-f0-9]{64}$'");
        });
    }
}

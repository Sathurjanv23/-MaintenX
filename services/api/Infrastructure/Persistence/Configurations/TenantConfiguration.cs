namespace MaintenX.Api.Infrastructure.Persistence.Configurations;

using MaintenX.Api.Domain.Tenants;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata.Builders;

/// <summary>
/// Entity configuration for the Tenant root catalog entity.
/// Maps to 'platform.tenants' with strict constraints, indexes, and concurrency control.
/// </summary>
public sealed class TenantConfiguration : IEntityTypeConfiguration<Tenant>
{
    public void Configure(EntityTypeBuilder<Tenant> builder)
    {
        // 1. Table and Schema Mapping
        builder.ToTable("tenants", "platform");

        // 2. Primary Key
        builder.HasKey(t => t.Id)
            .HasName("pk_tenants");

        builder.Property(t => t.Id)
            .HasColumnName("id")
            .ValueGeneratedNever();

        // 3. Slug (Normalized, Required, Unique Index)
        builder.Property(t => t.Slug)
            .HasColumnName("slug")
            .HasMaxLength(100)
            .IsRequired();

        builder.HasIndex(t => t.Slug)
            .IsUnique()
            .HasDatabaseName("ix_tenants_slug");

        // 4. Display Name (Required, Max Length 200)
        builder.Property(t => t.DisplayName)
            .HasColumnName("display_name")
            .HasMaxLength(200)
            .IsRequired();

        // 5. Status (Enum stored as string with DB Check Constraint)
        builder.Property(t => t.Status)
            .HasColumnName("status")
            .HasMaxLength(50)
            .HasConversion<string>()
            .IsRequired();

        builder.ToTable(t => t.HasCheckConstraint(
            "ck_tenants_status",
            "status IN ('Active', 'Suspended', 'PendingOnboarding', 'Deactivated')"));

        // 6. Timestamps (UTC with time zone)
        builder.Property(t => t.CreatedAtUtc)
            .HasColumnName("created_at_utc")
            .HasColumnType("timestamp with time zone")
            .IsRequired();

        builder.Property(t => t.UpdatedAtUtc)
            .HasColumnName("updated_at_utc")
            .HasColumnType("timestamp with time zone")
            .IsRequired();

        // 7. Optimistic Concurrency Token
        builder.Property(t => t.Version)
            .HasColumnName("version")
            .IsConcurrencyToken()
            .IsRequired();
    }
}

#nullable disable

namespace MaintenX.Api.Infrastructure.Persistence.Migrations;

using Microsoft.EntityFrameworkCore.Migrations;

/// <summary>
/// Additive migration introducing PostgreSQL CHECK constraint on platform.tenants (slug).
/// Enforces lowercase alphanumeric characters and single hyphens between words.
/// </summary>
public partial class HardenTenantSlugConstraints : Migration
{
    /// <inheritdoc />
    protected override void Up(MigrationBuilder migrationBuilder)
    {
        migrationBuilder.AddCheckConstraint(
            name: "ck_tenants_slug",
            schema: "platform",
            table: "tenants",
            sql: "slug ~ '^[a-z0-9]+(-[a-z0-9]+)*$' AND length(slug) >= 2 AND length(slug) <= 100");
    }

    /// <inheritdoc />
    protected override void Down(MigrationBuilder migrationBuilder)
    {
        migrationBuilder.DropCheckConstraint(
            name: "ck_tenants_slug",
            schema: "platform",
            table: "tenants");
    }
}

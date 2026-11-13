#nullable disable

namespace MaintenX.Api.Infrastructure.Persistence.Migrations;

using System;
using Microsoft.EntityFrameworkCore.Migrations;

/// <summary>
/// Initial database migration establishing the platform schema and tenants catalog table.
/// </summary>
public partial class InitialDatabaseFoundation : Migration
{
    /// <inheritdoc />
    protected override void Up(MigrationBuilder migrationBuilder)
    {
        migrationBuilder.EnsureSchema(
            name: "platform");

        migrationBuilder.CreateTable(
            name: "tenants",
            schema: "platform",
            columns: table => new
            {
                id = table.Column<Guid>(type: "uuid", nullable: false),
                slug = table.Column<string>(type: "character varying(100)", maxLength: 100, nullable: false),
                display_name = table.Column<string>(type: "character varying(200)", maxLength: 200, nullable: false),
                status = table.Column<string>(type: "character varying(50)", maxLength: 50, nullable: false),
                created_at_utc = table.Column<DateTime>(type: "timestamp with time zone", nullable: false),
                updated_at_utc = table.Column<DateTime>(type: "timestamp with time zone", nullable: false),
                version = table.Column<long>(type: "bigint", nullable: false)
            },
            constraints: table =>
            {
                table.PrimaryKey("pk_tenants", x => x.id);
                table.CheckConstraint("ck_tenants_status", "status IN ('Active', 'Suspended', 'PendingOnboarding', 'Deactivated')");
            });

        migrationBuilder.CreateIndex(
            name: "ix_tenants_slug",
            schema: "platform",
            table: "tenants",
            column: "slug",
            unique: true);
    }

    /// <inheritdoc />
    protected override void Down(MigrationBuilder migrationBuilder)
    {
        migrationBuilder.DropTable(
            name: "tenants",
            schema: "platform");
    }
}

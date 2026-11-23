#nullable disable

namespace MaintenX.Api.Infrastructure.Persistence.Migrations;

using System;
using Microsoft.EntityFrameworkCore.Migrations;

/// <summary>
/// Additive migration introducing tenant membership persistence:
/// platform.tenant_memberships with foreign keys, partial unique index, and check constraints.
/// </summary>
public partial class AddTenantMembershipPersistence : Migration
{
    /// <inheritdoc />
    protected override void Up(MigrationBuilder migrationBuilder)
    {
        migrationBuilder.CreateTable(
            name: "tenant_memberships",
            schema: "platform",
            columns: table => new
            {
                id = table.Column<Guid>(type: "uuid", nullable: false),
                tenant_id = table.Column<Guid>(type: "uuid", nullable: false),
                user_id = table.Column<Guid>(type: "uuid", nullable: false),
                role = table.Column<string>(type: "character varying(50)", maxLength: 50, nullable: false),
                status = table.Column<string>(type: "character varying(50)", maxLength: 50, nullable: false),
                created_at_utc = table.Column<DateTime>(type: "timestamp with time zone", nullable: false),
                updated_at_utc = table.Column<DateTime>(type: "timestamp with time zone", nullable: false),
                deactivated_at_utc = table.Column<DateTime>(type: "timestamp with time zone", nullable: true),
                version = table.Column<long>(type: "bigint", nullable: false)
            },
            constraints: table =>
            {
                table.PrimaryKey("pk_tenant_memberships", x => x.id);
                table.CheckConstraint("ck_tenant_memberships_role", "role IN ('Owner', 'Administrator', 'Member')");
                table.CheckConstraint("ck_tenant_memberships_status", "status IN ('Pending', 'Active', 'Suspended', 'Revoked')");
                table.ForeignKey(
                    name: "fk_tenant_memberships_tenants_tenant_id",
                    column: x => x.tenant_id,
                    principalSchema: "platform",
                    principalTable: "tenants",
                    principalColumn: "id",
                    onDelete: ReferentialAction.Cascade);
                table.ForeignKey(
                    name: "fk_tenant_memberships_users_user_id",
                    column: x => x.user_id,
                    principalSchema: "platform",
                    principalTable: "users",
                    principalColumn: "id",
                    onDelete: ReferentialAction.Cascade);
            });

        migrationBuilder.CreateIndex(
            name: "ix_tenant_memberships_tenant_id_user_id_non_revoked",
            schema: "platform",
            table: "tenant_memberships",
            columns: new[] { "tenant_id", "user_id" },
            unique: true,
            filter: "status != 'Revoked'");

        migrationBuilder.CreateIndex(
            name: "ix_tenant_memberships_tenant_id",
            schema: "platform",
            table: "tenant_memberships",
            column: "tenant_id");

        migrationBuilder.CreateIndex(
            name: "ix_tenant_memberships_user_id",
            schema: "platform",
            table: "tenant_memberships",
            column: "user_id");

        migrationBuilder.CreateIndex(
            name: "ix_tenant_memberships_status",
            schema: "platform",
            table: "tenant_memberships",
            column: "status");
    }

    /// <inheritdoc />
    protected override void Down(MigrationBuilder migrationBuilder)
    {
        migrationBuilder.DropTable(
            name: "tenant_memberships",
            schema: "platform");
    }
}

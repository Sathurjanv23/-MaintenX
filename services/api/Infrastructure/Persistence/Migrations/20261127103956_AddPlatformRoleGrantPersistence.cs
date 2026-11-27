using System;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace MaintenX.Api.Infrastructure.Persistence.Migrations
{
    /// <inheritdoc />
    public partial class AddPlatformRoleGrantPersistence : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.CreateTable(
                name: "platform_role_grants",
                schema: "platform",
                columns: table => new
                {
                    id = table.Column<Guid>(type: "uuid", nullable: false),
                    user_id = table.Column<Guid>(type: "uuid", nullable: false),
                    role = table.Column<string>(type: "character varying(50)", maxLength: 50, nullable: false),
                    status = table.Column<string>(type: "character varying(50)", maxLength: 50, nullable: false),
                    granted_at_utc = table.Column<DateTime>(type: "timestamp with time zone", nullable: false),
                    granted_by_user_id = table.Column<Guid>(type: "uuid", nullable: false),
                    revoked_at_utc = table.Column<DateTime>(type: "timestamp with time zone", nullable: true),
                    revoked_by_user_id = table.Column<Guid>(type: "uuid", nullable: true),
                    revocation_reason = table.Column<string>(type: "character varying(500)", maxLength: 500, nullable: true),
                    version = table.Column<long>(type: "bigint", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("pk_platform_role_grants", x => x.id);
                    table.CheckConstraint("ck_platform_role_grants_granted_by_non_empty", "granted_by_user_id <> '00000000-0000-0000-0000-000000000000'");
                    table.CheckConstraint("ck_platform_role_grants_revocation_consistency", "(status = 'Active' AND revoked_at_utc IS NULL AND revoked_by_user_id IS NULL AND revocation_reason IS NULL) OR (status = 'Revoked' AND revoked_at_utc IS NOT NULL AND revoked_by_user_id IS NOT NULL AND revoked_by_user_id <> '00000000-0000-0000-0000-000000000000' AND revoked_at_utc >= granted_at_utc AND revocation_reason IS NOT NULL AND char_length(btrim(revocation_reason)) >= 3 AND char_length(revocation_reason) <= 500)");
                    table.CheckConstraint("ck_platform_role_grants_role", "role IN ('PlatformAdministrator')");
                    table.CheckConstraint("ck_platform_role_grants_status", "status IN ('Active', 'Revoked')");
                    table.CheckConstraint("ck_platform_role_grants_user_id_non_empty", "user_id <> '00000000-0000-0000-0000-000000000000'");
                    table.CheckConstraint("ck_platform_role_grants_version_positive", "version >= 1");
                    table.ForeignKey(
                        name: "fk_platform_role_grants_users_user_id",
                        column: x => x.user_id,
                        principalSchema: "platform",
                        principalTable: "users",
                        principalColumn: "id",
                        onDelete: ReferentialAction.Restrict);
                });

            migrationBuilder.CreateIndex(
                name: "ix_platform_role_grants_status",
                schema: "platform",
                table: "platform_role_grants",
                column: "status");

            migrationBuilder.CreateIndex(
                name: "ix_platform_role_grants_user_id",
                schema: "platform",
                table: "platform_role_grants",
                column: "user_id");

            migrationBuilder.CreateIndex(
                name: "ix_platform_role_grants_user_id_role_active",
                schema: "platform",
                table: "platform_role_grants",
                columns: new[] { "user_id", "role" },
                unique: true,
                filter: "status = 'Active'");
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropTable(
                name: "platform_role_grants",
                schema: "platform");
        }
    }
}

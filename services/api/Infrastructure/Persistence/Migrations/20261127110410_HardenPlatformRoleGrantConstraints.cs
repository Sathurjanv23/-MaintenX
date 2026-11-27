using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace MaintenX.Api.Infrastructure.Persistence.Migrations
{
    /// <inheritdoc />
    public partial class HardenPlatformRoleGrantConstraints : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropCheckConstraint(
                name: "ck_platform_role_grants_revocation_consistency",
                schema: "platform",
                table: "platform_role_grants");

            migrationBuilder.AddCheckConstraint(
                name: "ck_platform_role_grants_id_non_empty",
                schema: "platform",
                table: "platform_role_grants",
                sql: "id <> '00000000-0000-0000-0000-000000000000'");

            migrationBuilder.AddCheckConstraint(
                name: "ck_platform_role_grants_revocation_consistency",
                schema: "platform",
                table: "platform_role_grants",
                sql: "(status = 'Active' AND revoked_at_utc IS NULL AND revoked_by_user_id IS NULL AND revocation_reason IS NULL) OR (status = 'Revoked' AND revoked_at_utc IS NOT NULL AND revoked_by_user_id IS NOT NULL AND revoked_by_user_id <> '00000000-0000-0000-0000-000000000000' AND revoked_at_utc >= granted_at_utc AND revocation_reason IS NOT NULL AND char_length(btrim(revocation_reason, chr(32) || chr(9) || chr(10) || chr(13) || chr(11) || chr(12) || chr(160) || chr(5760) || chr(8192) || chr(8193) || chr(8194) || chr(8195) || chr(8196) || chr(8197) || chr(8198) || chr(8199) || chr(8200) || chr(8201) || chr(8202) || chr(8232) || chr(8233) || chr(8239) || chr(8287) || chr(12288))) >= 3 AND char_length(revocation_reason) <= 500)");
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropCheckConstraint(
                name: "ck_platform_role_grants_id_non_empty",
                schema: "platform",
                table: "platform_role_grants");

            migrationBuilder.DropCheckConstraint(
                name: "ck_platform_role_grants_revocation_consistency",
                schema: "platform",
                table: "platform_role_grants");

            migrationBuilder.AddCheckConstraint(
                name: "ck_platform_role_grants_revocation_consistency",
                schema: "platform",
                table: "platform_role_grants",
                sql: "(status = 'Active' AND revoked_at_utc IS NULL AND revoked_by_user_id IS NULL AND revocation_reason IS NULL) OR (status = 'Revoked' AND revoked_at_utc IS NOT NULL AND revoked_by_user_id IS NOT NULL AND revoked_by_user_id <> '00000000-0000-0000-0000-000000000000' AND revoked_at_utc >= granted_at_utc AND revocation_reason IS NOT NULL AND char_length(btrim(revocation_reason)) >= 3 AND char_length(revocation_reason) <= 500)");
        }
    }
}

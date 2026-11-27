using System;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace MaintenX.Api.Infrastructure.Persistence.Migrations
{
    /// <inheritdoc />
    public partial class AddPlatformAdminBootstrapAttribution : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropCheckConstraint(
                name: "ck_security_audit_events_event_type",
                schema: "platform",
                table: "security_audit_events");

            migrationBuilder.DropCheckConstraint(
                name: "ck_platform_role_grants_granted_by_non_empty",
                schema: "platform",
                table: "platform_role_grants");

            migrationBuilder.AlterColumn<Guid>(
                name: "granted_by_user_id",
                schema: "platform",
                table: "platform_role_grants",
                type: "uuid",
                nullable: true,
                oldClrType: typeof(Guid),
                oldType: "uuid");

            migrationBuilder.AddColumn<string>(
                name: "granted_by_actor_kind",
                schema: "platform",
                table: "platform_role_grants",
                type: "character varying(50)",
                maxLength: 50,
                nullable: false,
                defaultValue: "User");

            migrationBuilder.AddColumn<string>(
                name: "granted_by_operator_id",
                schema: "platform",
                table: "platform_role_grants",
                type: "character varying(200)",
                maxLength: 200,
                nullable: true);

            migrationBuilder.AddCheckConstraint(
                name: "ck_security_audit_events_event_type",
                schema: "platform",
                table: "security_audit_events",
                sql: "event_type IN ('UserRegistered', 'LoginSuccess', 'LoginFailed', 'AccountLockedOut', 'TokenRefreshed', 'TokenReplayDetected', 'SessionRevoked', 'PasswordChanged', 'SecurityStampRotated', 'UserSuspended', 'UserReactivated', 'UserDeactivated', 'PlatformAdministratorBootstrapped')");

            migrationBuilder.AddCheckConstraint(
                name: "ck_platform_role_grants_granted_actor_consistency",
                schema: "platform",
                table: "platform_role_grants",
                sql: "(granted_by_actor_kind = 'User' AND granted_by_user_id IS NOT NULL AND granted_by_user_id <> '00000000-0000-0000-0000-000000000000' AND granted_by_operator_id IS NULL) OR (granted_by_actor_kind = 'DeploymentOperator' AND granted_by_user_id IS NULL AND granted_by_operator_id IS NOT NULL AND char_length(btrim(granted_by_operator_id, chr(32) || chr(9) || chr(10) || chr(13) || chr(11) || chr(12) || chr(160) || chr(5760) || chr(8192) || chr(8193) || chr(8194) || chr(8195) || chr(8196) || chr(8197) || chr(8198) || chr(8199) || chr(8200) || chr(8201) || chr(8202) || chr(8232) || chr(8233) || chr(8239) || chr(8287) || chr(12288))) >= 3 AND char_length(granted_by_operator_id) <= 200)");

            migrationBuilder.AddCheckConstraint(
                name: "ck_platform_role_grants_granted_by_actor_kind",
                schema: "platform",
                table: "platform_role_grants",
                sql: "granted_by_actor_kind IN ('User', 'DeploymentOperator')");
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropCheckConstraint(
                name: "ck_security_audit_events_event_type",
                schema: "platform",
                table: "security_audit_events");

            migrationBuilder.DropCheckConstraint(
                name: "ck_platform_role_grants_granted_actor_consistency",
                schema: "platform",
                table: "platform_role_grants");

            migrationBuilder.DropCheckConstraint(
                name: "ck_platform_role_grants_granted_by_actor_kind",
                schema: "platform",
                table: "platform_role_grants");

            migrationBuilder.DropColumn(
                name: "granted_by_actor_kind",
                schema: "platform",
                table: "platform_role_grants");

            migrationBuilder.DropColumn(
                name: "granted_by_operator_id",
                schema: "platform",
                table: "platform_role_grants");

            migrationBuilder.AlterColumn<Guid>(
                name: "granted_by_user_id",
                schema: "platform",
                table: "platform_role_grants",
                type: "uuid",
                nullable: false,
                defaultValue: new Guid("00000000-0000-0000-0000-000000000000"),
                oldClrType: typeof(Guid),
                oldType: "uuid",
                oldNullable: true);

            migrationBuilder.AddCheckConstraint(
                name: "ck_security_audit_events_event_type",
                schema: "platform",
                table: "security_audit_events",
                sql: "event_type IN ('UserRegistered', 'LoginSuccess', 'LoginFailed', 'AccountLockedOut', 'TokenRefreshed', 'TokenReplayDetected', 'SessionRevoked', 'PasswordChanged', 'SecurityStampRotated', 'UserSuspended', 'UserReactivated', 'UserDeactivated')");

            migrationBuilder.AddCheckConstraint(
                name: "ck_platform_role_grants_granted_by_non_empty",
                schema: "platform",
                table: "platform_role_grants",
                sql: "granted_by_user_id <> '00000000-0000-0000-0000-000000000000'");
        }
    }
}

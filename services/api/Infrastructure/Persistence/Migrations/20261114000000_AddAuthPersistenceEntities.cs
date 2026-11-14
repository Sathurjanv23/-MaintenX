#nullable disable

namespace MaintenX.Api.Infrastructure.Persistence.Migrations;

using System;
using Microsoft.EntityFrameworkCore.Migrations;

/// <summary>
/// Additive migration introducing authentication persistence entities:
/// platform.users, platform.user_sessions, platform.refresh_tokens, and platform.security_audit_events.
/// </summary>
public partial class AddAuthPersistenceEntities : Migration
{
    /// <inheritdoc />
    protected override void Up(MigrationBuilder migrationBuilder)
    {
        // 1. Create platform.users
        migrationBuilder.CreateTable(
            name: "users",
            schema: "platform",
            columns: table => new
            {
                id = table.Column<Guid>(type: "uuid", nullable: false),
                email = table.Column<string>(type: "character varying(256)", maxLength: 256, nullable: false),
                password_hash = table.Column<string>(type: "character varying(500)", maxLength: 500, nullable: false),
                security_stamp = table.Column<string>(type: "character varying(64)", maxLength: 64, nullable: false),
                status = table.Column<string>(type: "character varying(50)", maxLength: 50, nullable: false),
                failed_login_attempts = table.Column<int>(type: "integer", nullable: false, defaultValue: 0),
                failed_login_window_started_at_utc = table.Column<DateTime>(type: "timestamp with time zone", nullable: true),
                lockout_end_utc = table.Column<DateTime>(type: "timestamp with time zone", nullable: true),
                last_login_at_utc = table.Column<DateTime>(type: "timestamp with time zone", nullable: true),
                created_at_utc = table.Column<DateTime>(type: "timestamp with time zone", nullable: false),
                updated_at_utc = table.Column<DateTime>(type: "timestamp with time zone", nullable: false),
                version = table.Column<long>(type: "bigint", nullable: false)
            },
            constraints: table =>
            {
                table.PrimaryKey("pk_users", x => x.id);
                table.CheckConstraint("ck_users_status", "status IN ('Active', 'Suspended', 'Deactivated')");
                table.CheckConstraint("ck_users_email_lowercase", "email = lower(email)");
                table.CheckConstraint("ck_users_failed_login_attempts", "failed_login_attempts >= 0");
            });

        migrationBuilder.CreateIndex(
            name: "ix_users_email",
            schema: "platform",
            table: "users",
            column: "email",
            unique: true);

        // 2. Create platform.user_sessions
        migrationBuilder.CreateTable(
            name: "user_sessions",
            schema: "platform",
            columns: table => new
            {
                id = table.Column<Guid>(type: "uuid", nullable: false),
                user_id = table.Column<Guid>(type: "uuid", nullable: false),
                created_at_utc = table.Column<DateTime>(type: "timestamp with time zone", nullable: false),
                last_used_at_utc = table.Column<DateTime>(type: "timestamp with time zone", nullable: false),
                expires_at_utc = table.Column<DateTime>(type: "timestamp with time zone", nullable: false),
                revoked_at_utc = table.Column<DateTime>(type: "timestamp with time zone", nullable: true),
                revocation_reason = table.Column<string>(type: "character varying(100)", maxLength: 100, nullable: true),
                version = table.Column<long>(type: "bigint", nullable: false)
            },
            constraints: table =>
            {
                table.PrimaryKey("pk_user_sessions", x => x.id);
                table.CheckConstraint("ck_user_sessions_revocation_reason", "revocation_reason IS NULL OR revocation_reason IN ('UserLogout', 'PasswordChanged', 'SecurityStampMismatch', 'AccountSuspended', 'AccountDeactivated', 'TokenReplayDetected', 'AdminRevoked', 'Expired')");
                table.ForeignKey(
                    name: "fk_user_sessions_users_user_id",
                    column: x => x.user_id,
                    principalSchema: "platform",
                    principalTable: "users",
                    principalColumn: "id",
                    onDelete: ReferentialAction.Cascade);
            });

        migrationBuilder.CreateIndex(
            name: "ix_user_sessions_user_id",
            schema: "platform",
            table: "user_sessions",
            column: "user_id");

        migrationBuilder.CreateIndex(
            name: "ix_user_sessions_expires_at_utc",
            schema: "platform",
            table: "user_sessions",
            column: "expires_at_utc");

        // 3. Create platform.refresh_tokens
        migrationBuilder.CreateTable(
            name: "refresh_tokens",
            schema: "platform",
            columns: table => new
            {
                id = table.Column<Guid>(type: "uuid", nullable: false),
                session_id = table.Column<Guid>(type: "uuid", nullable: false),
                token_hash = table.Column<string>(type: "character(64)", fixedLength: true, maxLength: 64, nullable: false),
                replaced_by_token_hash = table.Column<string>(type: "character(64)", fixedLength: true, maxLength: 64, nullable: true),
                created_at_utc = table.Column<DateTime>(type: "timestamp with time zone", nullable: false),
                expires_at_utc = table.Column<DateTime>(type: "timestamp with time zone", nullable: false),
                revoked_at_utc = table.Column<DateTime>(type: "timestamp with time zone", nullable: true)
            },
            constraints: table =>
            {
                table.PrimaryKey("pk_refresh_tokens", x => x.id);
                table.CheckConstraint("ck_refresh_tokens_token_hash", "token_hash ~ '^[a-f0-9]{64}$'");
                table.CheckConstraint("ck_refresh_tokens_replaced_by_token_hash", "replaced_by_token_hash IS NULL OR replaced_by_token_hash ~ '^[a-f0-9]{64}$'");
                table.ForeignKey(
                    name: "fk_refresh_tokens_user_sessions_session_id",
                    column: x => x.session_id,
                    principalSchema: "platform",
                    principalTable: "user_sessions",
                    principalColumn: "id",
                    onDelete: ReferentialAction.Cascade);
            });

        migrationBuilder.CreateIndex(
            name: "ix_refresh_tokens_token_hash",
            schema: "platform",
            table: "refresh_tokens",
            column: "token_hash",
            unique: true);

        migrationBuilder.CreateIndex(
            name: "ix_refresh_tokens_session_id",
            schema: "platform",
            table: "refresh_tokens",
            column: "session_id");

        migrationBuilder.CreateIndex(
            name: "ix_refresh_tokens_expires_at_utc",
            schema: "platform",
            table: "refresh_tokens",
            column: "expires_at_utc");

        // 4. Create platform.security_audit_events (zero FKs to preserve durable audit trail)
        migrationBuilder.CreateTable(
            name: "security_audit_events",
            schema: "platform",
            columns: table => new
            {
                id = table.Column<Guid>(type: "uuid", nullable: false),
                event_type = table.Column<string>(type: "character varying(50)", maxLength: 50, nullable: false),
                user_id = table.Column<Guid>(type: "uuid", nullable: true),
                session_id = table.Column<Guid>(type: "uuid", nullable: true),
                client_ip = table.Column<string>(type: "character varying(45)", maxLength: 45, nullable: true),
                details_json = table.Column<string>(type: "jsonb", nullable: true),
                created_at_utc = table.Column<DateTime>(type: "timestamp with time zone", nullable: false)
            },
            constraints: table =>
            {
                table.PrimaryKey("pk_security_audit_events", x => x.id);
                table.CheckConstraint("ck_security_audit_events_event_type", "event_type IN ('UserRegistered', 'LoginSuccess', 'LoginFailed', 'AccountLockedOut', 'TokenRefreshed', 'TokenReplayDetected', 'SessionRevoked', 'PasswordChanged', 'SecurityStampRotated', 'UserSuspended', 'UserReactivated', 'UserDeactivated')");
            });

        migrationBuilder.CreateIndex(
            name: "ix_security_audit_events_created_at_utc",
            schema: "platform",
            table: "security_audit_events",
            column: "created_at_utc");

        migrationBuilder.CreateIndex(
            name: "ix_security_audit_events_user_id",
            schema: "platform",
            table: "security_audit_events",
            column: "user_id");

        migrationBuilder.CreateIndex(
            name: "ix_security_audit_events_session_id",
            schema: "platform",
            table: "security_audit_events",
            column: "session_id");
    }

    /// <inheritdoc />
    protected override void Down(MigrationBuilder migrationBuilder)
    {
        migrationBuilder.DropTable(
            name: "security_audit_events",
            schema: "platform");

        migrationBuilder.DropTable(
            name: "refresh_tokens",
            schema: "platform");

        migrationBuilder.DropTable(
            name: "user_sessions",
            schema: "platform");

        migrationBuilder.DropTable(
            name: "users",
            schema: "platform");
    }
}

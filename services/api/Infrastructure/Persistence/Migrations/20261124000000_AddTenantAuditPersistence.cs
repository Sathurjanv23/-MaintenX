#nullable disable

namespace MaintenX.Api.Infrastructure.Persistence.Migrations;

using System;
using Microsoft.EntityFrameworkCore.Migrations;

/// <summary>
/// Additive migration introducing tenant audit event persistence:
/// platform.tenant_audit_events with immutable audit trail and explicit indexes.
/// </summary>
public partial class AddTenantAuditPersistence : Migration
{
    /// <inheritdoc />
    protected override void Up(MigrationBuilder migrationBuilder)
    {
        migrationBuilder.CreateTable(
            name: "tenant_audit_events",
            schema: "platform",
            columns: table => new
            {
                id = table.Column<Guid>(type: "uuid", nullable: false),
                tenant_id = table.Column<Guid>(type: "uuid", nullable: false),
                actor_user_id = table.Column<Guid>(type: "uuid", nullable: false),
                action = table.Column<string>(type: "character varying(50)", maxLength: 50, nullable: false),
                previous_status = table.Column<string>(type: "character varying(50)", maxLength: 50, nullable: false),
                new_status = table.Column<string>(type: "character varying(50)", maxLength: 50, nullable: false),
                reason = table.Column<string>(type: "character varying(500)", maxLength: 500, nullable: true),
                created_at_utc = table.Column<DateTime>(type: "timestamp with time zone", nullable: false)
            },
            constraints: table =>
            {
                table.PrimaryKey("pk_tenant_audit_events", x => x.id);
            });

        migrationBuilder.CreateIndex(
            name: "ix_tenant_audit_events_tenant_id",
            schema: "platform",
            table: "tenant_audit_events",
            column: "tenant_id");

        migrationBuilder.CreateIndex(
            name: "ix_tenant_audit_events_actor_user_id",
            schema: "platform",
            table: "tenant_audit_events",
            column: "actor_user_id");

        migrationBuilder.CreateIndex(
            name: "ix_tenant_audit_events_created_at_utc",
            schema: "platform",
            table: "tenant_audit_events",
            column: "created_at_utc");
    }

    /// <inheritdoc />
    protected override void Down(MigrationBuilder migrationBuilder)
    {
        migrationBuilder.DropTable(
            name: "tenant_audit_events",
            schema: "platform");
    }
}

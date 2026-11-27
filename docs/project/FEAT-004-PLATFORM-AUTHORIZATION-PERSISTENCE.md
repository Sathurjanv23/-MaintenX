# MaintenX — FEAT-004 Task 4.2.1 Platform Authorization Persistence

**Feature:** FEAT-004 — Role-Based Access Control (RBAC) & Platform Administration  
**Task:** 4.2.1 — Platform Authorization Persistence  
**Base Commit:** `d1f4c6717919ab2ece749f638effbbe077099ceb` (PR #44 merged on `main`)  
**Feature Branch:** `feat/004-02-01-platform-role-persistence`  
**Owner:** Sathu (`sathurjanv.23@uom.lk`) | **Reviewer:** Janu (`januka-karunakaran`)

---

## 1. Migration Dependency Conflict & Approved Scope Adjustment

### Root Cause
In EF Core 10, `Database.MigrateAsync()` validates the runtime `DbContext` model against the compiled model snapshot and throws `Microsoft.EntityFrameworkCore.Migrations.PendingModelChangesWarning` when `MaintenXDbContext` registers `PlatformRoleGrant` without a corresponding migration. Keeping entity configuration in Task 4.2.1 and migration generation in Task 4.2.2 broke all 14 `TenantPersistenceIntegrationTests` (and all integration tests invoking `MigrateAsync()`).

### Approved Revised Step 4.2 Task Boundaries
- **Task 4.2.1 (Current):** `PlatformRoleGrant` EF Core configuration (`PlatformRoleGrantConfiguration`), `MaintenXDbContext` registration (`PlatformRoleGrants`), EF Core model metadata unit tests (`PlatformRoleGrantPersistenceModelTests`), the single additive EF Core migration (`20261127103956_AddPlatformRoleGrantPersistence`), and migration smoke tests (`PlatformRoleGrantMigrationSmokeTests`).
- **Task 4.2.2 (Next):** Physical PostgreSQL constraint enforcement (all 6 check constraints, restrictive FK delete behavior, NULL semantics), migration upgrade/rollback verification, active-grant partial unique index enforcement, historical revoked grant retention, re-granting after revocation, and database integrity tests.
- **Task 4.2.3:** Persistence security verification, global scope isolation, optimistic concurrency under PostgreSQL, regression testing, and Step 4.3 handover.

> [!NOTE]
> Runtime platform authorization, administrator provisioning, and public lifecycle endpoints remain out of scope for Step 4.2 and are deferred to Steps 4.3–4.8. No administrator users or grants are seeded.

---

## 2. Persistence Schema & Migration Summary

- **Migration:** `20261127103956_AddPlatformRoleGrantPersistence`
- **Target Table:** `platform.platform_role_grants`
- **Primary Key:** `pk_platform_role_grants` (`id` `uuid`)
- **Foreign Key:** `fk_platform_role_grants_users_user_id` (`user_id` -> `platform.users(id)`, `ON DELETE RESTRICT`)
- **Concurrency Token:** `version` (`bigint`, `IsConcurrencyToken = true`)
- **Derived Property Ignored:** `IsActive`
- **Global Scope:** Does not implement `ITenantEntity`; excluded from tenant query filters and tenant write ownership checks.

### Check Constraints
1. `ck_platform_role_grants_user_id_non_empty`: `user_id <> '00000000-0000-0000-0000-000000000000'`
2. `ck_platform_role_grants_granted_by_non_empty`: `granted_by_user_id <> '00000000-0000-0000-0000-000000000000'`
3. `ck_platform_role_grants_role`: `role IN ('PlatformAdministrator')`
4. `ck_platform_role_grants_status`: `status IN ('Active', 'Revoked')`
5. `ck_platform_role_grants_version_positive`: `version >= 1`
6. `ck_platform_role_grants_revocation_consistency`: `(status = 'Active' AND revoked_at_utc IS NULL AND revoked_by_user_id IS NULL AND revocation_reason IS NULL) OR (status = 'Revoked' AND revoked_at_utc IS NOT NULL AND revoked_by_user_id IS NOT NULL AND revoked_by_user_id <> '00000000-0000-0000-0000-000000000000' AND revoked_at_utc >= granted_at_utc AND revocation_reason IS NOT NULL AND char_length(btrim(revocation_reason)) >= 3 AND char_length(revocation_reason) <= 500)`

### Indexes
- `ix_platform_role_grants_user_id` (`user_id`)
- `ix_platform_role_grants_status` (`status`)
- `ix_platform_role_grants_user_id_role_active` (`UNIQUE` on `(user_id, role)` `WHERE status = 'Active'`)

### Rollback Behavior & Data-Loss Warning
- `Up()` is strictly additive (`CreateTable` + 3 `CreateIndex` calls on `platform.platform_role_grants`); no existing tables, columns, or tenant isolation rules are modified.
- `Down()` executes `DropTable("platform_role_grants", schema: "platform")`. **Rolling back this migration permanently removes all `platform.platform_role_grants` data** and must only be executed against disposable test databases or with an approved backup/restore plan.

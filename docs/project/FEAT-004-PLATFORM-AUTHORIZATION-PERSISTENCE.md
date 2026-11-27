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

---

## 3. Task 4.2.2 Physical PostgreSQL Verification & Corrective Migration

**Verification Branch:** `feat/004-02-02-permission-persistence` (base `295e668a8b80838374363629898dacb326545bb4`)  
**Corrective Migration:** `20261127110410_HardenPlatformRoleGrantConstraints`

### Confirmed Database Integrity Defects & Corrections
1. **Empty Primary Key UUID (`id = Guid.Empty`)**: PostgreSQL accepted `00000000-0000-0000-0000-000000000000` for `id` because `PRIMARY KEY` alone does not prohibit the all-zero UUID. Added `ck_platform_role_grants_id_non_empty` (`id <> '00000000-0000-0000-0000-000000000000'`).
2. **Revocation Reason Whitespace Mismatch**: PostgreSQL `btrim(revocation_reason)` without a second argument trims only ASCII space (`U+0020`), so `"\t\t\t"`, `"\n\n\n"`, `"\r\n\t "`, `"\u00A0\u00A0\u00A0"`, and `"  ab\t"` previously passed the `>= 3` length check. Updated `ck_platform_role_grants_revocation_consistency` to trim ASCII whitespace (`chr(32), chr(9), chr(10), chr(13), chr(11), chr(12)`) and Unicode `Char.IsWhiteSpace` separators (`chr(160), chr(5760), chr(8192)–chr(8202), chr(8232), chr(8233), chr(8239), chr(8287), chr(12288)`).

### Verification Matrix
| Area | Status | Evidence |
|---|---|---|
| Physical schema (`information_schema.columns`, `pg_constraint`, `pg_indexes`) | **PASS** | `PhysicalSchema_*` (`10` columns, no `tenant_id` / `is_active`, 7 check constraints, 1 restrictive FK, 3 indexes) |
| Check constraints (`23514`) & NOT NULL (`23502`) | **PASS** | `CheckConstraints_*`, `NotNullConstraints_*` |
| Revocation consistency, NULL semantics & whitespace boundaries (`23514`, `22001`) | **PASS** | `RevocationConsistency_*`, `RevocationReason_*` |
| Partial unique index (`23505`) & concurrent duplicate inserts | **PASS** | `PartialUniqueIndex_*` (single active grant, multiple revoked history, re-granting, concurrent race) |
| Target user FK & restrictive deletion (`23503`) | **PASS** | `ForeignKey_NonexistentUserRejected_AndHardDeletingUserWithActiveOrRevokedGrantBlockedWith23503` |
| EF Core lifecycle round-trip & optimistic concurrency | **PASS** | `EfCoreRoundTrip_CreateRevokeIdempotentAndOptimisticConcurrency` (`Version` 1 -> 2, idempotency, `DbUpdateConcurrencyException`) |
| Migration upgrade safety with existing records | **PASS** | `MigrationUpgrade_FromPreviousMigrationWithExistingRecords_PreservesDataAndAddsTable` |
| Runtime platform authorization & lifecycle endpoints | **DEFERRED** | Steps `4.3`–`4.8` |

### Actor Attribution & Lifecycle Boundary
- **Actor Attribution (`granted_by_user_id`, `revoked_by_user_id`):** Intentionally have **no foreign key** to `platform.users(id)` so historical audit attribution outlives user accounts and bootstrap attribution in Step 4.3.2 does not require fabricating a synthetic user. A non-empty UUID is not proof of a verified administrator identity; authoritative actor verification belongs to application services in Steps `4.3`+.
- **Row-Level CHECK Boundary:** PostgreSQL `CHECK` constraints validate current row state only; they do not prevent a raw SQL `UPDATE` from mutating a `Revoked` row back to `Active` if all columns are made consistent. Terminal transition immutability is enforced in domain/application services (`PlatformRoleGrant.Revoke()`).


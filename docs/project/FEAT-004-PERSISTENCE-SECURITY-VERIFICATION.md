# MaintenX — FEAT-004 Step 4.2 Persistence Security Verification & Step 4.3 Handover

**Feature:** FEAT-004 — Role-Based Access Control (RBAC) & Platform Administration  
**Task:** 4.2.3 — Persistence Security Verification (Step 4.2 Gate)  
**Base Commit:** `cea67e6afb60e4f10a8a4b1cb7920bbcd622bbc1` (PR #46 merged on `main`)  
**Feature Branch:** `test/004-02-03-rbac-persistence-security`  
**Owner:** Sathu (`sathurjanv.23@uom.lk`) | **Reviewer:** Janu (`januka-karunakaran`)

---

## 1. Executive Summary & Step 4.2 Acceptance Decision

**Step 4.2 Persistence Acceptance Decision:** **PASS (RBAC Persistence Foundation Verified)** — `PlatformRoleGrant` EF Core mapping, additive migrations (`20261127103956_AddPlatformRoleGrantPersistence` and `20261127110410_HardenPlatformRoleGrantConstraints`), physical PostgreSQL 16 constraints, global scope isolation, transactional optimistic concurrency, historical grant retention, and non-exposure across existing HTTP endpoints are verified.

> [!IMPORTANT]
> **Runtime Authorization Remains Deferred (`TD-01`):** Having a persisted `Active` `PlatformRoleGrant` row does **not** grant runtime platform authority yet. `TenantActorResolver` continues to set `IsPlatformAdmin = false` for all HTTP requests, and no public platform grant or tenant lifecycle routes are exposed. Runtime resolution and administrator provisioning belong to Step 4.3.

---

## 2. Step 4.2 Scope & Task Traceability (4.2.1 – 4.2.3)

| Task | Scope | Outcome | Primary Evidence |
|---|---|---|---|
| **4.2.1** | `PlatformRoleGrantConfiguration`, `MaintenXDbContext` registration, model metadata tests, additive migration `AddPlatformRoleGrantPersistence`, migration smoke tests | **PASS** (PR #45) | `PlatformRoleGrantPersistenceModelTests` (4), `PlatformRoleGrantMigrationSmokeTests` (2) |
| **4.2.2** | Physical PostgreSQL 16 schema, 7 check constraints, restrictive FK, partial unique index, concurrent insert race, lifecycle round-trip, corrective migration `HardenPlatformRoleGrantConstraints` | **PASS** (PR #46) | `PlatformRoleGrantDatabaseIntegrityTests` (29) |
| **4.2.3** | Global scope isolation, tenant filter preservation, HTTP non-exposure, premature authority protection, transactional concurrency, auth/audit data preservation, Step 4.3 handover | **PASS** (Current) | `PlatformRoleGrantPersistenceSecurityTests` (5) |

---

## 3. Final Physical Database Schema & Entity Configuration

- **Table:** `platform.platform_role_grants` (`10` columns; no `tenant_id`, no `is_active`)
- **Entity:** `PlatformRoleGrant` (`IsActive` ignored; does not implement `ITenantEntity`)
- **Primary Key:** `pk_platform_role_grants` on `id` (`uuid`)
- **Foreign Key:** `fk_platform_role_grants_users_user_id` (`user_id` -> `platform.users(id)`, `ON DELETE RESTRICT`)
- **Concurrency Token:** `version` (`bigint`, `IsConcurrencyToken = true`)
- **Secondary Indexes (`3`):** `ix_platform_role_grants_user_id`, `ix_platform_role_grants_status`, and partial unique index `ix_platform_role_grants_user_id_role_active` (`UNIQUE (user_id, role) WHERE status = 'Active'`)
- **Check Constraints (`7`):**
  1. `ck_platform_role_grants_id_non_empty` (`id <> '00000000-0000-0000-0000-000000000000'`)
  2. `ck_platform_role_grants_user_id_non_empty` (`user_id <> '00000000-0000-0000-0000-000000000000'`)
  3. `ck_platform_role_grants_granted_by_non_empty` (`granted_by_user_id <> '00000000-0000-0000-0000-000000000000'`)
  4. `ck_platform_role_grants_role` (`role IN ('PlatformAdministrator')`)
  5. `ck_platform_role_grants_status` (`status IN ('Active', 'Revoked')`)
  6. `ck_platform_role_grants_version_positive` (`version >= 1`)
  7. `ck_platform_role_grants_revocation_consistency` (enforces `NULL` revocation fields on `Active`, non-null/non-empty/ordered revocation metadata on `Revoked`, and ASCII + Unicode whitespace trimming `>= 3` and `<= 500` chars)

---

## 4. Security Verification Findings

### 4.1 Global Data Scope & Tenant Isolation Preservation
- **PASS:** `PlatformRoleGrant` does not implement `ITenantEntity` and receives no tenant query filter or write-ownership check. Reads and writes succeed with no active tenant context, under Tenant A, under Tenant B, and across parallel tenant contexts, while `TenantMemberships` remain strictly isolated per tenant and fail-closed without a tenant context.

### 4.2 HTTP Exposure & Premature Authority Protection
- **PASS:** Repository audit confirms `PlatformRoleGrant` / `PlatformRoleGrants` have zero references in `Application/*` or HTTP endpoints. `TenantActorResolver` unconditionally sets `IsPlatformAdmin: false`.
- **PASS:** Integration test `PrematureAuthorityProtection_ActivePlatformRoleGrant_DoesNotElevateHttpActorOrExposeGrants` verifies that a user with a persisted `Active` `PlatformRoleGrant` cannot obtain platform data from `GET /api/v1/tenants/{id}` or `/api/v1/tenants/me`, cannot elevate via `X-Platform-Admin: true`, cannot access `/api/v1/tenants/{id}/activate`, and receives `404` on `/api/v1/platform/role-grants`.

### 4.3 Optimistic Concurrency & Multi-Row Limitations
- **PASS (Single-Row):** Explicit PostgreSQL transaction test confirms stale revocation fails with `DbUpdateConcurrencyException` while leaving the authoritative revocation (`Version = 2`, `RevokedByUserId`, `RevocationReason`, `Id`) intact with zero duplicate rows.
- **Known Limitation (Multi-Row):** Neither `version` nor `ix_platform_role_grants_user_id_role_active` prevents two concurrent transactions from revoking two *different* `PlatformAdministrator` rows simultaneously (last-admin race). Step 4.3+ mutation services must implement global administrator mutation coordination (authoritative grant revalidation, account eligibility checks, consistent lock ordering, atomic grant + audit mutations, and retry/serialization handling).

### 4.4 Historical Grant Retention & Actor Attribution Policy
- **Retention:** Revoking a grant transitions `Status` to `Revoked` (`Version` incremented); re-granting creates a new row with a distinct `Id`. Row-level `CHECK` constraints do not enforce transition immutability against raw SQL `UPDATE`/`DELETE` by a privileged DB operator; application services must enforce terminal revocation.
- **Actor Attribution:** `granted_by_user_id` and `revoked_by_user_id` intentionally have no FK so audit attribution outlives user accounts. A non-empty UUID is attribution metadata only, not proof of actor authority. Task `4.3.2` must resolve genuine operator-driven first-admin bootstrap attribution without fabricating fake users or using the target user's ID artificially.

### 4.5 Migration Upgrade, Corrective Safety & Rollback
- **PASS:** Upgrading from `20261124000000_AddTenantAuditPersistence` preserves `Tenant`, `User`, `TenantMembership`, `UserSession`, `RefreshToken`, `SecurityAuditEvent`, and `TenantAuditEvent` with zero seeded administrators.
- **PASS:** Upgrading from `20261127103956_AddPlatformRoleGrantPersistence` to `20261127110410_HardenPlatformRoleGrantConstraints` preserves existing valid `Active` and `Revoked` grants; rolling back `HardenPlatformRoleGrantConstraints` preserves valid records; rolling back `AddPlatformRoleGrantPersistence` drops `platform.platform_role_grants` and its data (destructive — disposable test DBs only).
- **Pending Model Changes:** `dotnet ef migrations has-pending-model-changes` and `HasPendingModelChanges()` report zero drift.

---

## 5. Confirmed Defects Resolved in Step 4.2

1. **Task 4.2.1:** Resolved EF Core 10 `PendingModelChangesWarning` on `MigrateAsync()` via approved additive migration `20261127103956_AddPlatformRoleGrantPersistence`.
2. **Task 4.2.2:** Added `ck_platform_role_grants_id_non_empty` (rejecting `id = Guid.Empty`) and hardened `ck_platform_role_grants_revocation_consistency` (ASCII + Unicode whitespace trimming) via `20261127110410_HardenPlatformRoleGrantConstraints`.
3. **Task 4.2.3:** Zero new persistence security defects discovered.

---

## 6. SRS Traceability & Technical Debt

- **FR-005 (RBAC & Permissions):** **PARTIAL** — Domain foundation (Step 4.1) and PostgreSQL persistence (Step 4.2) complete; runtime resolution, provisioning, and endpoints deferred to Steps `4.3`–`4.8`.
- **NFR-001 (Multi-Tenant Isolation):** **COMPLETE (Preserved)** — Global `PlatformRoleGrant` entity verified not to weaken tenant query filters or ownership checks.
- **Unresolved Technical Debt:** `TD-01` (Authoritative platform admin identity — still open), `TD-02`, `TD-03`, `TD-04`, `TD-05`, `TD-06`, `TD-07`, `TD-08`, `TD-12` (GitHub reviewer assignment).
- **Resolved Technical Debt (Preserved):** `TD-09`, `TD-10`, `TD-11`.

---

## 7. Step 4.3 Trusted Authority Handover

- **4.3.1 — Authoritative Platform Grant Resolver:** Resolve persisted `Active` `PlatformRoleGrant`s for verified authenticated users with active account eligibility and valid non-revoked session; fail-closed; map to `PlatformRolePermissionMap` without arbitrary actor Booleans.
- **4.3.2 — Secure Platform Administrator Provisioning:** Explicit operator-authorized first-admin bootstrap, genuine audit attribution (resolving `GrantedByUserId` bootstrap design without synthetic users), idempotency, zero default credentials, no public self-promotion.
- **4.3.3 — Trusted Actor Integration & Revocation:** Integrate trusted `IsPlatformAdmin` resolution, revalidate current grants per request, deny revoked grants immediately even for existing valid JWTs, and coordinate global last-admin invariants across concurrent mutations.
- **4.3.4 — Platform Identity Security Regression:** Test forged-admin rejection, ordinary-user denial, Tenant Owner vs Platform Admin separation, inactive account denial, revoked grant denial, bootstrap security, and concurrent grant mutation races.

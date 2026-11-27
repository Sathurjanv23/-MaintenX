# MaintenX — FEAT-004 Step 4.1 Domain Security Verification & Step 4.2 Persistence Handover

**Feature:** FEAT-004 — Role-Based Access Control (RBAC) & Platform Administration  
**Task:** 4.1.4 — Domain Security Verification (Step 4.1 Gate)  
**Base Commit:** `2dc123d5054723df84b1140f2f981fd3844b42b7` (PR #43 merged on `main`)  
**Feature Branch:** `test/004-01-04-rbac-domain-security`  
**Owner:** Sathu (`sathurjanv.23@uom.lk`) | **Reviewer:** Janu (`januka-karunakaran`)  

---

## 1. Executive Summary & Step 4.1 Acceptance Decision

**Step 4.1 Domain Acceptance Decision:** **PASS (Domain Foundation Complete)** — all authorization primitives, 14-permission catalog, immutable role mappings, platform grant lifecycle, and privilege assignment invariants are verified. Runtime grant resolution, EF Core persistence, and HTTP endpoints remain deferred to Steps `4.2`–`4.8`.

---

## 2. Tasks 4.1.1 – 4.1.4 Verification Matrix

| Area | Classification | Source Reference | Test Evidence |
|---|---|---|---|
| **Authorization Primitives** (`4.1.1`) | **PASS** | `AuthorizationScopeKind.cs`, `AuthorizationScope.cs`, `PermissionKey.cs` | `AuthorizationDomainPrimitivesTests` (33 cases) |
| **Permission Catalog (14 keys)** (`4.1.2`) | **PASS** | `PermissionDefinition.cs`, `PermissionCatalog.cs` | `PermissionCatalogAndRoleMapTests` (14 catalog tests) |
| **Role-Permission Matrix** (`4.1.2`) | **PASS** | `TenantRolePermissionMap.cs`, `PlatformRolePermissionMap.cs` | `ExhaustiveRolePermissionMatrix_MatchesExactSpecification` + `ExhaustivePlatformRolePermissionMatrix_MatchesExactSpecification` (56 cases: 4 roles x 14 permissions) |
| **Platform Grant Lifecycle** (`4.1.3`) | **PASS** | `PlatformRole.cs`, `PlatformRoleGrantStatus.cs`, `PlatformRoleGrant.cs` | `PrivilegeInvariantsTests` (grant/revoke/idempotency/timestamps) |
| **Tenant Privilege Hierarchy** (`4.1.3`) | **PASS** | `TenantPrivilegeRules.cs`, `PrivilegeCheckResult.cs` | `PrivilegeInvariantsTests` & `RbacDomainSecurityRegressionTests` |
| **Last-Owner & Last-Admin Rules** (`4.1.3/4.1.4`) | **PASS** | `TenantPrivilegeRules.CountRemainingActiveOwnersExcluding`, `PlatformPrivilegeRules` | `DuplicateOwnerRecordsForTargetUser_CannotSatisfyLastActiveOwnerInvariant` |
| **Trusted Authority & Runtime** | **DEFERRED** (`4.3`–`4.8`) | `TenantActorResolver.cs` (`IsPlatformAdmin = false`) | Verified unchanged; no production user has platform privileges |

---

## 3. Confirmed Domain Security Finding & Correction (Task 4.1.4)

- **Finding:** `TenantPrivilegeRules.CountRemainingActiveOwnersExcluding` previously filtered by `m.Id != excludedMembershipId`. If an input collection contained a second/duplicate `TenantMembership` record for the *same* `target.UserId` with a different `Id`, that duplicate record could falsely satisfy the remaining active `Owner` count.
- **Correction:** Updated `TenantPrivilegeRules.CountRemainingActiveOwnersExcluding` (and callers `CanAssignRole`, `CanSuspendMembership`, `CanRevokeMembership`) to exclude by `target.UserId` (`m.UserId != excludedUserId && m.UserId != Guid.Empty`), matching `PlatformPrivilegeRules.CountRemainingActiveAdminsExcluding`.
- **Regression Test:** `DuplicateOwnerRecordsForTargetUser_CannotSatisfyLastActiveOwnerInvariant`.

---

## 4. Trusted Authority, Persistence & Concurrency Limitations

1. **Domain != Runtime Authority**: Constructing `PlatformRoleGrant` or `PermissionKey` in memory does **not** authenticate a caller. `TenantActorResolver` continues to set `IsPlatformAdmin = false` until Step `4.3` implements server-side DB grant verification.
2. **Account Eligibility**: An `Active` `PlatformRoleGrant` or `TenantMembership` does not by itself prove the user's `User` account (`UserStatus.Active`, `SecurityStamp`, active `UserSession`) is eligible to authenticate; Step `4.3`/`4.4` must verify account and session state on every privileged call.
3. **Multi-Record Concurrency**: Entity-level `Version` tokens on `TenantMembership` and `PlatformRoleGrant` do **not** prevent concurrent transactions from removing two different Owners/Admins simultaneously. Steps `4.2`–`4.7` must coordinate last-owner/last-admin mutations via tenant-wide/global locking (`SELECT ... FOR UPDATE` or serializable transactions with retry).

---

## 5. Step 4.2 Persistence Handover (`PlatformRoleGrant`)

1. **Table**: `platform.platform_role_grants` (no `tenant_id` column; does **not** implement `ITenantEntity`).
2. **Columns**:
   - `id` (`uuid`, PK `pk_platform_role_grants`, `ValueGeneratedNever`)
   - `user_id` (`uuid`, FK -> `platform.users(id)` with `OnDelete(DeleteBehavior.Restrict)` or `Cascade` per audit retention policy; indexed)
   - `role` (`varchar(50)`, `HasConversion<string>()`, check constraint `role IN ('PlatformAdministrator')`)
   - `status` (`varchar(50)`, `HasConversion<string>()`, check constraint `status IN ('Active', 'Revoked')`)
   - `granted_at_utc` (`timestamptz`, NOT NULL)
   - `granted_by_user_id` (`uuid`, NOT NULL)
   - `revoked_at_utc` (`timestamptz`, nullable)
   - `revoked_by_user_id` (`uuid`, nullable)
   - `revocation_reason` (`varchar(500)`, nullable)
   - `version` (`bigint`, `IsConcurrencyToken()`, NOT NULL)
3. **Uniqueness & Retention**:
   - Partial unique index `ix_platform_role_grants_user_id_role_active` on `(user_id, role) WHERE status = 'Active'` — enforces at most one active grant per `(UserId, Role)` while preserving historical `Revoked` grants.
   - Check constraint `revoked_at_utc IS NULL OR revoked_at_utc >= granted_at_utc`.
4. **No Redundant Catalog Tables**: `PermissionCatalog`, `TenantRolePermissionMap`, and `PlatformRolePermissionMap` are static, immutable code-defined catalogs; no dynamic permission/role-mapping tables are required in Step `4.2`.

# MaintenX — FEAT-004 Task 4.3.2 Secure Platform Administrator Provisioning

**Feature:** FEAT-004 — Role-Based Access Control (RBAC) & Platform Administration  
**Task:** 4.3.2 — Secure Platform Administrator Provisioning  
**Base Commit:** `e73bde0a9491e5a166263d4019d73f2745ba2518` (PR #49 merged on `main`)  
**Feature Branch:** `feat/004-03-02-admin-provisioning`  
**Owner:** Sathu (`sathurjanv.23@uom.lk`) | **Reviewer:** Janu (`januka-karunakaran`)

---

## 1. Implementation Status Summary

| Capability | Status | Scope Boundary |
|---|---|---|
| **Initial Platform Administrator Bootstrap Capability** | **IMPLEMENTED** | Restricted one-shot CLI + globally locked atomic service |
| **Real Administrator Provisioned** | **NO** | Zero administrators seeded or provisioned in dev, test, or CI |
| **Trusted Production HTTP Actor Integration** | **NOT IMPLEMENTED** | `TenantActorResolver` continues to set `IsPlatformAdmin = false` (`Task 4.3.3`) |
| **Public Platform Administration / Lifecycle APIs** | **NOT IMPLEMENTED** | Deferred to Steps `4.4`–`4.8` |

---

## 2. Operational Trust Boundary & Entry Point

- **Restricted Operational Command:** `PlatformAdminBootstrapCommand` invoked via `Program.cs` when `--bootstrap-platform-admin` is supplied. When invoked in this mode, `Program.cs` executes the one-shot bootstrap command and exits **without** starting Kestrel/the public HTTP server.
- **Operator Authorization Boundary (`HostBootstrapOperatorAuthorizationProvider`):**
  - Requires explicit operational opt-in (`MaintenX:Bootstrap:AllowExecution == "true"`, e.g. `MAINTENX_BOOTSTRAP_ALLOW` / `MaintenX__Bootstrap__AllowExecution=true` set only in a restricted deployment/operator shell).
  - Derives operator identity from the OS/host process (`os:<Environment.UserName>@<Environment.MachineName>`), never from a caller-supplied `--authorized=true` flag or user-ID environment variable.
  - **Deployment Prerequisite:** Production security requires restricting OS/container execution privileges for `MaintenX:Bootstrap:AllowExecution=true` to authorized deployment operators only.
- **Safe Placeholder Example (Do Not Run Against Production With Test Data):**
  ```bash
  MaintenX__Bootstrap__AllowExecution=true \
    dotnet MaintenX.Api.dll --bootstrap-platform-admin \
    --target-email "<existing-eligible-user-email>" \
    --reason "Initial production platform administrator bootstrap"
  ```
  *(No passwords, JWTs, or secrets are accepted on the command line.)*

---

## 3. Target User Eligibility, Actor Attribution & First-Bootstrap Rules

- **Target User Eligibility:** Target user must already exist (resolved by `TargetUserId` or normalized `Email`), have `UserStatus.Active`, and have a valid 3–500 char reason. Never creates users, generates passwords, or issues tokens.
- **Genuine Actor Attribution (`GrantActorKind`):**
  - `GrantActorKind.User`: `GrantedByUserId` (non-empty `Guid`), `GrantedByOperatorId = null`.
  - `GrantActorKind.DeploymentOperator`: `GrantedByUserId = null`, `GrantedByOperatorId` (`os:<user>@<machine>`, 3–200 chars).
  - Enforced by `ck_platform_role_grants_granted_by_actor_kind` and `ck_platform_role_grants_granted_actor_consistency`.
- **First-Bootstrap & Idempotency Rules:**
  - Succeeds (`Created`) only when `0` active and `0` historical `PlatformAdministrator` grants exist.
  - Repeated call for the **same** active user returns `AlreadyProvisionedForSameUser` (idempotent, no duplicate grant or audit, `Version` unchanged).
  - Call for a **different** user after initialization returns `BootstrapUnavailable`.
  - Previously initialized platform where all grants were `Revoked` returns `BootstrapUnavailable` (disaster recovery requires a separate approved procedure).

---

## 4. Global Concurrency, Atomic Persistence & Durable Audit

- **Global Coordination:** Inside `CreateExecutionStrategy().ExecuteAsync(...)`, `PlatformAdminBootstrapService` begins a database transaction and acquires PostgreSQL transaction-scoped advisory lock `pg_advisory_xact_lock(748291034)` before revalidating target eligibility and grant history. This serializes concurrent same-target and different-target bootstrap attempts.
- **Atomic Grant + Audit:** `PlatformRoleGrant.CreateForBootstrap(...)` and `SecurityAuditEvent.Create(SecurityAuditEventType.PlatformAdministratorBootstrapped, ...)` are saved in the same `SaveChangesAsync()` and committed atomically. The audit event correlates directly to the grant ID via `SecurityAuditMetadata.ForBootstrap(grant.Id)` (`Metadata.DetectedLineage = "grant_<grant.Id:N>"`). If audit persistence fails, the entire transaction rolls back and `ChangeTracker.Clear()` prevents stale tracked state.
- **Migration & Downgrade Safety:** `AddPlatformAdminBootstrapAttribution` (updates `platform.platform_role_grants` actor attribution columns/constraints and `ck_security_audit_events_event_type` to allow `'PlatformAdministratorBootstrapped'`). Downgrading (`Down()`) fails closed if deployment operator grants exist without null-attribution backfill. See `docs/project/FEAT-004-SEC-002-BOOTSTRAP-HARDENING.md` for full security hardening details.

---

## 5. Remaining Limitations & Task 4.3.3 Handover

- **Remaining Limitations:** `TD-01` through `TD-08` and `TD-12` remain open; `TD-09`–`TD-11` remain resolved. `TenantActorResolver.IsPlatformAdmin` remains `false`.
- **Task 4.3.3 Handover:** Integrate `IPlatformGrantResolver` into trusted HTTP actor flows, remove caller-controlled `IsPlatformAdmin` shortcuts, enforce permission-specific revalidation on every request (rejecting existing JWTs after grant revocation), and implement coordinated global last-admin protection inside privileged grant-mutation transactions.

# FEAT-004-SEC-002 — Platform Administrator Bootstrap Security Hardening

## Overview
This document specifies the security remediation and hardening implemented following the merge of Task 4.3.2 (PR #50). It addresses audit event entity correlation, strict metadata immutability invariants, first-bootstrap idempotency refinement, and migration downgrade safety.

## Remediation Details

### 1. Direct Audit Correlation & Structured Metadata
- **Audit Lineage Binding**: `SecurityAuditMetadata.ForBootstrap(Guid grantId, string? actionTaken = Actions.PlatformAdministratorGranted)` creates an immutable metadata instance linking the exact primary key of the provisioned grant via the lineage identifier format `grant_<guid_hex>`.
- **Regex & Allowlist Protection**:
  - `LineageIdentifierRegex` was updated to accept `^grant_[a-fA-F0-9]{32}$` alongside existing lineage formats (`lineage_*`, `generation_*`, etc.).
  - Added allowlisted audit Reason `platform_administrator_bootstrap` (`SecurityAuditMetadata.Reasons.PlatformAdministratorBootstrap`).
  - Added allowlisted audit Action `platform_administrator_granted` (`SecurityAuditMetadata.Actions.PlatformAdministratorGranted`).
  - Arbitrary user-controlled text, passwords, tokens, or untrusted payload injections remain strictly rejected by domain validation and JSON serialization safeguards.
- **Correlation Integrity**:
  - `SecurityAuditEvent` records:
    - `EventType = SecurityAuditEventType.PlatformAdministratorBootstrapped`
    - `UserId = targetUser.Id`
    - `Metadata.Reason = "platform_administrator_bootstrap"`
    - `Metadata.DetectedLineage = "grant_<grant.Id:N>"`
    - `Metadata.ActionTaken = "platform_administrator_granted"`
    - `CreatedAtUtc = grant.GrantedAtUtc`
  - Atomicity is enforced in `PlatformAdminBootstrapService`: the grant and the security audit event are committed inside the same PostgreSQL transaction (`NpgsqlTransaction`). If either fails, the transaction rolls back completely with zero orphaned records.

### 2. Idempotency & Initialization State Hardening
- **Distinguishing Bootstrap from Post-Bootstrap Grants**:
  - `PlatformAdminBootstrapService` now explicitly checks `GrantedByActorKind == GrantActorKind.DeploymentOperator` when evaluating active administrator grants.
  - If an active grant exists for the target user that was provisioned by a `DeploymentOperator`, the service returns `AlreadyProvisionedForSameUser` (idempotent no-op, 0 new grants, 0 new audits).
  - If any active grant exists for a different user, or was issued by a `User` actor (e.g. via post-bootstrap administrative grant flows), initial bootstrap is rejected with `BootstrapUnavailable`.
  - Historical revoked grants (`Status == Revoked`) continue to trigger `BootstrapUnavailable` to prevent re-bootstrap of previously initialized platforms.

### 3. Migration Downgrade & Fail-Closed Behavior
- **Down Migration Safety**:
  - Migration `20261127120839_AddPlatformAdminBootstrapAttribution` alters `granted_by_user_id` to `NOT NULL` on `Down()`.
  - When deployment operator bootstrap records exist (`granted_by_actor_kind == 'DeploymentOperator'`, `granted_by_user_id IS NULL`), running `Down()` fails closed with a PostgreSQL null-value violation.
  - This behavior is intentional: downgrading past bootstrap attribution without data archiving is unsupported and fails safely without corrupting or fabricating historical user IDs.
  - Verified by integration test `MigrationDowngrade_WithDeploymentOperatorGrant_FailsClosedTransactionally`.

### 4. Operational Environment Authorization
- **Layered Defense**:
  - Server-side opt-in flag: `MaintenX:Bootstrap:AllowExecution == "true"` (denied by default).
  - Process identity attribution: derived securely from host execution environment (`os:<user>@<machine>`).
  - Restricted entry point: CLI-only command flag `--bootstrap-platform-admin` which terminates without starting the HTTP listener.
  - Runtime isolation: `TenantActorResolver.IsPlatformAdmin` remains strictly `false` in standard tenant actor resolution; tenant HTTP routes remain unaffected.

## Test Verification Summary
- **Unit Tests**: 734 passed (0 failed, 0 skipped).
  - Validates `SecurityAuditMetadata.ForBootstrap` correlation, regex enforcement, allowlist boundaries, and argument validation.
- **Integration Tests**: 360 passed (0 failed, 0 skipped).
  - Validates full PostgreSQL 16 schema integrity, concurrent same-target and different-target bootstrap, transactional rollback on audit failure, CLI command execution, and migration downgrade fail-closed behavior.
- **Total Backend Tests**: 1094 passed (0 failed, 0 skipped).

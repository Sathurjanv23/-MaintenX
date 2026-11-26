# MaintenX — FEAT-004 Permission Catalog & Role Mapping Matrix

**Feature:** FEAT-004 — Role-Based Access Control (RBAC) & Platform Administration  
**Task:** 4.1.2 — Permission Catalog & Role Mappings  
**Source of Truth:** `services/api/Domain/Authorization/PermissionCatalog.cs`, `TenantRolePermissionMap.cs`  

> [!IMPORTANT]
> Defining a permission in `PermissionCatalog` or mapping it in `TenantRolePermissionMap` establishes **domain capability eligibility only**. It does **not** grant runtime authority, provision platform administrators, or expose HTTP endpoints. Runtime policy evaluation and workflows are implemented in subsequent FEAT-004 tasks.

---

## 1. Platform-Scoped Permissions (`AuthorizationScopeKind.Platform`)

Platform permissions are strictly separated from `TenantMembershipRole` (`Owner`, `Administrator`, `Member`). No tenant role ever receives platform permissions.

| Permission Identifier | Scope | Purpose | Tenant Roles | Implementation Status |
|---|---|---|---|---|
| `platform.tenants.read` | `Platform` | View platform-wide tenant catalog and pending onboarding reviews | None | Defined in catalog; runtime & HTTP pending (Steps 4.5, 4.8) |
| `platform.tenants.activate` | `Platform` | Approve `PendingOnboarding` tenants and reactivate `Suspended` tenants (`TenantService.ActivateTenantAsync`) | None | Defined in catalog; HTTP route blocked pending Step 4.8 |
| `platform.tenants.suspend` | `Platform` | Temporarily suspend an `Active` tenant (`TenantService.SuspendTenantAsync`) | None | Defined in catalog; HTTP route blocked pending Step 4.8 |
| `platform.tenants.deactivate` | `Platform` | Permanently deactivate a tenant (`TenantService.DeactivateTenantAsync`) | None | Defined in catalog; HTTP route blocked pending Step 4.8 |

*Design Note: `platform.tenants.activate` is the single canonical permission for both initial onboarding approval (`PendingOnboarding -> Active`) and reactivation (`Suspended -> Active`), avoiding a redundant `platform.tenants.approve` permission.*

---

## 2. Tenant-Scoped Permissions (`AuthorizationScopeKind.Tenant`)

| Permission Identifier | Scope | Purpose | Owner | Administrator | Member | Deferred Resource Restrictions / Status |
|---|---|---|---|---|---|---|
| `tenant.metadata.read` | `Tenant` | Read tenant organization metadata and active context | Yes | Yes | Yes | Enforced at runtime (`GET /api/v1/tenants/{id}`, `/api/v1/tenancy/current`) |
| `tenant.settings.update` | `Tenant` | Update permitted tenant organization settings | Yes | Yes | No | Enforced at runtime (`PATCH /api/v1/tenants/{id}`, requires Active tenant & `ExpectedVersion`) |
| `tenant.members.read` | `Tenant` | List and inspect memberships within the target tenant | Yes | Yes | No | Defined in catalog; HTTP endpoint pending (Step 4.8) |
| `tenant.members.invite` | `Tenant` | Create and issue membership invitations | Yes | Yes | No | Defined in catalog; invitation workflow pending (Step 4.6) |
| `tenant.members.roles.assign` | `Tenant` | Assign or change organizational roles | Yes | No | No | Defined in catalog; Step 4.7 must enforce hierarchy, self-escalation & last-owner guards |
| `tenant.members.suspend` | `Tenant` | Suspend an active membership | Yes | Yes | No | Defined in catalog; Step 4.6/4.7 must prevent Admins from suspending Owners or last Owner |
| `tenant.members.restore` | `Tenant` | Restore a suspended membership to active status | Yes | Yes | No | Defined in catalog; membership workflow pending (Step 4.6) |
| `tenant.members.revoke` | `Tenant` | Permanently revoke a membership | Yes | Yes | No | Defined in catalog; Step 4.6/4.7 must enforce last-owner protection & Owner protection |
| `tenant.ownership.transfer` | `Tenant` | Transfer primary organization ownership | Yes | No | No | Defined in catalog; atomic transfer workflow pending (Step 4.7) |
| `tenant.audit.read` | `Tenant` | View tenant-scoped audit events (`TD-04`) | Yes | Yes | No | Defined in catalog; authorized audit endpoint deferred |

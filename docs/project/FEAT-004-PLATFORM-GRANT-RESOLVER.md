# MaintenX — FEAT-004 Task 4.3.1 Authoritative Platform Grant Resolver

**Feature:** FEAT-004 — Role-Based Access Control (RBAC) & Platform Administration  
**Task:** 4.3.1 — Authoritative Platform Grant Resolver  
**Base Commit:** `f49888fef2728624c30497346fb410fd4e3c9702` (PR #47 merged on `main`)  
**Feature Branch:** `feat/004-03-01-platform-grant-resolver`  
**Owner:** Sathu (`sathurjanv.23@uom.lk`) | **Reviewer:** Janu (`januka-karunakaran`)

---

## 1. Implementation Status Summary

| Capability | Status | Scope Boundary |
|---|---|---|
| **Authoritative Platform Grant Resolver (`IPlatformGrantResolver`)** | **IMPLEMENTED** | Evaluates authenticated principal, account eligibility, session validity, security stamp, active grant, and registered platform permission |
| **Administrator Provisioning** | **NOT IMPLEMENTED** | Deferred to Task `4.3.2` |
| **Production HTTP Actor Integration (`TenantActorResolver`)** | **NOT IMPLEMENTED** | `TenantActorResolver` continues to set `IsPlatformAdmin = false` (`Task 4.3.3`) |
| **Public Platform APIs / Tenant Lifecycle Endpoints** | **NOT IMPLEMENTED** | Deferred to Steps `4.4`–`4.8` |

---

## 2. Application Contract & Trusted Authentication Boundary

- **Contract:** `MaintenX.Api.Application.Authorization.Services.IPlatformGrantResolver`
  - `Task<PlatformGrantResolutionResult> ResolveAsync(ClaimsPrincipal? principal, PermissionKey? permission, CancellationToken cancellationToken = default)`
- **Result:** `PlatformGrantResolutionResult` (`IsAllowed`, `UserId`, `GrantId`, `Role`, `Permission`, `DenialReason`) with `private` constructor and `internal static` `Allow(...)` / `Deny(...)` factories so external callers cannot manufacture trusted authorization evidence.
- **Trusted Authentication Boundary:** `PlatformGrantResolver` requires `principal?.Identity is ClaimsIdentity identity && identity.IsAuthenticated && !string.IsNullOrWhiteSpace(identity.AuthenticationType)` and extracts non-ambiguous `sub` (or `NameIdentifier`), `sid`, and `sst` claims. It never trusts request headers, query/body fields, client-supplied role claims, or caller-supplied `PlatformRoleGrant` / `IsPlatformAdmin` values. In-process callers must only pass `ClaimsPrincipal` instances produced by ASP.NET Core's configured JWT bearer authentication middleware.

---

## 3. Authoritative Verification Pipeline (Non-Caching, Fail-Closed)

1. **Permission Validation:** Rejects `null`, unregistered, or non-`Platform` permissions using `PermissionCatalog.IsRegistered` and `AuthorizationScopeKind.Platform` (exact match only; no wildcards).
2. **Identity & Claim Ambiguity:** Rejects unauthenticated principals, missing authentication type, missing/empty/malformed `sub` or `sid`, missing/whitespace `sst`, and duplicate claims of the same type or conflicting values.
3. **Current Account Eligibility:** Queries `MaintenXDbContext.Users.AsNoTracking()` directly (bypassing the 60s `IMemoryCache` in `SecurityStampValidator` so account suspension, deactivation, or security stamp rotation takes effect immediately). Rejects nonexistent users, `Status != UserStatus.Active`, and constant-time (`CryptographicOperations.FixedTimeEquals`) `SecurityStamp` mismatches.
4. **Current Session Validity:** Queries `MaintenXDbContext.UserSessions.AsNoTracking()` directly using `TimeProvider.GetUtcNow().UtcDateTime`. Rejects missing, wrong-user (`session.UserId != userId`), revoked (`RevokedAtUtc is not null`), or expired (`ExpiresAtUtc <= utcNow`) sessions without extending session lifetime.
5. **Authoritative Grant Lookup:** Queries `MaintenXDbContext.PlatformRoleGrants.AsNoTracking()` (`UserId == userId && Status == PlatformRoleGrantStatus.Active`). Takes up to 2 rows: denies if `0` (`NoActivePlatformGrant`) and fails closed if `> 1` (`AmbiguousActivePlatformGrants`). Evaluates `PlatformRolePermissionMap.CanAuthorize(grant, permission)`.
6. **Global Scope Independence:** `PlatformRoleGrant` has no `TenantId` and no tenant query filter; decisions are identical without tenant context, under Tenant A, and under Tenant B. Tenant roles (`Owner`, `Administrator`, `Member`) never confer platform permissions.
7. **Failure & Cancellation Handling:** `OperationCanceledException` always propagates. Non-cancellation database/infrastructure exceptions are logged without exposing tokens or security stamps and return `PlatformGrantResolutionResult.Deny("InfrastructureFailure")`.

---

## 4. Dependency Injection & Lifetime

- Registered via `AuthorizationServiceExtensions.AddMaintenXAuthorization()` in `Program.cs` as `services.AddScoped<IPlatformGrantResolver, PlatformGrantResolver>()`, matching `MaintenXDbContext` (scoped) and `TimeProvider` (singleton).

---

## 5. Remaining Limitations & Check-to-Use Boundary

- **Check-to-Use Race:** A fresh `AsNoTracking()` read eliminates positive authorization caching, but does not by itself eliminate check-to-use races across concurrent grant revocations. Future privileged mutation handlers (Steps `4.3.3`+) must revalidate authority inside their coordinated transaction boundary.
- **Existing HTTP Boundary Preserved:** `TenantActorResolver` continues to set `IsPlatformAdmin: false` (`TD-01` remains open until Task `4.3.3`).

---

## 6. Task 4.3.2 Handover — Secure Platform Administrator Provisioning

- **`GrantedByUserId` Bootstrap Attribution Analysis:** `PlatformRoleGrant.Create` and `ck_platform_role_grants_granted_by_non_empty` currently require a non-empty `Guid` for `GrantedByUserId`. For genuine operator-driven first-administrator bootstrap (when no existing `PlatformAdministrator` user exists yet), Task `4.3.2` must **not** fabricate a synthetic user account, invent a random human UUID, or set `GrantedByUserId = targetUser.Id` to imitate self-promotion. Instead, Task `4.3.2` should evaluate introducing either an explicit nullable `GrantedByUserId` for operator-authorized bootstrap (with a `BootstrapOperatorReference` / `GrantedByKind` audit field and updated check constraint) or a dedicated, explicitly audited bootstrap attribution convention approved before implementation.
- **Required Controls for Task 4.3.2:** Explicit operator authorization, eligible existing `Active` user verification, idempotency, concurrent bootstrap protection, durable audit evidence, zero hardcoded credentials, zero public self-promotion, and zero automatic default administrator grants.

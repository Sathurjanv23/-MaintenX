# MaintenX — FEAT-004-SEC-001 Authentication Provenance Remediation

**Feature:** FEAT-004 — Role-Based Access Control (RBAC) & Platform Administration  
**Remediation:** `4.3.1-SEC-001` — Platform Grant Authentication Provenance Remediation  
**Base Commit:** `352264c6cff3bb70a7df8bc6bec60be05ae24a1b` (PR #48 merged on `main`)  
**Remediation Branch:** `fix/004-03-01-platform-grant-provenance`  
**Owner:** Sathu (`sathurjanv.23@uom.lk`) | **Reviewer:** Janu (`januka-karunakaran`)

---

## 1. Confirmed Security Finding & Classification

- **Classification:** **In-Process Authentication Contract Weakness** (not an externally exploitable HTTP vulnerability, because `IPlatformGrantResolver` is not yet wired into any production HTTP endpoint).
- **Root Cause:** The original Task `4.3.1` signature `ResolveAsync(ClaimsPrincipal? principal, PermissionKey? permission, CancellationToken)` only checked `ClaimsIdentity.IsAuthenticated` and `!string.IsNullOrWhiteSpace(AuthenticationType)`, allowing an in-process caller to construct an arbitrary `ClaimsPrincipal` with synthetic claims and obtain an `Allowed` decision without passing ASP.NET Core's `JwtBearerHandler`.

---

## 2. Contract & Provenance Remediation

- **Previous Contract:** `ResolveAsync(ClaimsPrincipal? principal, PermissionKey? permission, CancellationToken)`
- **Corrected Contract:** `ResolveAsync(PermissionKey? permission, CancellationToken)` — no `ClaimsPrincipal` parameter and no compatibility overload.
- **Trusted Authentication Provenance Source:**
  - `IHttpContextAccessor.HttpContext` (server-controlled request scope; missing `HttpContext` fails closed with `MissingHttpContext`).
  - `IAuthenticationService.AuthenticateAsync(httpContext, JwtBearerDefaults.AuthenticationScheme)` — requires `Succeeded == true`, `Ticket != null`, `Ticket.AuthenticationScheme == "Bearer"`, `Principal != null`, and **exactly one** authenticated `ClaimsIdentity` (`AmbiguousAuthenticatedIdentities` otherwise).
  - Never uses `HttpContext.User` alone, never falls back to other schemes, and never combines claims across multiple identities.
- **In-Process Trust Assumptions:** Enforcing `IHttpContextAccessor` + `IAuthenticationService.AuthenticateAsync(..., "Bearer")` prevents accidental or caller-supplied `ClaimsPrincipal` spoofing at the application service boundary. It does not claim protection against arbitrary malicious code already executing inside the trusted server process.

---

## 3. Real JWT Pipeline & Freshness Verification

- Exercised real ASP.NET Core `JwtBearerHandler` (`ValidIssuer`, `ValidAudience`, `ClockSkew = TimeSpan.Zero`, HMAC-SHA256 signing key validation) via an isolated test-only endpoint (`/__test/platform-resolve`) in `PlatformGrantResolverIntegrationTests`:
  - **Valid signed JWT** from `/api/v1/auth/login` -> `200 OK` (`Allowed`).
  - **Invalid signature, unsigned (`alg: none`), expired JWT, wrong issuer, wrong audience, missing token, malformed token, untrusted scheme + `X-Platform-Admin: true`** -> `403 Forbidden` (`UnauthenticatedBearerContext`).
  - **Same valid signed JWT freshness:** Immediately denied upon grant revocation (`NoActivePlatformGrant`), account suspension (`IneligibleAccountOrSecurityStampMismatch`), security stamp rotation (`IneligibleAccountOrSecurityStampMismatch`), and session revocation (`InvalidOrExpiredSession`).

---

## 4. Preserved Boundaries & Remaining Limitations

- `TenantActorResolver` continues to set `IsPlatformAdmin = false` (`TD-01` remains open until Task `4.3.3`).
- Check-to-use concurrency races across concurrent grant revocations remain deferred to Step `4.3.3`+ transaction coordination.
- **Task 4.3.2 Handover:** Secure first-administrator provisioning (operator authorization, `GrantedByUserId` bootstrap attribution design, idempotency, concurrency protection, audit trail) remains the next task after this remediation merges.

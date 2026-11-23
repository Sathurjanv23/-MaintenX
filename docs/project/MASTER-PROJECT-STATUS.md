# MaintenX — Master Project Status & Architectural Audit

**Document ID:** MASTER-PROJECT-STATUS
**Audit Reference:** PROJECT-AUDIT-001
**Audit Date:** 2026-11-23
**Auditor Roles:** Senior .NET Software Architect, Security Engineer, QA Lead, DevOps Engineer, Technical Project Manager
**Repository:** `Sathurjanv23/-MaintenX`
**Base Commit:** `b88748ed07c7f7bc19a1cf6ffae1c238b77626ad` (via merged PR #22 on `main`)
**Audit Branch:** `docs/003-master-project-audit`

---

## 1. Executive Summary & Purpose

MaintenX is an enterprise-grade cloud-native multi-tenant facility maintenance Software-as-a-Service (SaaS) platform engineered for commercial real estate operators, university campuses, hospital networks, facility managers, and mobile field technicians. The platform automates reactive maintenance ticketing, preventative maintenance scheduling, equipment asset tracking, and real-time technician dispatching.

The system is constructed as a **Modular Monolith** using ASP.NET Core on .NET 10 LTS, PostgreSQL 16 Alpine, Next.js 14+ (App Router), and Flutter 3.29.0.

### Current High-Level Milestone Position
- **Milestone 0 (Monorepo Bootstrap & Toolchain)**: **100% COMPLETE** (FEAT-000, TECH-001).
- **Milestone 1A (Database Foundation)**: **100% COMPLETE** (FEAT-001).
- **Milestone 1B (Authentication & Session Backend)**: **100% COMPLETE** (FEAT-002 Tasks T1 through T8).
- **Milestone 1C (Multi-Tenancy & RBAC)**: **NOT STARTED** (Planned as FEAT-003 and FEAT-004).
- **Milestone 1D (Frontend & Mobile Authentication UI)**: **NOT STARTED** (Bootstrap shells only; planned as FEAT-005 and mobile auth).
- **Milestones 2–5 (Facilities, Assets, Work Orders, Maintenance Schedules, Notifications)**: **NOT STARTED** (Architecture planned).

---

## 2. Technology Stack & Runtime Verification Matrix

| Subsystem | Core Technology | Version / Pinned State | Realized Implementation | Local & CI Verification Status |
| :--- | :--- | :--- | :--- | :--- |
| **API Backend** | ASP.NET Core (.NET 10 LTS) | `net10.0` (pinned in `global.json` to `10.0.100`) | Minimal APIs via `IModule`, Clean Architecture layers, RFC 7807 problem details, health endpoints | **PASSED in CI** (Build + 349 Unit Tests + 156 Integration Tests) |
| **Database & ORM** | PostgreSQL 16 Alpine / EF Core 10 | PostgreSQL 16 Alpine, EF Core `10.0.0`, Npgsql `10.0.0` | `platform` schema, UUID PKs, snake_case, `SELECT ... FOR UPDATE` locking, EF migrations | **PASSED in CI** (Isolated disposable DBs `maintenx_test_*` validated) |
| **Background Worker** | .NET 10 Worker Service | `net10.0` | Skeleton hosted background service (`MaintenX.Worker`) with 30s heartbeat pulse | **PASSED in CI** (Compiled Release cleanly with 0 errors) |
| **Web Frontend** | Next.js (React 18, TypeScript) | Next.js `14.2.35`, TypeScript `5.5.4`, Tailwind `3.4.14` | Client-rendered status dashboard connecting to `/health/live`, `/health/ready`, `/api/v1/info` | **PASSED** (`pnpm lint` and `pnpm build` verified locally & in CI) |
| **Mobile App** | Flutter / Dart | Flutter SDK `3.29.0` (Dart 3.x) | Material 3 startup screen, Android/iOS platform runners, loopback API configuration | **PASSED in CI** (`flutter analyze` + `flutter test` verified in CI) |
| **Containerization** | Docker Compose | Compose file v3.8+ specification | Single container: `maintenx-postgres` (PostgreSQL 16) with healthcheck and role initialization script | **PASSED** (`docker-compose config` verified locally & in CI) |
| **CI / CD Pipeline** | GitHub Actions | Pinned v4/v5 Actions (`checkout@v4`, `setup-dotnet@v4`, etc.) | 4 automated parallel workflows on push/PR (`ci.yml`) | **PASSED** (100% green across all merged PRs) |

---

## 3. GitHub History & Merged Development Traceability

Every stage of development has been delivered through strictly reviewed, atomic Pull Requests targeting `main`:

| PR # | Title / Scope | Branch | Merge Commit | Merge Date (UTC) | Verification Outcome |
| :---: | :--- | :--- | :--- | :---: | :--- |
| **#1** | `fix: harden MaintenX bootstrap verification` | `chore/000-bootstrap` | `0d2db09` | 2026-11-12 13:08 | Initial monorepo layout, Next.js dashboard, Flutter scaffold |
| **#2** | `fix: harden MaintenX bootstrap verification` | `chore/000-bootstrap` | `75db358` | 2026-11-12 13:10 | CI pipeline and script permission hardening |
| **#3** | `chore: align development toolchains` | `chore/001-toolchain-alignment` | `e2a4005` | 2026-11-12 13:39 | Pinned .NET 10.0.100, migrated package references |
| **#4** | `Chore/001 toolchain alignment` | `chore/001-toolchain-alignment` | `dcbef28` | 2026-11-12 14:04 | Pinned Flutter 3.29.0, scaffolded Android/iOS platform directories |
| **#5** | `feat: implement PostgreSQL database foundation` | `feat/001-database-foundation` | `a3224b5` | 2026-11-13 02:06 | Configured `MaintenXDbContext`, `Tenant` root entity, migrations |
| **#6** | `fix: complete database foundation hardening` | `fix/001-database-hardening` | `4150531` | 2026-11-13 13:32 | Enforced test role separation and non-superuser execution |
| **#7** | `Fix/001 database hardening` | `fix/001-database-hardening` | `4159516` | 2026-11-14 03:40 | Hardened disposable database teardown guards |
| **#8** | `fix: finalize database test security hardening` | `fix/001-database-hardening` | `8e3a246` | 2026-11-14 03:53 | Finalized `TestDatabaseGuard` host allowlisting |
| **#9** | `fix: secure PostgreSQL initialization and harden database tests` | `fix/001-database-hardening` | `e7401c3` | 2026-11-14 04:23 | Sealed PostgreSQL initialization container scripts |
| **#10** | `Feat/002 auth security configuration` | `feat/002-auth-security-configuration` | `3780a8c` | 2026-11-14 05:44 | Configured `JwtOptions`, `JwtKeyRing`, rate limiting policies |
| **#11** | `Feat/002 auth security configuration` | `feat/002-auth-security-configuration` | `9b31ea6` | 2026-11-14 06:35 | Hardened `TrustedProxyOptions` with fail-fast production validator |
| **#12** | `feat(auth): implement authentication domain entities, lifecycle rules` | `feat/002-auth-domain-entities` | `fe16616` | 2026-11-14 08:48 | Auth domain aggregates: `User`, `UserSession`, `RefreshToken`, `SecurityAuditEvent` |
| **#13** | `fix(auth): correct domain invariants, rolling failure window` | `feat/002-auth-domain-remediation` | `88c68ff` | 2026-11-14 09:16 | 15-min rolling lockout window and security audit invariants |
| **#14** | `fix(auth): close T2 domain security review findings` | `feat/002-auth-domain-remediation` | `99446d1` | 2026-11-14 09:51 | Closed domain review findings, added exhaustive unit tests |
| **#15** | `feat(auth): add EF Core mappings and authentication migration` | `feat/002-auth-ef-configurations` | `b680194` | 2026-11-14 10:58 | Mapped auth entities to `platform` schema; migration `20261114000000` |
| **#16** | `feat(auth): implement authentication security services` | `feat/002-auth-security-services` | `e987fcb` | 2026-11-14 11:40 | `PasswordSecurityService`, `JwtTokenService`, `RefreshTokenService`, `SecurityStampValidator` |
| **#17** | `feat(auth): implement authentication application services` | `feat/002-auth-application-services` | `30dbc46` | 2026-11-14 12:52 | `AuthenticationService` with `SELECT ... FOR UPDATE` row locking & replay protection |
| **#18** | `feat(auth): expose authentication API endpoints` | `feat/002-auth-api-endpoints` | `921e16b` | 2026-11-17 03:50 | 5 Minimal API endpoints under `/api/v1/auth`, DTO redactions, generic 401 |
| **#19** | `test(auth): add end-to-end authentication lifecycle coverage` | `feat/002-auth-e2e-testing` | `b8479a0` | 2026-11-17 04:15 | Automated E2E lifecycle test suite (`AuthEndToEndLifecycleTests`) |
| **#20** | `docs(auth): formalize authentication architecture and ADR-0003` | `feat/002-auth-architecture-documentation` | `0df5641` | 2026-11-18 02:39 | Authored ADR-0003, updated system overview and roadmap |
| **#21** | `docs(auth): correct security architecture details` | `docs/002-auth-architecture-corrections` | `6ede242` | 2026-11-18 02:58 | Refined PBKDF2 HMAC-SHA256, CSRF nuance, audit immutability |
| **#22** | `docs(auth): refine password hashing, CSRF, and audit immutability` | `feat/002-auth-architecture-documentation` | `b88748e` | 2026-11-18 03:43 | Fast-forward synchronization of branch documentation into `main` |

---

## 4. Subsystem Audits

### 4.1 Backend Architecture (.NET 10 Web API)
- **Architecture Pattern**: Modular Monolith adhering to Clean Architecture principles.
- **Project Location**: `services/api/` (`MaintenX.Api.csproj`).
- **Target Framework**: .NET 10.0 (`net10.0`).
- **Module Boundary Architecture**:
  - `IModule` discovery pattern (`Common/Modules/IModule.cs`): modules register endpoints via `app.MapEndpoints()` at application startup without MVC controller overhead.
  - Currently active modules: `AuthModule` (`Application/Auth/AuthModule.cs`).
- **Dependency Injection & Middleware Pipeline** (`Program.cs`):
  1. `UseForwardedHeaders()` (front of pipeline for reverse proxy IP resolution).
  2. `UseExceptionHandler()` (RFC 7807 `GlobalExceptionHandler`).
  3. `UseRateLimiter()` (ASP.NET Core memory-bounded rate limiting).
  4. `UseAuthentication()` & `UseAuthorization()`.
  5. Route mapping: `/health/live`, `/health/ready`, `/api/v1/info`, `/api/v1/auth/*`.
- **Background Worker Subsystem**:
  - Location: `services/worker/` (`MaintenX.Worker.csproj`).
  - Current State: Compiles and runs a basic heartbeat log every 30 seconds. No domain job handlers, scheduled task executors, or message queues are currently implemented.

### 4.2 Database & Persistence Architecture (PostgreSQL 16 + EF Core 10)
- **Engine**: PostgreSQL 16 Alpine containerized via Docker.
- **Context**: `MaintenXDbContext` (`Infrastructure/Persistence/MaintenXDbContext.cs`).
- **Schema Segmentation**:
  - All existing tables reside strictly in the `platform` schema (`platform.tenants`, `platform.users`, `platform.user_sessions`, `platform.refresh_tokens`, `platform.security_audit_events`).
  - Zero tables in the default `public` schema.
- **Migrations Applied & Validated**:
  1. `20261113000000_InitialDatabaseFoundation`: `platform.tenants` root catalog table.
  2. `20261113000001_HardenTenantSlugConstraints`: Regex slug check constraint `ck_tenants_slug`.
  3. `20261114000000_AddAuthPersistenceEntities`: Added users, sessions, refresh tokens, and security audit tables.
- **Relational Integrity & Cascades**:
  - `platform.user_sessions` &rarr; `ON DELETE CASCADE` from `platform.users`.
  - `platform.refresh_tokens` &rarr; `ON DELETE CASCADE` from `platform.user_sessions`.
  - `platform.security_audit_events` &rarr; Omits foreign keys to guarantee append-only non-cascading audit durability.
- **Concurrency & Pessimistic Locking**:
  - Optimistic locking via `version (bigint)` column on mutable root entities (`Tenant`, `User`, `UserSession`).
  - Pessimistic row-level locking via `SELECT ... FOR UPDATE` in `AuthSessionUnitOfWork` wrapped in EF Core resilient execution strategies (`strategy.ExecuteAsync(...)`).

### 4.3 Web Frontend Architecture (Next.js 14+)
- **Location**: `apps/web/`.
- **Framework**: Next.js 14.2.35 (App Router), React 18.3.1, TypeScript 5.5.4, Tailwind CSS 3.4.14, Lucide React 0.453.0.
- **Current Realized Pages**:
  - `src/app/page.tsx`: Bootstrap status dashboard with real-time health connectivity cards (`/health/live`, `/health/ready`, `/api/v1/info`).
  - `src/app/layout.tsx`: Root HTML layout with font configuration and meta tags.
- **API Client**: `src/lib/api-client.ts` implementing lightweight fetch wrapper with `checkLiveHealth()`, `checkReadyHealth()`, `getApiInfo()`.
- **Missing Frontend Scope**:
  - Zero authentication UI (no login, register, password reset, or token refresh interceptor).
  - Zero state management (no Redux, Zustand, React Query, or Context for auth tokens).
  - Zero tenant management, facility, asset, or work order UI.
  - Zero automated test runner (no Jest, Vitest, or Playwright configured in `package.json`).

### 4.4 Mobile App Architecture (Flutter 3.x)
- **Location**: `apps/mobile/`.
- **Framework**: Flutter SDK 3.29.0, Dart 3.x, Material 3 design tokens.
- **Current Realized Screens**:
  - `lib/main.dart`: `MaintenXStartupScreen` rendering bootstrap status card and branding.
  - `lib/core/config/app_config.dart`: App configuration with `apiBaseUrl` (`http://10.0.2.2:5000` Android emulator loopback).
- **Test Suite**: `test/widget_test.dart` (1 test verifying startup screen rendering).
- **Missing Mobile Scope**:
  - Zero authentication screens or workflows.
  - Zero secure token storage (no `flutter_secure_storage`).
  - Zero HTTP client / API client interceptors.
  - Zero technician work order screens, offline databases (e.g. SQLite/Isar), photo capture, or QR scanning.

---

## 5. Security & Authentication Audit Findings

| Component / Mechanism | Approved Architecture (ADR-0003) | Realized Code Implementation | Audit Finding & Verification |
| :--- | :--- | :--- | :--- |
| **Password Hashing** | PBKDF2 HMAC-SHA256 (ASP.NET Core Identity V3), 100k iterations | `PasswordSecurityService` wrapping `PasswordHasher<User>` | **VERIFIED**: Transparent rehash out-of-lock, dummy verification for nonexistent users. |
| **Access Tokens (JWT)** | 15-minute lifetime, HS256, `IJwtKeyRing` dynamic signing | `JwtTokenService` generating claims (`sub`, `sid`, `security_stamp`) | **VERIFIED**: 15m expiration, key retirement with mandatory 24h verification retention. |
| **Refresh Tokens** | 7-day lifetime, 64-byte random, stored as SHA-256 hash | `RefreshTokenService` storing SHA-256 byte[32] in DB | **VERIFIED**: Raw tokens never persisted; transferred via JSON request/response body. |
| **Refresh Token Rotation & Replay** | Single-use rotation; immediate session family revocation on replay | `AuthenticationService.RefreshTokensAsync` with replay precedence | **VERIFIED**: Replay check precedes expiry check; revokes parent session & all sibling tokens. |
| **Concurrency Control** | Parameterized `SELECT ... FOR UPDATE` row locks | `AuthLockingExtensions.LockSessionForUpdateAsync` | **VERIFIED**: Wrapped in `strategy.ExecuteAsync()` within `READ COMMITTED` transactions. |
| **Account Lockout** | 5 failed attempts engaging 15-minute rolling lockout | `User.RecordFailedLogin` and `LockoutEndUtc` checking | **VERIFIED**: Returns generic 401 Unauthorized (`INVALID_CREDENTIALS`), never 423 Locked. |
| **Security Stamp Validation** | Scoped validator with 60s in-memory cache TTL | `SecurityStampValidator` querying `EfUserSecurityStampStore` | **VERIFIED**: Cache entry has strict 60s absolute expiration; local invalidation on mutations. |
| **API Rate Limiting** | Presentation sliding window (Register: 5/min, Login: 10/min, Refresh: 30/min) | `SecurityServiceExtensions.AddMaintenXSecurity` via `RateLimiter` | **VERIFIED**: Tracked IPs use sliding windows; untracked/overflow fallback to 1-permit fixed. |
| **Reverse Proxy Trust** | `ForwardedHeadersOptions` with strict production allowlist | `TrustedProxyOptionsValidator` checking `KnownProxies`/`KnownNetworks` | **VERIFIED**: Fails fast on production startup if allowlist is empty or IP/CIDR fails parsing. |
| **Security Audit Logging** | Append-only `platform.security_audit_events` with JSONB details | `SecurityAuditEvent` domain entity with structured metadata | **VERIFIED**: Client IP recorded for forensics; sensitive secrets (passwords, tokens) excluded. |
| **Admin Password Reset** | Logic implemented; HTTP endpoint deferred until RBAC | `AuthenticationService.AuthorizedResetPasswordAsync` | **VERIFIED**: Endpoint intentionally absent from `AuthModule` until FEAT-004 RBAC is active. |

---

## 6. Testing & CI Pipeline Audit

### Verified Test Execution Counts (CI Run `44232784151`)
- **Backend Unit Tests**: **349 passed**, 0 failed, 0 skipped (Duration: 5s).
- **Backend Integration Tests**: **156 passed**, 0 failed, 0 skipped (Duration: 43s against PostgreSQL 16).
- **Mobile Widget Tests**: **1 passed**, 0 failed (Duration: 6s).
- **Frontend Verification**: `pnpm lint` and `pnpm build` completed with 0 warnings/errors.
- **Docker Compose**: `docker compose config` and container initialization scripts verified.
- **Total Automated Test Count Across Repository**: **506 passing automated tests**.

### Environment & Tooling Observations
1. **Local .NET 10 / Docker Availability**:
   - The developer machine is configured with .NET 8 locally while the project strictly targets .NET 10 LTS (`global.json` pinned to `10.0.100`).
   - All backend builds and integration tests execute containerized inside GitHub Actions CI runner (`ubuntu-latest` with PostgreSQL 16 service container).
   - Local test execution requires either installing .NET 10 SDK locally or launching the local Docker Desktop daemon.
2. **NuGet Vulnerability Audit**:
   - `dotnet list package --vulnerable --include-transitive` executes in CI and reports **0 known vulnerable packages**.
3. **Compiler Warnings in CI**:
   - Minor deprecation warning in `SecurityServiceExtensions.cs`: `ForwardedHeadersOptions.KnownNetworks` is marked obsolete in .NET 10 in favor of `KnownIPNetworks`. Technical debt ticket logged below.

---

## 7. Technical Debt & Outstanding Risks

| ID | Category | Description | Severity | Remediation Plan |
| :---: | :--- | :--- | :---: | :--- |
| **TD-01** | Scalability | In-memory `RateLimiter` and in-memory `SecurityStampValidator` cache are node-local. In horizontal multi-node deployments, rate limits multiply across $N$ instances and stamp cache invalidation requires up to 60s to propagate across peer nodes. | Medium | Introduce Redis backplane for distributed sliding-window rate limiting and distributed stamp cache pub/sub invalidation in future scale-out task. |
| **TD-02** | Security / DB | `platform.security_audit_events` immutability is enforced at application/domain level, but database lacks append-only triggers or SQL `REVOKE UPDATE, DELETE` permissions. | Low | Add database migration introducing PostgreSQL trigger preventing updates or deletes on `platform.security_audit_events`. |
| **TD-03** | Toolchain | `SecurityServiceExtensions.cs` uses `KnownNetworks` which emits a deprecation warning in .NET 10 (`Use KnownIPNetworks instead`). | Low | Migrate property assignment to `options.KnownIPNetworks.Add(net)` in future maintenance chore. |
| **TD-04** | Toolchain | GitHub Actions runners log warnings that Node.js 20 actions (`actions/checkout@v4`, `setup-dotnet@v4`) will migrate to Node.js 24 runtime. | Low | Monitor official GitHub Actions release tags and update action versions when v5 versions finalize. |
| **TD-05** | Frontend QA | Next.js web application lacks an automated unit or E2E testing harness (no Jest, Vitest, or Playwright configured). | Medium | Install Vitest and Playwright in Next.js app during frontend feature development. |
| **TD-06** | Mobile QA | Flutter application has only 1 basic startup widget test and lacks mocked integration tests or state management architecture. | Medium | Establish BLoC / Riverpod state architecture and repository integration tests during mobile feature tasks. |

---

## 8. Current Project Position & Immediate Next Step

With the formal completion of Monorepo Tooling (FEAT-000, TECH-001), Database Foundation (FEAT-001), and the complete Authentication & Security Subsystem (FEAT-002 Tasks T1–T8), the platform persistence and identity boundaries are solidly established.

**Authoritative Next Feature Recommendation**:
Proceed to **FEAT-003: Multi-Tenancy Architecture & Management**.
- *Rationale*: Multi-tenancy is the architectural backbone upon which all subsequent business domains (Facilities, Assets, Work Orders) depend. Tenant resolution middleware, tenant context accessors, global EF Core query filters (`WHERE TenantId = @CurrentTenantId`), and tenant onboarding workflows must be established before building domain entities or UI screens.

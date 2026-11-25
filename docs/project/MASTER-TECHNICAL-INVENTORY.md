# MaintenX — Master Technical Inventory & System Catalog

**Document ID:** MASTER-TECHNICAL-INVENTORY
**Audit Reference:** PROJECT-AUDIT-001
**Audit Date:** 2026-11-25
**Auditor Roles:** Senior .NET Software Architect, Security Engineer, DevOps Engineer
**Repository:** `Sathurjanv23/-MaintenX`
**Base Commit:** `b6eac47a5b8f2f7c91e1ee405393cf819cd35ac6` (PR #38 merged on `main`)

---

## 1. Backend Architecture & Module Inventory

### 1.1 Project Structure & Solution Hierarchy
- **Solution File**: `MaintenX.sln` (.NET 10.0 LTS)
- **Projects**:
  - `services/api/MaintenX.Api.csproj`: Authoritative ASP.NET Core API host (`net10.0`).
  - `services/worker/MaintenX.Worker.csproj`: Background worker service (`net10.0`).
  - `tests/unit/MaintenX.UnitTests.csproj`: Unit test suite (`net10.0`, xUnit 2.9.2).
  - `tests/integration/MaintenX.IntegrationTests.csproj`: PostgreSQL integration test suite (`net10.0`, xUnit 2.9.2, Testcontainers / PostgreSQL fixtures).

### 1.2 Module Organization & Class Paths

```
services/api/
├── Application/
│   └── Auth/
│       ├── AuthModule.cs                                # Minimal API module definition (IModule)
│       ├── Contracts/                                   # Request & Response DTOs
│       │   ├── ChangePasswordRequest.cs
│       │   ├── LoginRequest.cs
│       │   ├── LoginResponse.cs
│       │   ├── PasswordMutationResponse.cs
│       │   ├── RefreshTokenRequest.cs
│       │   ├── RefreshTokenResponse.cs
│       │   ├── RegisterRequest.cs
│       │   └── RegisterResponse.cs
│       ├── Models/                                      # Application result records
│       │   ├── AuthTokenResult.cs
│       │   ├── LoginResult.cs
│       │   ├── LogoutResult.cs
│       │   ├── PasswordMutationResult.cs
│       │   ├── RefreshTokenResult.cs
│       │   └── RegistrationResult.cs
│       ├── Persistence/
│       │   └── AuthLockingExtensions.cs                 # SELECT ... FOR UPDATE query extensions
│       ├── Services/
│       │   ├── AuthenticationService.cs                 # Core orchestrator with EF execution strategy
│       │   └── IAuthenticationService.cs                # Application service contract
│       └── Validation/
│           └── PasswordValidation.cs                    # Password complexity rules
├── Common/
│   ├── Errors/
│   │   └── GlobalExceptionHandler.cs                    # RFC 7807 ProblemDetails middleware
│   ├── Health/
│   │   └── DatabaseHealthCheck.cs                       # PostgreSQL connectivity probe with safe errors
│   ├── Modules/
│   │   ├── IModule.cs                                   # Modular endpoint mapping abstraction
│   │   └── ModuleExtensions.cs                          # Assembly scanning & DI registration
│   └── Security/
│       ├── BoundedPartitionManager.cs                   # Memory-bounded rate limit tracking
│       ├── EfUserSecurityStampStore.cs                  # EF Core security stamp retrieval store
│       ├── IJwtKeyRing.cs                               # Dynamic key ring interface
│       ├── IJwtTokenService.cs                          # Access token issuance interface
│       ├── IPasswordSecurityService.cs                  # PBKDF2 hashing & timing mitigation interface
│       ├── IRefreshTokenService.cs                      # Cryptographic refresh token generator interface
│       ├── ISecurityStampValidator.cs                   # Scoped validator with 60s cache interface
│       ├── IUserSecurityStampStore.cs                   # Database stamp lookup interface
│       ├── JwtKeyRing.cs                                # Key ring with 24h retired key retention
│       ├── JwtTokenService.cs                           # HMAC-SHA256 JWT generator
│       ├── PasswordSecurityService.cs                   # PBKDF2 HMAC-SHA256 with dummy verification
│       ├── RefreshTokenService.cs                       # 64-byte random generator + SHA-256 hash
│       ├── SecurityServiceExtensions.cs                 # Comprehensive DI & pipeline registration
│       └── SecurityStampValidator.cs                    # In-memory cached security stamp validator
├── Configuration/
│   ├── DatabaseOptions.cs / DatabaseOptionsValidator.cs
│   ├── JwtOptions.cs / JwtOptionsValidator.cs
│   ├── RateLimitingOptions.cs / RateLimitingOptionsValidator.cs
│   └── TrustedProxyOptions.cs / TrustedProxyOptionsValidator.cs
├── Domain/
│   ├── Auth/
│   │   ├── RefreshToken.cs                              # SHA-256 hash, lineage tracking, replay detection
│   │   ├── SecurityAuditEvent.cs                        # Append-only security audit entity
│   │   ├── SecurityAuditEventType.cs                    # Categorized audit event enum
│   │   ├── SecurityAuditMetadata.cs                     # Structured JSONB metadata
│   │   ├── SessionRevocationReason.cs                   # Audit revocation reason enum & constants
│   │   ├── User.cs                                      # Root user aggregate (lockout, stamps, version)
│   │   ├── UserSession.cs                               # Session aggregate (absolute 30d expiry)
│   │   └── UserStatus.cs                                # PendingVerification, Active, Suspended, Deactivated
│   └── Tenants/
│       ├── ITenantEntity.cs                             # Multi-tenant contract (TenantId Guid)
│       ├── Tenant.cs                                    # Root tenant aggregate (slug, displayName, status, version)
│       ├── TenantAuditEvent.cs                          # Append-only tenant lifecycle & settings audit event
│       ├── TenantMembership.cs                          # Tenant membership aggregate (ITenantEntity)
│       ├── TenantMembershipRole.cs                      # Owner, Administrator, Member
│       ├── TenantMembershipStatus.cs                    # Pending, Active, Suspended, Revoked
│       └── TenantStatus.cs                              # Active, Suspended, PendingOnboarding, Deactivated
├── Application/Tenancy/                                 # FEAT-003 Multi-Tenancy Application & HTTP Layer
│   ├── TenancyModule.cs                                 # /api/v1/tenancy/current & /api/v1/tenants/* endpoints
│   ├── TenancyServiceExtensions.cs                      # AddMaintenXTenancy() & UseTenantResolution()
│   ├── Context/                                         # ITenantContext, TenantContext, TenantContextAccessor
│   ├── Contracts/                                       # CreateTenant*, UpdateTenantRequest, TenantResponse, UserTenantMembershipResponse
│   ├── Endpoints/                                       # TenantResultHttpMapper (RFC 7807 ProblemDetails)
│   ├── Middleware/                                      # TenantResolutionMiddleware, RequireTenantContextAttribute
│   ├── Models/                                          # TenantActorContext, TenantResult, TenantMembershipResult, etc.
│   ├── Resolution/                                      # ITenantActorResolver, TenantActorResolver, TenantResolutionService
│   ├── Services/                                        # ITenantService, TenantService, ITenantMembershipService, TenantMembershipService
│   └── Validation/                                      # TenantValidation
└── Infrastructure/
    └── Persistence/
        ├── Configurations/                              # EF Core IEntityTypeConfiguration mappings
        │   ├── RefreshTokenConfiguration.cs
        │   ├── SecurityAuditEventConfiguration.cs
        │   ├── TenantAuditEventConfiguration.cs
        │   ├── TenantConfiguration.cs
        │   ├── TenantMembershipConfiguration.cs
        │   ├── UserConfiguration.cs
        │   └── UserSessionConfiguration.cs
        ├── DesignTimeDbContextFactory.cs                # Migration tooling factory
        ├── MaintenXDbContext.cs                         # Master DbContext with platform schema
        └── Migrations/                                  # Code-first migration snapshots & model
```

---

## 2. Database Schema & Persistence Inventory

All database tables reside strictly under the `platform` schema in PostgreSQL 16 Alpine:

### 2.1 Table Specifications

#### 1. `platform.tenants`
- **Purpose**: Root organization and tenant catalog.
- **Columns**:
  - `id` (`uuid`, PK, non-clustered, not generated)
  - `name` (`character varying(100)`, NOT NULL)
  - `slug` (`character varying(50)`, NOT NULL, unique lowercase slug)
  - `status` (`character varying(20)`, NOT NULL: `Active`, `Suspended`, `Terminated`)
  - `created_at_utc` (`timestamp with time zone`, NOT NULL)
  - `updated_at_utc` (`timestamp with time zone`, NULL)
  - `version` (`bigint`, NOT NULL, default 1, optimistic concurrency token)
- **Indexes**:
  - `pk_tenants` (PRIMARY KEY on `id`)
  - `ix_tenants_slug` (UNIQUE on `slug`)
  - `ix_tenants_status` (B-tree on `status`)
- **Constraints**:
  - `ck_tenants_slug`: `slug ~ '^[a-z0-9]+(-[a-z0-9]+)*$'`
  - `ck_tenants_status`: `status IN ('Active', 'Suspended', 'Terminated')`

#### 2. `platform.users`
- **Purpose**: User identity credentials, lockout counters, and security stamp.
- **Columns**:
  - `id` (`uuid`, PK)
  - `email` (`character varying(256)`, NOT NULL, normalized lowercase)
  - `password_hash` (`character varying(500)`, NOT NULL, PBKDF2 hash)
  - `security_stamp` (`character varying(100)`, NOT NULL, random security stamp)
  - `status` (`character varying(30)`, NOT NULL: `PendingVerification`, `Active`, `Suspended`, `Deactivated`)
  - `failed_login_attempts` (`integer`, NOT NULL, default 0)
  - `failed_login_window_started_at_utc` (`timestamp with time zone`, NULL)
  - `lockout_end_utc` (`timestamp with time zone`, NULL)
  - `last_login_at_utc` (`timestamp with time zone`, NULL)
  - `created_at_utc` (`timestamp with time zone`, NOT NULL)
  - `updated_at_utc` (`timestamp with time zone`, NULL)
  - `version` (`bigint`, NOT NULL, default 1, optimistic concurrency token)
- **Indexes**:
  - `pk_users` (PRIMARY KEY on `id`)
  - `ix_users_email` (UNIQUE on `email`)
  - `ix_users_status` (B-tree on `status`)
- **Constraints**:
  - `ck_users_email_lowercase`: `email = lower(email)`
  - `ck_users_status`: `status IN ('PendingVerification', 'Active', 'Suspended', 'Deactivated')`
  - `ck_users_failed_login_attempts`: `failed_login_attempts >= 0`

#### 3. `platform.user_sessions`
- **Purpose**: Authenticated user session tracking and activity monitoring.
- **Columns**:
  - `id` (`uuid`, PK)
  - `user_id` (`uuid`, NOT NULL, FK &rarr; `platform.users(id)` ON DELETE CASCADE)
  - `created_at_utc` (`timestamp with time zone`, NOT NULL)
  - `last_used_at_utc` (`timestamp with time zone`, NOT NULL)
  - `expires_at_utc` (`timestamp with time zone`, NOT NULL, 30-day absolute expiration)
  - `revoked_at_utc` (`timestamp with time zone`, NULL)
  - `revocation_reason` (`character varying(50)`, NULL)
  - `version` (`bigint`, NOT NULL, default 1, concurrency token)
- **Indexes**:
  - `pk_user_sessions` (PRIMARY KEY on `id`)
  - `ix_user_sessions_user_id` (B-tree on `user_id`)
  - `ix_user_sessions_expires_at_utc` (B-tree on `expires_at_utc`)
  - `ix_user_sessions_revoked_at_utc` (B-tree on `revoked_at_utc`)
- **Constraints**:
  - `ck_user_sessions_revocation_reason`: Valid reasons (`UserLogout`, `PasswordChanged`, `SecurityStampMismatch`, `AccountSuspended`, `AccountDeactivated`, `TokenReplayDetected`, `AdminRevoked`, `Expired`).

#### 4. `platform.refresh_tokens`
- **Purpose**: Single-use cryptographic refresh token hashes and lineage tracking.
- **Columns**:
  - `id` (`uuid`, PK)
  - `session_id` (`uuid`, NOT NULL, FK &rarr; `platform.user_sessions(id)` ON DELETE CASCADE)
  - `token_hash` (`bytea`, NOT NULL, SHA-256 hash, length 32 bytes)
  - `created_at_utc` (`timestamp with time zone`, NOT NULL)
  - `expires_at_utc` (`timestamp with time zone`, NOT NULL, max 7 days, capped at session expiry)
  - `revoked_at_utc` (`timestamp with time zone`, NULL)
  - `replaced_by_token_hash` (`bytea`, NULL, SHA-256 hash of child token)
- **Indexes**:
  - `pk_refresh_tokens` (PRIMARY KEY on `id`)
  - `ix_refresh_tokens_token_hash` (UNIQUE on `token_hash`)
  - `ix_refresh_tokens_session_id` (B-tree on `session_id`)
  - `ix_refresh_tokens_expires_at_utc` (B-tree on `expires_at_utc`)

#### 5. `platform.security_audit_events`
- **Purpose**: Append-only security audit trail with structured metadata and IP tracking.
- **Columns**:
  - `id` (`uuid`, PK, non-clustered, not generated)
  - `event_type` (`character varying(50)`, NOT NULL)
  - `user_id` (`uuid`, NULL, no FK for durability)
  - `session_id` (`uuid`, NULL, no FK for durability)
  - `client_ip` (`character varying(45)`, NULL, normalized IPv4 or IPv6 string)
  - `details_json` (`jsonb`, NULL, structured metadata)
  - `created_at_utc` (`timestamp with time zone`, NOT NULL)
- **Indexes**:
  - `pk_security_audit_events` (PRIMARY KEY on `id`)
  - `ix_security_audit_events_created_at_utc` (B-tree on `created_at_utc`)
  - `ix_security_audit_events_user_id` (B-tree on `user_id`)
  - `ix_security_audit_events_session_id` (B-tree on `session_id`)
- **Constraints**:
  - `ck_security_audit_events_event_type`: Valid event types (`UserRegistered`, `LoginSuccess`, `LoginFailed`, `AccountLockedOut`, `TokenRefreshed`, `TokenReplayDetected`, `SessionRevoked`, `PasswordChanged`, `SecurityStampRotated`, `UserSuspended`, `UserReactivated`, `UserDeactivated`).

---

## 3. HTTP API Endpoint Inventory

All business routes are exposed via ASP.NET Core Minimal APIs grouped under `/api/v1/auth/`:

| Path | Method | Auth | Rate Limit Policy | Request Body | Response Body | Status Codes |
| :--- | :---: | :---: | :--- | :--- | :--- | :--- |
| `/health/live` | GET | Anonymous | None | None | `HealthCheckResponse` | 200 OK |
| `/health/ready` | GET | Anonymous | None | None | `HealthCheckResponse` | 200 OK, 503 Unhealthy |
| `/api/v1/info` | GET | Anonymous | None | None | `ApiInfoResponse` | 200 OK |
| `/api/v1/auth/register` | POST | Anonymous | `Auth.Registration` (5/min) | `RegisterRequest` (`email`, `password`, `firstName`, `lastName`) | `RegisterResponse` (`message`) | 200 OK, 400 Bad Request, 429 Too Many Requests |
| `/api/v1/auth/login` | POST | Anonymous | `Auth.Login` (10/min) | `LoginRequest` (`email`, `password`) | `LoginResponse` (`accessToken`, `refreshToken`, `tokenType`, `expiresIn`, `user`) | 200 OK, 400 Bad Request, 401 Unauthorized, 429 Too Many Requests |
| `/api/v1/auth/refresh` | POST | Anonymous | `Auth.Refresh` (30/min) | `RefreshTokenRequest` (`refreshToken`) | `RefreshTokenResponse` (`accessToken`, `refreshToken`, `tokenType`, `expiresIn`) | 200 OK, 400 Bad Request, 401 Unauthorized, 429 Too Many Requests |
| `/api/v1/auth/logout` | POST | Bearer JWT | None | None (claims-driven `sid`) | None (204 No Content) | 204 No Content, 401 Unauthorized |
| `/api/v1/auth/change-password` | POST | Bearer JWT | None | `ChangePasswordRequest` (`currentPassword`, `newPassword`) | `PasswordMutationResponse` (`message`) | 200 OK, 400 Bad Request, 401 Unauthorized |

---

## 4. Web Frontend Inventory (`apps/web`)

- **Root Layout**: `src/app/layout.tsx` (Inter font, metadata, viewport).
- **Home / Dashboard**: `src/app/page.tsx` (Client component querying health probes and displaying API connectivity cards with refresh capability).
- **API Client**: `src/lib/api-client.ts` (Typed HTTP wrapper for health probes and API metadata).
- **Styling**: Tailwind CSS 3.4.14 with PostCSS and Autoprefixer.
- **Dependencies**: Next.js 14.2.35, React 18.3.1, React DOM 18.3.1, Lucide React 0.453.0.
- **Build Status**: Verified via `pnpm build` generating static prerendered routes (`/`, `/_not-found`).

---

## 5. Mobile App Inventory (`apps/mobile`)

- **Main Entrypoint**: `lib/main.dart` (Material 3 application launching `MaintenXStartupScreen`).
- **Configuration**: `lib/core/config/app_config.dart` (`appName: 'MaintenX Mobile'`, `apiBaseUrl: 'http://10.0.2.2:5000'`).
- **Platform Runnners**:
  - Android: `android/app/src/main/AndroidManifest.xml` (API level 21+).
  - iOS: `ios/Runner/Info.plist` (iOS 12.0+ deployment target).
- **Dependencies**: Flutter SDK 3.29.0, `flutter_test`.
- **Test Suite**: `test/widget_test.dart` (asserts startup screen title and bootstrap status).

---

## 6. Test Suite & Automation Inventory

| Test Suite / Project | Target Framework | Runner / Framework | Test Count | Test File Locations | Primary Responsibilities |
| :--- | :---: | :---: | :---: | :--- | :--- |
| **MaintenX.UnitTests** | `net10.0` | xUnit 2.9.2 | **349** | `tests/unit/` (13 test files) | Tests domain aggregates (`User`, `UserSession`, `RefreshToken`, `SecurityAuditEvent`), cryptographic services (`JwtKeyRing`, `JwtTokenService`, `PasswordSecurityService`, `RefreshTokenService`, `SecurityStampValidator`), and configuration validators. |
| **MaintenX.IntegrationTests** | `net10.0` | xUnit 2.9.2 / PostgreSQL 16 | **156** | `tests/integration/` (8 test files) | Tests real PostgreSQL operations: `DatabaseFoundationIntegrationTests` (DB-001–DB-019), `AuthPersistenceIntegrationTests`, `SecurityConfigurationIntegrationTests`, `AuthenticationServiceIntegrationTests`, `AuthEndpointsIntegrationTests`, and `AuthEndToEndLifecycleTests`. Protected by `TestDatabaseGuard` with isolated disposable databases (`maintenx_test_*`). |
| **Mobile Widget Tests** | Dart 3.x | `flutter_test` | **1** | `apps/mobile/test/widget_test.dart` | Asserts Material 3 widget rendering, branding, and bootstrap state. |
| **Frontend Lint & Build** | Node 22 / pnpm | Next.js Compiler / ESLint | **2 checks** | `apps/web/` | Verifies zero ESLint warnings and compiles optimized production build. |
| **Docker Compose CI** | Shell / Docker | `docker compose config` | **2 checks** | `infra/docker/` | Validates YAML syntax and executes `01-init-roles.sh` test runner. |

---

## 7. Infrastructure, CI/CD & Deployment Catalog

- **Docker Compose Configuration**: `docker-compose.yml`
  - Service: `postgres` (`postgres:16-alpine`, port 5432, volume `maintenx-postgres-data`, network `maintenx-network`).
  - Init Scripts: `infra/docker/init-db/01-init-roles.sh` (provisions application role `maintenx_app` and development database `maintenx_dev`).
- **GitHub Actions Workflow**: `.github/workflows/ci.yml`
  - Job 1: `validate-docker` (validates compose file and executes container initialization script).
  - Job 2: `backend-ci` (spins up PostgreSQL 16 service container, sets up .NET 10, executes `dotnet list package --vulnerable`, builds Release, runs 349 unit tests, runs 156 integration tests against PostgreSQL).
  - Job 3: `frontend-ci` (sets up pnpm 11, Node 22, installs frozen dependencies, runs `pnpm lint`, runs `pnpm build`).
  - Job 4: `flutter-ci` (sets up Java 17, Flutter 3.29.0 stable, executes `flutter pub get`, `flutter analyze`, `flutter test`).
- **Environment Templates**: `.env.example` defining database credentials, connection strings, JWT signing keys, and proxy configurations.

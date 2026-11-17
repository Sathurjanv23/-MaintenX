# Feature Record: FEAT-002 T7 — End-to-End Automated Testing

## 1. Feature Metadata
- **Task ID**: FEAT-002 (T7)
- **Task Name**: End-to-End Automated Testing & Security Verification
- **Branch**: `feat/002-auth-e2e-testing`
- **Base Commit**: `921e16be44c2c62d5d9253f6168c328d7b4353f1` (PR #18 merged)
- **Target Framework**: .NET 10 (`net10.0`)
- **Database Engine**: PostgreSQL 16 Alpine
- **Test Framework**: xUnit 2.9.2, `Microsoft.AspNetCore.Mvc.Testing` 10.0.0, EF Core 10 LTS

---

## 2. Test Architecture & Prerequisites

The T7 test suite provides full-lifecycle, black-box HTTP automated verification of the FEAT-002 authentication subsystem. Rather than relying on mock objects, the suite executes against the real ASP.NET Core request pipeline and isolated real PostgreSQL 16 test databases.

### Key Architectural Pillars:
1. **Real HTTP Pipeline**: Uses `WebApplicationFactory<Program>` to bootstrap the full middleware stack, including `UseForwardedHeaders`, `UseRateLimiter`, `UseAuthentication` (JWT Bearer), `UseAuthorization`, and `IModule` endpoint mappings under `/api/v1/auth`.
2. **PostgreSQL Database Isolation**:
   - Each test fixture dynamically provisions an isolated, disposable test database (`maintenx_test_*`) using `TestDatabaseGuard`.
   - Databases are migrated via `context.Database.MigrateAsync()`.
   - Dedicated role separation: Administrator operations (`postgres`) provision and teardown schemas; application operations run under restricted application roles (`maintenx_app`).
   - Automated safe teardown drops the isolated database in `DisposeAsync`.
3. **Partition Isolation for Rate Limiting**:
   - Tests inject simulated socket remote IP addresses via a custom startup filter (`X-Test-Socket-Remote-Ip`), ensuring distinct test cases operate in isolated rate limiter partitions without inter-test interference.
4. **Deterministic Clock & State Testing**:
   - Account lockout recovery is validated deterministically by updating the database `lockout_end_utc` timestamp rather than introducing flaky wall-clock delays.

---

## 3. End-to-End Scenarios Covered

The test suite is encapsulated in `tests/integration/AuthEndToEndLifecycleTests.cs` and covers nine primary scenarios:

### Scenario A: Complete Registration and Authentication Lifecycle
- **Test**: `E2E_FullLifecycle_RegisterLoginRefreshProtectedProbeAndLogout_SucceedsEndToEnd`
- **Flow**:
  1. User registers via `POST /api/v1/auth/register` $\rightarrow$ returns 200 OK with generic response.
  2. Authenticates via `POST /api/v1/auth/login` $\rightarrow$ returns 200 OK with valid `AccessToken`, `RefreshToken`, expiration, and `SessionId`.
  3. Probes protected endpoint (`/api/v1/test/auth-probe`) without token $\rightarrow$ 401 Unauthorized.
  4. Probes protected endpoint with valid JWT Bearer token $\rightarrow$ 200 OK with matching claims (`sub` and `sid`).
  5. Rotates refresh token via JSON body `POST /api/v1/auth/refresh` $\rightarrow$ 200 OK with rotated token pair.
  6. Verified replacement access token functions against protected endpoints.
  7. Re-attempts refresh with the old token $\rightarrow$ rejected with 401 Unauthorized.
  8. Calls `POST /api/v1/auth/logout` with active token $\rightarrow$ 204 No Content.
  9. Validates PostgreSQL state: session is marked revoked with `UserLogout`, and active tokens are revoked.
  10. Post-logout refresh attempts fail with 401 Unauthorized.

### Scenario B: Password Change and Multi-Session Invalidation
- **Test**: `E2E_PasswordChange_MultiSession_RevokesAllSessionsAndRejectsOldCredentials`
- **Flow**:
  1. Establishes two independent concurrent sessions (Client A and Client B).
  2. Client A calls `POST /api/v1/auth/change-password` with current and new password.
  3. Old password rejected on login $\rightarrow$ 401 Unauthorized.
  4. New password accepted on login $\rightarrow$ 200 OK.
  5. Refresh tokens from both Session A and Session B are immediately rejected $\rightarrow$ 401 Unauthorized.
  6. In PostgreSQL: All previous user sessions are revoked with `SessionRevocationReason.PasswordChanged`.
  7. `ISecurityStampValidator` confirms the old security stamp is invalid and local cache is invalidated.

### Scenario C: Refresh Token Replay and Single-Flight Concurrency
- **Tests**:
  - `E2E_RefreshTokenReplay_RevokesSessionFamilyAndLogsAudit_LeavesUnrelatedSessionsIntact`:
    - Simulates token theft and replay of rotated token $R_0$.
    - Replay returns generic 401 Unauthorized.
    - PostgreSQL verification: Victim's session family and descendant active tokens are revoked with `TokenReplayDetected`.
    - Unrelated user's session remains active and completely untouched.
    - Durable `SecurityAuditEvent` of type `TokenReplayDetected` is committed without disclosing raw tokens or passwords.
  - `E2E_ConcurrentRefresh_SingleFlightRotation_AllowsAtMostOneSuccess`:
    - Dispatches two concurrent `POST /api/v1/auth/refresh` requests with the exact same token via `Task.WhenAll`.
    - Asserts row-level locking serializes the requests: exactly one request succeeds (200 OK) and the other fails (401 Unauthorized).

### Scenario D: Login Lockout and Deterministic Recovery
- **Test**: `E2E_LoginLockout_FiveFailuresTriggersLockout_ReturnsGeneric401_RecoversAfterWindow`
- **Flow**:
  1. Four failed login attempts return generic 401 Unauthorized (`"Invalid email or password."`).
  2. Fifth failure triggers 15-minute rolling lockout window in PostgreSQL.
  3. Sixth attempt (even with valid credentials) returns generic 401 Unauthorized without disclosing lockout status (never 423 Locked).
  4. Deterministically sets `lockout_end_utc` in PostgreSQL to 1 minute in the past.
  5. Subsequent login with valid credentials succeeds immediately (200 OK) and resets failure counters.

### Scenario E: Registration and Input Validation
- **Tests**:
  - `E2E_Registration_DuplicateAndCaseInsensitiveEmail_ReturnsUniformGenericResponse`:
    - Mixed-case registration with leading/trailing whitespace returns 200 OK.
    - Duplicate registration with clean lowercase returns identical 200 OK without disclosing account existence.
    - Exactly one user is persisted in PostgreSQL.
  - `E2E_Registration_InputValidation_RejectsInvalidPayloadsSafely`:
    - Rejects password < 12 characters, > 128 characters, empty password, malformed JSON, and oversized payloads.
    - Verifies zero sensitive leakage (passwords, hashes, stamps) in error responses.

### Scenario F: Rate Limiting and Untrusted Header Isolation
- **Tests**:
  - `E2E_RateLimiting_EnforcesPermitLimitsAcrossEndpoints_AndReturnsRetryAfter`:
    - Registration: 5 requests allowed per 60 seconds; 6th returns 429 Too Many Requests with `Retry-After`.
    - Login: 10 requests allowed per 60 seconds; 11th returns 429 Too Many Requests with `Retry-After`.
    - Refresh: 30 requests allowed per 60 seconds; 31st returns 429 Too Many Requests with `Retry-After`.
  - `E2E_RateLimiting_UntrustedForwardedHeaders_CannotEvadeRateLimiter`:
    - Simulates an attacker sending spoofed `X-Forwarded-For` headers from an untrusted socket IP.
    - Verifies `ForwardedHeadersMiddleware` rejects untrusted headers and rate limiting tracks the actual socket IP, throttling the 11th attempt with 429 Too Many Requests.

---

## 4. Test Execution Commands

```bash
# Execute only the T7 E2E lifecycle test suite
dotnet test tests/integration/MaintenX.IntegrationTests.csproj -c Release --filter "FullyQualifiedName~AuthEndToEndLifecycleTests"

# Execute all authentication integration tests
dotnet test tests/integration/MaintenX.IntegrationTests.csproj -c Release --filter "FullyQualifiedName~Auth"

# Execute full solution integration test suite
dotnet test tests/integration/MaintenX.IntegrationTests.csproj -c Release

# Execute full solution unit test suite
dotnet test tests/unit/MaintenX.UnitTests.csproj -c Release
```

---

## 5. Security & Invariant Verification Summary
- **Zero Production Changes**: Implemented purely within the test suite and documentation; production runtime policies and security contracts remain unaltered.
- **Zero Sensitive Leaks**: Confirmed that passwords, password hashes, security stamps, and raw tokens never appear in Problem Details or audit logs.
- **Strict Role Separation**: Real PostgreSQL tests execute with restricted `maintenx_app` credentials for application queries.
- **Clean Concurrency**: Parallel refresh tests prove single-flight token rotation under high contention.

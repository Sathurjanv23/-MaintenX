# Feature Record: FEAT-002 T5 — Authentication Application Services

## 1. Feature Metadata
- **Task ID**: FEAT-002 (T5)
- **Task Name**: Authentication Application Services Implementation
- **Branch**: `feat/002-auth-application-services`
- **Base Commit**: `e987fcbc4c8eb27bf03651b40b8e06a6512fc2c2` (PR #16 merged)
- **Target Framework**: .NET 10 (`net10.0`)
- **Database Engine**: PostgreSQL 16 Alpine
- **ORM / Provider**: Entity Framework Core 10 (`Npgsql.EntityFrameworkCore.PostgreSQL` 10.0.0)

---

## 2. Architecture & Design Principles

The Authentication Application Services layer orchestrates all core authentication workflows for the MaintenX SaaS platform. The implementation adheres strictly to the approved FEAT-002 architecture:

1. **Transactional Integrity & Concurrency Control**:
   - Explicit PostgreSQL `READ COMMITTED` transactions orchestrate all state-mutating workflows.
   - Row-level locking via parameterized `SELECT ... FOR UPDATE` prevents concurrent session and token race conditions without risking distributed lock deadlocks.
   - Strict hierarchical lock acquisition ordering:
     $$\text{User} \longrightarrow \text{UserSession} \longrightarrow \text{RefreshToken}$$
   - When revoking multiple active sessions (e.g., during password change or reset), session row locks are deterministically ordered by primary key (`ORDER BY id FOR UPDATE`) to guarantee zero inter-transaction deadlock risk.

2. **Timing-Attack Mitigations**:
   - **Registration**: PBKDF2 password hashing executes *before* querying candidate email existence. Both new user registrations and duplicate registration attempts incur identical computational latency, eliminating account enumeration via timing discrepancies.
   - **Login**: Credential verification employs a two-phase pipeline:
     1. Asynchronous read-only snapshot query against `platform.users` (non-locking).
     2. Out-of-lock PBKDF2 password verification (`IPasswordSecurityService.VerifyHashedPassword`), guaranteeing slow cryptographic operations never hold exclusive PostgreSQL row locks.
     3. Nonexistent users and locked-out accounts execute dummy PBKDF2 verification (`IPasswordSecurityService.VerifyDummyPassword`) to present identical computational latency.
     4. PostgreSQL row locks are acquired only after password verification for failure counter incrementation or session/token issuance.

3. **Single-Flight Refresh Token Rotation & Critical Replay Precedence**:
   - Active refresh tokens are single-use; rotation atomically revokes the current token, issues a successor child token, updates `UserSession.LastUsedAtUtc`, and generates a fresh JWT access token.
   - **Critical Replay Precedence**: Checking for token replay (`token.IsRotated`) precedes checks for session revocation or token expiration.
   - When a rotated token is presented:
     - The entire session family is immediately revoked with reason `TokenReplayDetected`.
     - Active sibling/child refresh tokens are revoked.
     - A permanent `SecurityAuditEvent` of type `TokenReplayDetected` is durably committed to PostgreSQL.
     - If the session was already revoked by a prior action, its original revocation reason is preserved, but the replay audit event is still durably recorded.
   - New refresh token expiration is strictly capped at the parent session's absolute expiration timestamp (`UserSession.ExpiresAtUtc`).

4. **Security Audit Durability & Zero PII Leakage**:
   - Security audit events (`platform.security_audit_events`) are committed within the same database transaction as the authentication mutation.
   - Audit foreign keys use `ON DELETE SET NULL` for user and session references, ensuring audit history remains durable and queryable even if user entities are purged.
   - All audit records utilize structured metadata (`SecurityAuditMetadata`) with allow-listed reasons and actions (`permit`, `deny`, `session_created`, `session_revoked`, `token_rotated`, `lockout_applied`).
   - Plaintext passwords, password hashes, raw tokens, token hashes, and unverified candidate emails are strictly excluded from audit records, log statements, and exception messages.
   - Result records (`AuthTokenResult`, `LoginResult`, `RefreshTokenResult`) implement custom `ToString()` methods that explicitly redact raw tokens.

---

## 3. Workflow Specifications

### A. User Registration (`RegisterAsync`)
- Validates email format and password length (12–128 characters).
- Mitigates timing attacks by computing PBKDF2 hash before database query.
- Returns uniform generic message: `"If the email address is eligible, an account initialization has been processed."`
- Safely catches PostgreSQL unique constraint violation race conditions (`23505` `ix_users_email`) and returns the generic response without disclosing account existence.

### B. User Login (`LoginAsync`)
- Non-locking snapshot check of user record.
- Nonexistent users execute dummy PBKDF2 verification and return `InvalidCredentials`.
- Out-of-lock PBKDF2 password verification.
- **On Failure**: Acquires user row lock, evaluates rolling 15-minute failure window, increments failure count, enforces 15-minute lockout upon 5 consecutive failures, records `UserLoginFailed` or `AccountLockedOut` audit event.
- **On Success**: Acquires user row lock, verifies snapshot version hasn't mutated concurrently, resets failed login counters, performs transparent rehash if PBKDF2 parameters evolved (without rotating security stamp), creates `UserSession`, creates `RefreshToken`, issues signed JWT access token, records `LoginSuccess` audit event.

### C. Refresh Token Rotation (`RefreshTokenAsync`)
- Validates raw refresh token and computes SHA-256 hash.
- Acquires row lock on `UserSession`, then on `RefreshToken`.
- Evaluates replay attack invariant first. If `IsRotated == true`, revokes entire session family and child tokens, logs `TokenReplayDetected` audit event, and returns replay failure.
- Verifies session is neither expired nor revoked, and verifies owning user remains `Active`.
- Issues new 64-byte cryptographic refresh token, links successor hash to previous token, updates `UserSession.LastUsedAtUtc`, issues new access JWT, records `TokenRefreshed` audit event.

### D. Logout (`LogoutAsync`)
- Acquires row lock on `UserSession`.
- Idempotent: returns success if session does not exist or is already revoked.
- Verifies session caller identity if caller userId is provided.
- Revokes session with reason `UserLogout`, revokes all active child tokens, evicts security stamp from `IMemoryCache`, records `SessionRevoked` audit event.

### E. Password Mutation (`ChangePasswordAsync` & `AuthorizedResetPasswordAsync`)
- Validates new password length (12–128 characters).
- Out-of-lock verification of current credentials (`ChangePasswordAsync`).
- Acquires user row lock, revalidates version concurrency.
- Updates password hash, updates password version, rotates security stamp (`User.UpdatePassword`).
- Acquires deterministic row locks (`ORDER BY id FOR UPDATE`) on all active user sessions and revokes them with reason `PasswordChanged`.
- Atomically revokes all active child refresh tokens.
- Evicts security stamp from `IMemoryCache` via `ISecurityStampValidator.Invalidate(userId)`.
- Records `PasswordChanged` audit event.

---

## 4. Test Evidence Summary

### Unit Tests
- **Test Project**: `tests/unit/MaintenX.UnitTests.csproj`
- **Total Tests**: 349 passed, 0 failed, 0 skipped.
- **Coverage**:
  - `PasswordValidation` constraint enforcement (min 12, max 128, empty/whitespace rejection, non-disclosure).
  - Diagnostic string redaction in result models (`AuthTokenResult`, `LoginResult`, `RefreshTokenResult`).
  - Pre-persistence parameter validation across all application service endpoints.
  - Dependency injection registration and scoped lifetime validation for `IAuthenticationService`.

### PostgreSQL Integration Tests
- **Test Project**: `tests/integration/MaintenX.IntegrationTests.csproj`
- **Total Tests**: 112 passed, 0 failed, 0 skipped (including 13 dedicated `AuthenticationServiceIntegrationTests`).
- **PostgreSQL Target**: Real PostgreSQL 16 Alpine container on `maintenx-network`.
- **Scenarios Verified**:
  1. `RegisterAsync_ValidInputs_CreatesUserAndSecurityAuditEvent`: Complete user persistence and allow audit event.
  2. `RegisterAsync_DuplicateEmail_ReturnsGenericResponseAndAuditsDenyWithoutEnumeration`: Uniform response on duplicate registration, deny audit logged without leaking email.
  3. `LoginAsync_ValidCredentials_IssuesJwtWithRequiredClaimsAndResetsFailedAttempts`: JWT claims (`kid`, `sub`, `sid`, `sst`), session creation, token creation, login success audit event.
  4. `LoginAsync_InvalidPassword_IncrementsFailedAttemptsAndAuditsFailure`: Failed login counter increment and deny audit.
  5. `LoginAsync_FiveFailedAttempts_EnforcesFifteenMinuteLockout`: 5 failures enforce lockout, subsequent attempts during lockout rejected with lockout duration.
  6. `LoginAsync_NonexistentUser_ExecutesDummyHashAndReturnsInvalidCredentials`: Dummy verification executed, failure audited with null userId.
  7. `RefreshTokenAsync_ValidToken_RotatesAtomicallyAndCapsExpiryAtSessionExpiry`: Atomic rotation, lineage update, expiry capped at session boundary.
  8. `RefreshTokenAsync_TokenReplayDetected_RevokesSessionFamilyAndRecordsAuditEvent`: Replay triggers session family revocation and durable replay audit event.
  9. `RefreshTokenAsync_ConcurrentRotation_OneSucceedsAndSecondDetectsReplay`: Two concurrent refresh requests race on row locks; first rotates, second immediately detects replay.
  10. `LogoutAsync_ValidSession_RevokesSessionAndActiveRefreshTokensIdempotently`: Idempotent session and child token revocation.
  11. `LogoutAsync_CallerMismatch_ReturnsFailure`: Session ownership verification failure.
  12. `ChangePasswordAsync_ValidCredentials_RotatesSecurityStampAndRevokesAllSessions`: Security stamp rotation, deterministic session family revocation, old password invalidated, new password accepted.
  13. `AuthorizedResetPasswordAsync_RotatesSecurityStampAndRevokesAllSessions`: Administrative reset rotates security stamp and revokes all active sessions.

### Security & Vulnerability Audit
- **Command**: `dotnet list MaintenX.sln package --vulnerable --include-transitive`
- **Result**: Zero vulnerable packages identified across `MaintenX.Api`, `MaintenX.Worker`, `MaintenX.UnitTests`, and `MaintenX.IntegrationTests`.

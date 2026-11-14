# Feature Record: FEAT-002 T5 — Authentication Application Services

## 1. Feature Metadata
- **Task ID**: FEAT-002 (T5)
- **Task Name**: Authentication Application Services Implementation & Remediation
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

2. **Timing-Attack Mitigations & Out-of-Lock Cryptography**:
   - **Registration**: PBKDF2 password hashing executes *before* querying candidate email existence. Both new user registrations and duplicate registration attempts incur identical computational latency, eliminating account enumeration via timing discrepancies.
   - **Login**: Credential verification employs a strict two-phase pipeline:
     1. Asynchronous read-only snapshot query against `platform.users` (non-locking).
     2. Out-of-lock PBKDF2 password verification (`IPasswordSecurityService.VerifyHashedPassword`), guaranteeing slow cryptographic operations never hold exclusive PostgreSQL row locks.
     3. Nonexistent users and locked-out accounts execute dummy PBKDF2 verification (`IPasswordSecurityService.VerifyDummyPassword`) to present identical computational latency.
     4. **Out-of-Lock Rehash Precomputation**: When `NeedsRehash(verification)` is true, the replacement password hash is computed *before* acquiring the user row lock and *before* opening the success transaction. Inside the lock, the rehash is applied only after revalidating that the user status, version token, security stamp, password hash, and lockout state match the snapshot. Transparent rehash updates the password hash without rotating the security stamp.
     5. PostgreSQL row locks are acquired only after password verification and rehash computation have completed.

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
   - All audit records utilize structured metadata (`SecurityAuditMetadata`) with allow-listed reasons and actions (`permit`, `deny`, `session_created`, `session_revoked`, `token_rotated`, `lockout_applied`, `security_stamp_rotated`).
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
- **On Failure**: Acquires user row lock, evaluates active status and unchanged password hash, increments failure count, enforces 15-minute lockout upon 5 consecutive failures, records `LoginFailed` or `AccountLockedOut` audit event.
- **On Success**: Computes rehash outside lock if required. Acquires user row lock, verifies snapshot version, status, stamp, and hash haven't mutated concurrently. Resets failed login counters, applies precomputed rehash if needed (without rotating security stamp), creates `UserSession`, creates `RefreshToken`, issues signed JWT access token, records `LoginSuccess` audit event.

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
- Out-of-lock hashing of new password.
- Acquires user row lock, revalidates version concurrency.
- Updates password hash, updates password version, rotates security stamp (`User.UpdatePassword`).
- Acquires deterministic row locks (`ORDER BY id FOR UPDATE`) on all active user sessions and revokes them with reason `PasswordChanged`.
- Atomically revokes all active child refresh tokens.
- Evicts security stamp from `IMemoryCache` via `ISecurityStampValidator.Invalidate(userId)`.
- Records `PasswordChanged` audit event.

---

## 4. Architectural Boundaries: Authorization & Rate Limiting

1. **Administrative Reset Authorization Boundary**:
   - `AuthorizedResetPasswordAsync` is an internal application service method designed for administrative or authorized recovery operations.
   - It validates domain invariants and prevents resetting deactivated accounts, but does *not* inspect HTTP caller context or claims principal identity.
   - **T6 Obligation**: Upstream callers (T6 HTTP API controllers) MUST enforce administrative authorization (e.g. `[Authorize(Roles = "Admin")]`) or verified recovery token validation prior to calling this method.

2. **Rate Limiting Boundary**:
   - Memory-bounded rate limiting policies (`Auth.Registration`, `Auth.Login`, `Auth.Refresh`) are registered into the service collection in `SecurityServiceExtensions.cs` and run as ASP.NET Core middleware (`app.UseRateLimiter()`).
   - Rate limiting is an HTTP transport concern; the application service `IAuthenticationService` does not enforce IP rate limits directly.
   - **T6 Obligation**: Protection against brute-force traffic requires T6 endpoint mappings to attach `.RequireRateLimiting(...)` policies to the respective HTTP routes.

---

## 5. Test Evidence & Coverage Matrix

### Test Execution Summary
- **Unit Tests**: **349 passed, 0 failed, 0 skipped** (`tests/unit/MaintenX.UnitTests.csproj`).
- **PostgreSQL Integration Tests**: **118 passed, 0 failed, 0 skipped** (`tests/integration/MaintenX.IntegrationTests.csproj`, running against real PostgreSQL 16 Alpine container).
- **Vulnerability Audit**: **0 vulnerable packages** across all solution projects.

### Detailed Test Classification

| Invariant / Requirement | Test Method | Test Category | Target Invariant Verified |
|---|---|---|---|
| Concurrent registration race | `RegisterAsync_ConcurrentRegistrationForSameEmail_ResultsInExactlyOneUserAndGenericResponses` | **Genuine Concurrency** | Simultaneous `Task.WhenAll` calls with identical normalized email; exactly 1 user created, generic responses, 0 unhandled exceptions. |
| Concurrent failed logins | `LoginAsync_ConcurrentFailedLogins_EnforcesLockoutWithoutLostUpdates` | **Genuine Concurrency** | Simultaneous `Task.WhenAll` failed logins; row locks serialize updates, zero lost updates, 15-minute lockout enforced. |
| Concurrent session logout | `LogoutAsync_ConcurrentLogoutForSameSession_IsSafeIdempotentAndConsistent` | **Genuine Concurrency** | Simultaneous `Task.WhenAll` logouts for same session; idempotent success, session revoked with `UserLogout`, all tokens revoked. |
| Concurrent refresh rotation race | `RefreshTokenAsync_ConcurrentRotation_OneSucceedsAndSecondDetectsReplay` | **Genuine Concurrency** | Simultaneous `Task.WhenAll` refresh calls; exactly 1 succeeds, exactly 1 detects replay and revokes session. |
| Replay on already-revoked session | `RefreshTokenAsync_ReplayOnAlreadyRevokedSession_PreservesOriginalReasonAndPersistsReplayAudit` | Sequential Integration | Rotated token replayed against logged-out session; detects replay, preserves `UserLogout` reason, commits replay audit event. |
| Transparent rehash without stamp rotation | `LoginAsync_WhenRehashNeeded_UpdatesPasswordHashWithoutRotatingSecurityStamp` | Sequential Integration | Rehash computes outside lock, updates password hash and version, preserves security stamp, issues valid tokens. |
| Stale snapshot rehash abortion | `LoginAsync_WhenRehashNeeded_StaleSnapshotAbortsAndDoesNotApplyRehash` | Sequential Integration | Intervening password mutation makes snapshot stale; login aborts, rehash discarded, tokens not issued. |
| Normal login without rehash | `LoginAsync_ValidCredentials_IssuesJwtWithRequiredClaimsAndResetsFailedAttempts` | Sequential Integration | Standard login issues tokens with claims (`kid`, `sub`, `sid`, `sst`), resets failed attempts, commits audit. |
| Lockout enforcement | `LoginAsync_FiveFailedAttempts_EnforcesFifteenMinuteLockout` | Sequential Integration | 5 sequential failures trigger lockout; subsequent attempts during lockout rejected with lockout duration. |
| Nonexistent user dummy timing | `LoginAsync_NonexistentUser_ExecutesDummyHashAndReturnsInvalidCredentials` | Sequential Integration | Nonexistent user executes dummy PBKDF2 hash, audits failure with null userId. |
| Duplicate registration response | `RegisterAsync_DuplicateEmail_ReturnsGenericResponseAndAuditsDenyWithoutEnumeration` | Sequential Integration | Duplicate email returns identical generic response, audits deny without disclosing email existence. |
| Refresh token expiry capping | `RefreshTokenAsync_ValidToken_RotatesAtomicallyAndCapsExpiryAtSessionExpiry` | Sequential Integration | New refresh token expiry never exceeds parent session absolute expiry. |
| Multi-session password change | `ChangePasswordAsync_ValidCredentials_RotatesSecurityStampAndRevokesAllSessions` | Sequential Integration | Deterministic session locking (`ORDER BY id FOR UPDATE`), rotates security stamp, revokes all active sessions. |
| Administrative password reset | `AuthorizedResetPasswordAsync_RotatesSecurityStampAndRevokesAllSessions` | Sequential Integration | Resets password, rotates security stamp, revokes all sessions, commits `AdminAction` audit. |
| Logout caller ownership mismatch | `LogoutAsync_CallerMismatch_ReturnsFailure` | Sequential Integration | Rejects logout when caller userId does not match session owner. |
| Audit durability after user deletion | `SecurityAuditEvents_PersistWithSetNull_WhenUserAndSessionDeleted` | Sequential Integration | Foreign keys use `ON DELETE SET NULL`; audit records survive user and session deletion. |
| Diagnostic token redaction | `SensitiveModels_RedactRawTokensInToString` | Unit | `ToString()` on `AuthTokenResult`, `LoginResult`, `RefreshTokenResult` redacts raw tokens. |
| Password length validation | `PasswordValidation_RejectsPasswordsShorterThan12Characters` | Unit | Enforces 12–128 character bounds; exceptions do not disclose input characters. |
| Scoped DI registration | `AddMaintenXSecurity_RegistersAuthenticationService_AsScoped` | Unit | Verifies `IAuthenticationService` resolves with `Scoped` lifetime. |

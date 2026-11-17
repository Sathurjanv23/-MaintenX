# Feature Record: FEAT-002 T6 — Authentication API Endpoints

## 1. Feature Metadata
- **Task ID**: FEAT-002 (T6)
- **Task Name**: Authentication HTTP API Endpoints
- **Branch**: `feat/002-auth-api-endpoints`
- **Base Commit**: `30dbc463ff1cb2756b7bc2da0a64ad596a204072` (PR #17 merged)
- **Target Framework**: .NET 10 (`net10.0`)
- **Hosting / Routing**: ASP.NET Core Minimal APIs via `IModule` architecture (`AuthModule`)
- **Transport**: JSON over HTTPS / HTTP

---

## 2. Overview & Architecture

The T6 Authentication API layer exposes the HTTP surface for the FEAT-002 authentication application services (`IAuthenticationService`). Built on the ASP.NET Core Minimal API and `IModule` pattern, it provides a clean, decoupled endpoint group under `/api/v1/auth` without introducing MVC controllers or altering underlying domain/database schemas.

### Core Architectural Principles:
1. **Module Discovery**: `AuthModule` implements `IModule` and is registered as a singleton in dependency injection via `SecurityServiceExtensions.AddMaintenXSecurity()`. It is automatically discovered and mapped by `app.MapEndpoints()` at application startup.
2. **Anonymous vs Authenticated Boundaries**:
   - Anonymous endpoints: `/register`, `/login`, `/refresh`.
   - Authenticated endpoints: `/logout`, `/change-password` (protected by `.RequireAuthorization()`).
3. **Claims-Driven Identity**: Authenticated endpoints extract caller identity directly from validated JWT claims (`ClaimTypes.NameIdentifier` / `"sub"` for User ID and `"sid"` for Session ID), preventing caller impersonation or parameter tampering.
4. **Resilient Execution Strategy Support**: Application service transactional methods are wrapped within `_dbContext.Database.CreateExecutionStrategy().ExecuteAsync(...)` to ensure full compatibility with Npgsql retrying execution strategies configured with transient failure retries.
5. **Universal Generic Error Mapping**: To prevent username harvesting, account enumeration, and lockout state leakage:
   - Registration returns a uniform generic message regardless of whether an account was created or already existed.
   - Login returns generic `401 Unauthorized` (`ProblemDetails` with code `INVALID_CREDENTIALS`) for incorrect password, non-existent user, deactivated user, or locked out account. HTTP `423 Locked` is intentionally avoided.

---

## 3. Endpoints & Route Specifications

All endpoints are mapped under the route group: `/api/v1/auth`.

### 1. User Registration (`POST /api/v1/auth/register`)
- **Authorization**: Anonymous (`.AllowAnonymous()`)
- **Rate Limiting**: Policy `"Auth.Registration"` (IP-based sliding window: 5 permits per 15 minutes)
- **Request Body**: `RegisterRequest`
  ```json
  {
    "email": "user@example.com",
    "password": "Password123!",
    "firstName": "John",
    "lastName": "Doe"
  }
  ```
- **Validation**:
  - `email`: Not empty, valid format (`@` present).
  - `password`: Not empty, 12 to 128 characters in length.
  - `firstName` & `lastName`: Optional / string.
- **Success Response**: `200 OK`
  ```json
  {
    "message": "If the email address is eligible, an account initialization has been processed."
  }
  ```
- **Error Responses**:
  - `400 Bad Request`: Validation failure on email or password length (RFC 7807 Problem Details).
  - `429 Too Many Requests`: Rate limit exceeded.

### 2. User Login (`POST /api/v1/auth/login`)
- **Authorization**: Anonymous (`.AllowAnonymous()`)
- **Rate Limiting**: Policy `"Auth.Login"` (IP-based sliding window: 10 permits per 15 minutes)
- **Request Body**: `LoginRequest`
  ```json
  {
    "email": "user@example.com",
    "password": "Password123!"
  }
  ```
- **Validation**:
  - `email`: Not empty, valid format.
  - `password`: Not empty, 1 to 128 characters.
- **Success Response**: `200 OK`
  ```json
  {
    "accessToken": "eyJhbGciOi...",
    "refreshToken": "64_byte_cryptographic_token_string...",
    "expiresInSeconds": 900,
    "tokenType": "Bearer",
    "sessionId": "a1b2c3d4-e5f6-7890-abcd-ef1234567890"
  }
  ```
- **Error Responses**:
  - `400 Bad Request`: Validation failure (empty email or password).
  - `401 Unauthorized`: Generic `ProblemDetails` (`"Invalid email or password."`) returned uniformly for:
    - User does not exist
    - Incorrect password
    - Account is locked out
    - Account is deactivated
  - `429 Too Many Requests`: Rate limit exceeded.

### 3. Refresh Token Rotation (`POST /api/v1/auth/refresh`)
- **Authorization**: Anonymous (`.AllowAnonymous()`)
- **Rate Limiting**: Policy `"Auth.Refresh"` (IP-based sliding window: 30 permits per 15 minutes)
- **Request Body**: `RefreshTokenRequest`
  ```json
  {
    "refreshToken": "64_byte_cryptographic_token_string..."
  }
  ```
- **Validation**:
  - `refreshToken`: Not empty.
- **Success Response**: `200 OK`
  ```json
  {
    "accessToken": "eyJhbGciOi...",
    "refreshToken": "new_64_byte_cryptographic_token_string...",
    "expiresInSeconds": 900,
    "tokenType": "Bearer",
    "sessionId": "a1b2c3d4-e5f6-7890-abcd-ef1234567890"
  }
  ```
- **Error Responses**:
  - `400 Bad Request`: Empty refresh token.
  - `401 Unauthorized`: Invalid, expired, revoked, or replayed refresh token, or inactive account. If token replay is detected, the session family is revoked server-side and an audit log is durably recorded.
  - `429 Too Many Requests`: Rate limit exceeded.

### 4. User Logout (`POST /api/v1/auth/logout`)
- **Authorization**: Authenticated (`.RequireAuthorization()`)
- **Rate Limiting**: Standard API tier
- **Request Body**: None
- **Identity Derivation**:
  - User ID extracted from `ClaimTypes.NameIdentifier` / `sub`.
  - Session ID extracted from `sid` claim.
- **Success Response**: `204 No Content`
- **Error Responses**:
  - `401 Unauthorized`: Missing, expired, or invalid JWT access token, or missing required claims.
- **Idempotence**: If the session has already been revoked or expired, the endpoint returns `204 No Content` without throwing errors.

### 5. Change Password (`POST /api/v1/auth/change-password`)
- **Authorization**: Authenticated (`.RequireAuthorization()`)
- **Rate Limiting**: Standard API tier
- **Request Body**: `ChangePasswordRequest`
  ```json
  {
    "currentPassword": "OldPassword123!",
    "newPassword": "NewStrongPassword456!"
  }
  ```
- **Validation**:
  - `currentPassword`: Not empty.
  - `newPassword`: Not empty, 12 to 128 characters.
- **Identity Derivation**:
  - User ID extracted from `ClaimTypes.NameIdentifier` / `sub`.
- **Success Response**: `200 OK`
  ```json
  {
    "message": "Password changed successfully."
  }
  ```
- **Error Responses**:
  - `400 Bad Request`: Validation failure (e.g. new password length outside 12-128 characters).
  - `401 Unauthorized`: Invalid current credentials, unauthenticated request, or inactive account.
  - `429 Too Many Requests`: Rate limit exceeded.

---

## 4. Token Transport & Client Security Architecture

### Why JSON Body Transport Was Selected
The refresh token endpoint utilizes a JSON request/response body rather than HTTP-only cookies:
1. **Multi-Platform Support**: The MaintenX platform targets web, native desktop, and mobile clients (`apps/`). Native clients on Android and iOS interact cleanly with JSON token responses stored in secure OS vaults without cookie jar emulation or same-site cookie quirks.
2. **Elimination of Cross-Site Request Forgery (CSRF)**: Utilizing Bearer Authorization headers and JSON bodies eliminates browser ambient credentials (automatic cookie submission), eliminating CSRF vulnerabilities on authentication mutations.

### Client-Side Storage & Security Guidance
- **Native / Mobile Clients**: Store the refresh token in encrypted hardware-backed keystores (iOS Keychain, Android EncryptedSharedPreferences/KeyStore).
- **Web SPA Clients**: Prefer an architecture with a Backend-For-Frontend (BFF) proxy or store access tokens in memory and use short-lived sessions. Never store raw refresh tokens in unencrypted `localStorage` vulnerable to cross-site scripting (XSS).

---

## 5. Explicit Deferrals & Future Boundaries

### Deferral of Administrative Password Reset Endpoint
The underlying application service method `IAuthenticationService.AuthorizedResetPasswordAsync` is fully implemented and tested in T5. However, the corresponding HTTP endpoint (`POST /api/v1/auth/admin/reset-password` or similar) is **explicitly deferred**:
- **Rationale**: MaintenX does not currently have a trusted Role-Based Access Control (RBAC) model, tenant boundary claims validator, or cryptographic password-reset token exchange service in place.
- Exposing `AuthorizedResetPasswordAsync` without a hardened administrative authorization guard or signed recovery token verification would introduce a critical privilege escalation vector.
- The endpoint will be introduced in an upcoming feature once administrative roles, claims transformations, and permission policies are formally established.

---

## 6. Known Inherited Limitations
- **In-Memory Rate Limiting**: The rate-limiting middleware operates locally in-memory per host instance. When scaling horizontally across multiple container instances, a distributed rate-limiting store (such as Redis) will be required.
- **No Self-Service Password Reset Token Flow**: User password self-recovery via signed email verification tokens is not part of FEAT-002 and is scheduled for a future feature.

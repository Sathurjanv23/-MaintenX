# Feature Record: TECH-001 — Development Toolchain Alignment

## 1. Feature Metadata
- **Task ID**: TECH-001
- **Task Name**: Development Toolchain Alignment & API Security Hardening
- **Branch**: `chore/001-toolchain-alignment`
- **Status**: Implemented & Verified
- **Completed Date**: 2026-11-12
- **Author**: Principal .NET Architect, Senior DevOps Engineer, Flutter Engineer, QA Automation Lead

---

## 2. Summary of Changes
Standardized and aligned the complete monorepo toolchain prior to domain entity and database schema implementation.

Key deliverables:
1. **.NET 10 LTS Toolchain Alignment**:
   - Pinned `global.json` to `.NET 10.0.100` with `latestFeature` roll-forward.
   - Migrated all projects (`MaintenX.Api`, `MaintenX.Worker`, `MaintenX.UnitTests`, `MaintenX.IntegrationTests`) to strictly target `net10.0` (`<TargetFramework>net10.0</TargetFramework>`).
   - Removed all temporary `.NET 8` fallback logic.
2. **API Security Hardening (Information Disclosure Prevention)**:
   - Secured `DatabaseHealthCheck.cs` and `HealthCheckResponseWriter.cs` to eliminate raw PostgreSQL exception traces, internal connection strings, and database topology leaks from public API responses.
   - Emits safe generic public status messages (`"Database service is operational."` and `"Database service is unavailable."`) while capturing deep exception diagnostics in internal application logs.
   - Updated integration test suites to assert safe non-leaking error responses.
3. **Flutter Mobile Scaffolding**:
   - Inspected `apps/mobile` and added full Android (`android/build.gradle`, `android/settings.gradle`, `android/app/build.gradle`, `AndroidManifest.xml`, `MainActivity.kt`) and iOS (`ios/Runner/Info.plist`, `ios/Runner/AppDelegate.swift`) platform scaffolding while preserving existing application code.
4. **CI/CD Pipeline Expansion & Toolchain Pinning (GitHub Actions)**:
   - Updated `.github/workflows/ci.yml` to target `.NET 10 SDK` (`10.0.x`).
   - Upgraded deprecated GitHub Actions (`actions/setup-java@v4` &rarr; `actions/setup-java@v5`).
   - Pinned Flutter SDK version explicitly to `3.29.0` via `subosito/flutter-action@v2`.
   - Added a dedicated `flutter-ci` job validating `flutter pub get`, `flutter analyze`, and `flutter test`.
5. **.NET 10 Package Major Version Alignment**:
   - Upgraded core .NET packages from 8.x to official 10.0 releases (`Microsoft.AspNetCore.OpenApi` 10.0.0, `Microsoft.Extensions.Hosting` 10.0.0, and `Microsoft.AspNetCore.Mvc.Testing` 10.0.0).
6. **Strict PostgreSQL Integration Testing**:
   - Enforced strict positive PostgreSQL readiness assertion in `HealthCheckIntegrationTests.cs` (asserts HTTP 200 OK, `status == Healthy`, and PostgreSQL check `status == Healthy` without allowing HTTP 503 fallback when PostgreSQL is provisioned).
   - Preserved isolated and deterministic negative database connectivity tests utilizing port 59999.
7. **Roadmap Correction**:
   - Aligned the roadmap to:
     - `FEAT-001: PostgreSQL Database Foundation`
     - `FEAT-002: Authentication`
     - `FEAT-003: Multi-Tenancy`
     - `FEAT-004: Role-Based Access Control`
     - `FEAT-005: Next.js Authentication UI`

---

## 3. Toolchain & Environment Matrix

| Subsystem | Intended Production Target | Local Machine State | CI Environment |
|---|---|---|---|
| **.NET SDK** | .NET 10 LTS (`net10.0`) | SDK 8.0.425 installed (Blocked locally until .NET 10 SDK installer executed) | .NET 10.0.x via `actions/setup-dotnet@v4` |
| **Node.js** | &ge; 22.x | v24.18.0 | Node.js 22 via `actions/setup-node@v4` |
| **pnpm** | 11.x | 11.17.0 | pnpm 11 via `pnpm/action-setup@v4` |
| **Flutter SDK** | &ge; 3.10.x (pinned 3.29.0) | Missing from host PATH | Pinned 3.29.0 via `subosito/flutter-action@v2` |
| **Database** | PostgreSQL 16 Alpine | Containerized in Docker Desktop | Containerized service in CI |
| **Web App** | Next.js 14+ (App Router) | Verified build & lint | Verified build & lint in CI |


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
4. **CI/CD Pipeline Expansion (GitHub Actions)**:
   - Updated `.github/workflows/ci.yml` to target `.NET 10 SDK` (`10.0.x`).
   - Added a dedicated `flutter-ci` job validating `flutter pub get`, `flutter analyze`, and `flutter test` using `subosito/flutter-action@v2`.
5. **Roadmap Correction**:
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
| **Flutter SDK** | &ge; 3.10.x | Missing from host PATH | Stable channel via `subosito/flutter-action@v2` |
| **Database** | PostgreSQL 16 Alpine | Containerized in Docker Desktop | Containerized service in CI |
| **Web App** | Next.js 14+ (App Router) | Verified build & lint | Verified build & lint in CI |

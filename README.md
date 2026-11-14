# MaintenX — Enterprise Facility Maintenance SaaS Platform

[![MaintenX CI Pipeline](https://github.com/Sathurjanv23/-MaintenX/actions/workflows/ci.yml/badge.svg)](https://github.com/Sathurjanv23/-MaintenX/actions/workflows/ci.yml)
[![Architecture: Modular Monolith](https://img.shields.io/badge/Architecture-Modular%20Monolith-blue.svg)](docs/architecture/overview.md)
[![Backend: .NET 10 LTS](https://img.shields.io/badge/Backend-.NET%2010%20LTS-purple.svg)](services/api/)
[![Frontend: Next.js 14+](https://img.shields.io/badge/Frontend-Next.js%20(App%20Router)-black.svg)](apps/web/)
[![Database: PostgreSQL 16](https://img.shields.io/badge/Database-PostgreSQL%2016-336791.svg)](docker-compose.yml)
[![Mobile: Flutter](https://img.shields.io/badge/Mobile-Flutter%203.x-02569B.svg)](apps/mobile/)

MaintenX is a cloud-based multi-tenant facility maintenance and Computerized Maintenance Management System (CMMS) SaaS platform engineered for commercial facility managers, building operators, and maintenance technicians.

---

## 1. Business Problem & Solution

Commercial properties, universities, hospitals, and industrial facilities face significant operational downtime, delayed repair responses, lost maintenance documentation, and regulatory compliance risks when relying on manual spreadsheets or legacy fragmented tools.

**MaintenX solves this by providing:**
- A unified multi-tenant architecture isolating each client organization's data.
- Hierarchical location management (Campus &rarr; Building &rarr; Floor &rarr; Zone/Room).
- Equipment asset tracking with preventative maintenance schedules.
- Reactive work order dispatching with real-time status tracking for mobile field technicians.
- Deep observability with automated health reporting.

---

## 2. Technology Stack & Verification State

| Layer | Technology | Version / State | Verification Details |
|---|---|---|---|
| **Web Frontend** | Next.js 14+ (App Router) | v14.2.35, TypeScript, Tailwind | `pnpm lint` and `pnpm build` verified (**PASSED**) |
| **API Backend** | ASP.NET Core Web API | .NET 10 LTS (`net10.0`) | `global.json` pinned, verified in CI pipeline (**PASSED**) |
| **Database & ORM** | PostgreSQL 16 / EF Core 10 | PostgreSQL 16, EF Core 10.0.0 | Npgsql provider, schema migrations & tests verified (**PASSED**) |
| **Background Worker** | .NET Worker Service | .NET 10 LTS (`net10.0`) | Compiled cleanly with 0 errors (**PASSED**) |
| **Mobile App** | Flutter 3.x | Flutter SDK (Not Installed Locally) | Scaffold complete; verified in CI pipeline (**PASSED in CI**) |
| **Architecture** | Modular Monolith | DDD, Clean Architecture | Module contracts (`IModule`) & platform schema established |
| **CI / CD** | GitHub Actions | Pinned v4/v5 actions | CI workflow configured in `.github/workflows/ci.yml` |

---

## 3. Implementation Status & Feature Roadmap

### Completed Features & Tooling Tasks
- [x] **FEAT-000: Monorepo Bootstrap & Hardening**
  - Modular monorepo directory layout (`apps/`, `services/`, `tests/`, `infra/`, `docs/`, `.github/`)
  - ASP.NET Core Web API with Clean Architecture structure and module contracts (`IModule`)
  - Global exception handling using RFC 7807 Problem Details
  - Health check endpoints: `/health/live` (shallow probe) and `/health/ready` (PostgreSQL connectivity)
  - Demonstrated live PostgreSQL containerization with Docker Compose and failover recovery
  - Safe environment configuration templates (`.env.example`)
  - Next.js web application foundation with live backend connectivity dashboard
  - Flutter cross-platform mobile client scaffold with startup screen and configuration
  - Architecture documentation, System Requirements Specification, and ADR-0001
- [x] **TECH-001: Development Toolchain Alignment & API Security Hardening**
  - Pinned `global.json` to `.NET 10.0.100` (`latestFeature` roll-forward)
  - Migrated all projects strictly to `net10.0`
  - Aligned .NET packages (`Microsoft.AspNetCore.OpenApi`, `Microsoft.Extensions.Hosting`, `Microsoft.AspNetCore.Mvc.Testing`) to official 10.0 releases
  - Eliminated information disclosure in `DatabaseHealthCheck` (generic safe public error messages, deep exception logs server-side)
  - Strictly asserted positive PostgreSQL readiness in integration tests without allowing 503 fallback
  - Fully scaffolded Android and iOS platform directories in `apps/mobile`
  - Pinned Flutter SDK `3.29.0` and upgraded GitHub Actions (`actions/setup-java@v5`) in CI pipeline
- [x] **FEAT-001: PostgreSQL Database Foundation**
  - Configured EF Core 10 LTS persistence infrastructure (`Microsoft.EntityFrameworkCore` 10.0.0, `Npgsql.EntityFrameworkCore.PostgreSQL` 10.0.0)
  - Configured `MaintenXDbContext` with connection pooling, command timeouts, and connection resiliency (`EnableRetryOnFailure`)
  - Implemented `MaintenXDesignTimeDbContextFactory` with fail-fast validation and zero hardcoded credentials
  - Implemented root tenant catalog entity `Tenant` in `Domain/Tenants/Tenant.cs` mapped to `platform.tenants`
  - Enforced schema segmentation, UUID primary keys, normalized unique slug index (`ix_tenants_slug`), and lifecycle check constraints (`ck_tenants_status`, `ck_tenants_slug`)
  - Established optimistic concurrency control with `version` token and automatic UTC auditing
  - Generated code-first migrations (`20261113000000_InitialDatabaseFoundation`, `20261113000001_HardenTenantSlugConstraints`) and idempotent SQL scripts
  - Implemented isolated real PostgreSQL integration tests (`DatabaseFoundationIntegrationTests` DB-001 through DB-019) executing in dedicated disposable databases (`maintenx_test_*`) protected by strict fail-closed safety guards, host allowlisting, explicit provisioning opt-in (`TestDatabase:AllowProvisioning`), genuine administrator (`postgres`) vs. restricted application (`maintenx_app`) role separation, automatic teardown on setup failure, and automated migration upgrade testing (`DB014`)
  - Authored comprehensive [Database Architecture Documentation](docs/architecture/database-design.md) and [ADR-0002](docs/adr/ADR-0002-postgresql-efcore.md)

### Feature Roadmap *(Clearly Marked as Planned)*
- [ ] **FEAT-002: Authentication** *(Planned)*
- [ ] **FEAT-003: Multi-Tenancy** *(Planned)*
- [ ] **FEAT-004: Role-Based Access Control** *(Planned)*
- [ ] **FEAT-005: Next.js Authentication UI** *(Planned)*

---

## 4. Database Architecture & Operations Guide

### Technology & Conventions
- **Engine**: PostgreSQL 16 Alpine
- **ORM**: Entity Framework Core 10 (`Npgsql.EntityFrameworkCore.PostgreSQL` 10.0.0)
- **Schemas**: `platform` (catalog & global services), domain-specific schemas for future modules
- **Naming**: `snake_case` tables, columns, primary keys (`pk_{table}`), indexes (`ix_{table}_{col}`), and check constraints (`ck_{table}_{property}`)
- **Concurrency**: Optimistic locking via `version` column (`bigint`) with `DbUpdateConcurrencyException` detection

### Local Database Inspection
To inspect the running PostgreSQL database inside Docker:
```bash
# Connect to PostgreSQL via psql CLI
docker exec -it maintenx-postgres psql -U maintenx_app -d maintenx_dev

# Inspect platform schema tables
\dt platform.*

# Inspect platform.tenants columns and constraints
\d+ platform.tenants

# Query migration history
SELECT * FROM platform."__EFMigrationsHistory";
```

### Migration Workflow & Commands
Migrations are code-reviewed C# classes and compiled into idempotent SQL scripts. Application startup does **not** auto-migrate production schemas.

```bash
# Create a new migration (design-time factory resolves connection)
dotnet ef migrations add <MigrationName> --project services/api --startup-project services/api

# Apply migrations to local development database
dotnet ef database update --project services/api --startup-project services/api

# Apply idempotent SQL script directly (CI/CD / DB Administrator review)
# On Linux/macOS:
psql -U maintenx_app -d maintenx_dev -f docs/migrations/0001_initial_database_foundation.sql
# On Windows (PowerShell):
Get-Content docs/migrations/0001_initial_database_foundation.sql -Raw | docker exec -i maintenx-postgres psql -U maintenx_app -d maintenx_dev
```

### Known Limitations
- **Tenant Isolation**: Row-level tenant isolation filters (`WHERE tenant_id = @current_tenant`) and tenant resolution middleware belong to **FEAT-003: Multi-Tenancy**. FEAT-001 implements the root tenant catalog persistence model only.
- **No Public CRUD Endpoints**: Public tenant onboarding endpoints are deliberately omitted until authentication and authorization boundaries are completed in FEAT-002 and FEAT-004.

---

## 4. Prerequisites & Installation

### Core Tools
- **Git** (&ge; 2.40)
- **Node.js** (&ge; 22.x, v24.18.0 installed)
- **pnpm** (&ge; 9.x, 11.17.0 installed)
- **Docker & Docker Compose** (Docker Desktop with Compose v5.x installed)

### .NET 10 LTS Installation Instructions
The production target for MaintenX backend services is **.NET 10 LTS**. On machines where only .NET SDK 8 is currently installed:
1. Download the .NET 10 SDK installer from [https://dotnet.microsoft.com/download/dotnet/10.0](https://dotnet.microsoft.com/download/dotnet/10.0).
2. Run the installer and verify installation:
   ```bash
   dotnet --list-sdks
   ```
3. To build the complete solution:
   ```bash
   dotnet build MaintenX.sln
   ```

### Flutter SDK Installation Instructions
To run or develop the mobile client in `apps/mobile`:
1. Download Flutter SDK from [https://docs.flutter.dev/get-started/install/windows](https://docs.flutter.dev/get-started/install/windows).
2. Extract to an accessible directory (e.g. `C:\src\flutter`) and add `flutter/bin` to your system `PATH`.
3. Install Android Studio and set up Android SDK / Command-line Tools.
4. Verify Flutter environment:
   ```bash
   flutter doctor -v
   ```

---

## 5. Local Development Setup

### 1. Configure Environment
```bash
# Copy example environment configuration
cp .env.example .env
```

### 2. Start PostgreSQL via Docker Compose
Docker Compose initializes a cluster with a dedicated superuser (`postgres`) and creates a restricted application role (`maintenx_app` without superuser or createdb privileges) owning the `maintenx_dev` database. The credentials are dynamically provisioned via `POSTGRES_APP_PASSWORD` and `POSTGRES_ADMIN_PASSWORD` defined in your `.env` file (executed securely via `infra/docker/init-db/01-init-roles.sh` with no committed default credentials):
```bash
docker-compose up -d postgres
```
Verify the container is healthy:
```bash
docker-compose ps
```

### 3. Configure Database Credentials (.NET User Secrets or Environment Variables)
No database credentials or passwords are committed in `appsettings.json`. For local development, set `DefaultConnection` via .NET User Secrets:
```bash
cd services/api
dotnet user-secrets set "ConnectionStrings:DefaultConnection" "Host=localhost;Port=5432;Database=maintenx_dev;Username=maintenx_app;Password=<your_local_app_password>;"
cd ../..
```
Or via environment variables:
```bash
# On Linux / macOS:
export ConnectionStrings__DefaultConnection="Host=localhost;Port=5432;Database=maintenx_dev;Username=maintenx_app;Password=<your_local_app_password>;"

# On Windows (PowerShell):
$env:ConnectionStrings__DefaultConnection = "Host=localhost;Port=5432;Database=maintenx_dev;Username=maintenx_app;Password=<your_local_app_password>;"
```

### 4. Run ASP.NET Core Web API
```bash
dotnet run --project services/api/MaintenX.Api.csproj
```
Endpoints:
- **Base URL**: `http://localhost:5000`
- **Swagger / OpenAPI**: `http://localhost:5000/swagger`
- **Liveness Probe**: `http://localhost:5000/health/live` &rarr; HTTP 200
- **Readiness Probe**: `http://localhost:5000/health/ready` &rarr; HTTP 200 (DB Online) / HTTP 503 (DB Offline)
- **API Diagnostics**: `http://localhost:5000/api/v1/info`

### 5. Run Next.js Web Frontend
```bash
cd apps/web
pnpm install --frozen-lockfile
pnpm run dev
```
Open [http://localhost:3000](http://localhost:3000) to view the MaintenX dashboard with live backend connectivity indicators.

### 6. Run Flutter Mobile Client *(After Flutter SDK is installed)*
```bash
cd apps/mobile
flutter pub get
flutter run
```

---

## 6. Testing & CI Commands

### Backend (.NET API & Solution)
```bash
# Build complete solution
dotnet build MaintenX.sln

# Run dependency vulnerability audit
dotnet list MaintenX.sln package --vulnerable --include-transitive

# Run unit tests
dotnet test tests/unit/MaintenX.UnitTests.csproj

# Run integration tests against real PostgreSQL using separate administrator & application roles
# Set environment variables for isolated test provisioning:
# Windows (PowerShell):
$env:ConnectionStrings__AdminConnection = "Host=localhost;Port=5432;Database=postgres;Username=postgres;Password=<admin_password>;"
$env:ConnectionStrings__TestConnection = "Host=localhost;Port=5432;Database=postgres;Username=maintenx_app;Password=<app_password>;"
$env:ConnectionStrings__DefaultConnection = "Host=localhost;Port=5432;Database=maintenx_dev;Username=maintenx_app;Password=<app_password>;"
$env:TestDatabase__AllowProvisioning = "true"
$env:TestDatabase__AllowedHosts = "localhost;127.0.0.1;postgres"

dotnet test tests/integration/MaintenX.IntegrationTests.csproj
```

### Frontend (Next.js)
```bash
cd apps/web
pnpm run lint
pnpm run build
```

### Mobile (Flutter)
```bash
cd apps/mobile
flutter analyze
flutter test
```

### Infrastructure Configuration
```bash
docker-compose config
```

---

## 7. Development & Git Workflow

All work must follow the mandatory workflow:
1. Review `README.md` and repository status.
2. Branch off `main`: `git checkout -b <type>/<feat-id>-<name>` (e.g., `chore/001-toolchain-alignment`).
3. Implement solely the assigned feature.
4. Run builds, lints, and relevant tests.
5. Record changes in `docs/features/TECH-001-toolchain-alignment.md` and update `README.md`.
6. Verify no secrets or sensitive files are staged.
7. Create a focused conventional commit.
8. Push feature branch and open a pull request targeting `main`. Do not merge automatically.

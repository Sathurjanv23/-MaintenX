# MaintenX — Enterprise Facility Maintenance SaaS Platform

[![Architecture: Modular Monolith](https://img.shields.io/badge/Architecture-Modular%20Monolith-blue.svg)](docs/architecture/overview.md)
[![Backend: .NET 8 / 10](https://img.shields.io/badge/Backend-.NET%208%20%2F%2010%20LTS-purple.svg)](services/api/)
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

## 2. Technology Stack

| Layer | Technology | Details |
|---|---|---|
| **Web Frontend** | Next.js 14+ (App Router) | TypeScript, Tailwind CSS, Lucide Icons, pnpm |
| **API Backend** | ASP.NET Core Web API | .NET 8 (with .NET 10 readiness), C#, Minimal APIs & Controllers |
| **Mobile App** | Flutter 3.x | Dart, cross-platform Android & iOS |
| **Database** | PostgreSQL 16 Alpine | Relational storage, persistent volumes, connection pooling |
| **Architecture** | Modular Monolith | Domain-Driven Design (DDD), Clean Architecture |
| **Testing** | xUnit, WebApplicationFactory | Unit and integration test suites |
| **DevOps & Infra** | Docker, Docker Compose | Containerized local environment |

---

## 3. Implementation Status

### Features Implemented
- [x] **FEAT-000: Monorepo Bootstrap**
  - Modular monorepo directory layout (`apps/`, `services/`, `tests/`, `infra/`, `docs/`)
  - ASP.NET Core Web API with Clean Architecture structure and module contracts (`IModule`)
  - Global exception handling using RFC 7807 Problem Details
  - Health check endpoints: `/health/live` (shallow probe) and `/health/ready` (PostgreSQL connectivity)
  - PostgreSQL 16 containerization with Docker Compose and automated health check
  - Safe environment configuration templates (`.env.example`)
  - Next.js web application foundation with live backend connectivity dashboard
  - Flutter cross-platform mobile client scaffold with startup screen and configuration
  - Architecture documentation, System Requirements Specification, and ADR-0001

### Planned Features *(Marked as Planned)*
- [ ] **FEAT-001: Tenancy & Authentication Module** *(Planned)*
- [ ] **FEAT-002: Facilities & Spatial Hierarchy Module** *(Planned)*
- [ ] **FEAT-003: Asset Catalog & QR Code Tracking Module** *(Planned)*
- [ ] **FEAT-004: Work Order Management & Technician Dispatch** *(Planned)*
- [ ] **FEAT-005: Preventative Maintenance Scheduling Engine** *(Planned)*
- [ ] **FEAT-006: Multi-Channel Notifications (Push, SMS, Email)** *(Planned)*

---

## 4. Repository Structure

```
MaintenX/
├── apps/
│   ├── web/                     # Next.js App Router (TypeScript, Tailwind)
│   └── mobile/                  # Flutter cross-platform mobile client
│
├── services/
│   ├── api/                     # ASP.NET Core Modular Monolith Web API
│   │   ├── Common/              # Shared error handling, health checks, module contracts
│   │   ├── Configuration/       # Strongly typed option models
│   │   └── Program.cs           # Web application bootstrap
│   └── worker/                  # Background worker service for future queues/jobs
│
├── tests/
│   ├── unit/                    # xUnit unit test suite
│   └── integration/             # WebApplicationFactory integration test suite
│
├── infra/
│   └── docker/                  # Production multi-stage Dockerfiles
│
├── docs/
│   ├── architecture/            # Architecture overview & Mermaid diagrams
│   ├── adr/                     # Architectural Decision Records (ADR-0001)
│   ├── features/                # Completed feature records
│   └── srs/                     # System requirements specifications
│
├── .agents/
│   └── rules/                   # Monorepo engineering rules
│
├── docker-compose.yml           # Local PostgreSQL container definition
├── MaintenX.sln                 # Root .NET Solution file
├── .editorconfig                # Universal code formatting rules
├── .env.example                 # Safe development configuration template
└── README.md                    # Primary repository documentation
```

---

## 5. Prerequisites

Before running the project locally, ensure the following tools are installed:
- **Git** (&ge; 2.40)
- **.NET SDK** (&ge; 8.0, 8.0.425 installed; .NET 10 LTS compatible)
- **Node.js** (&ge; 20.x, v24.18.0 installed)
- **pnpm** (&ge; 9.x, 11.17.0 installed)
- **Docker & Docker Compose** (Docker Compose v5.x installed)
- **Flutter SDK** (&ge; 3.10.x, required for mobile execution)

---

## 6. Local Development Setup

### 1. Clone & Configure Environment
```bash
git clone https://github.com/Sathurjanv23/-MaintenX.git
cd -MaintenX

# Copy example environment configuration
cp .env.example .env
```

### 2. Start PostgreSQL via Docker Compose
```bash
docker-compose up -d postgres
```
Verify the database is accepting connections:
```bash
docker-compose ps
```

### 3. Run ASP.NET Core Web API
```bash
dotnet restore services/api/MaintenX.Api.csproj
dotnet run --project services/api/MaintenX.Api.csproj
```
The API will start at:
- **Base URL**: `http://localhost:5000`
- **Swagger / OpenAPI**: `http://localhost:5000/swagger`
- **Liveness Probe**: `http://localhost:5000/health/live`
- **Readiness Probe**: `http://localhost:5000/health/ready`
- **API Diagnostics**: `http://localhost:5000/api/v1/info`

### 4. Run Next.js Web Frontend
```bash
cd apps/web
pnpm install
pnpm run dev
```
Open [http://localhost:3000](http://localhost:3000) to view the MaintenX dashboard with live backend connectivity indicator.

### 5. Run Flutter Mobile App *(Requires Flutter SDK)*
```bash
cd apps/mobile
flutter pub get
flutter run
```

---

## 7. Testing Commands

### Backend (.NET API & Unit/Integration Tests)
```bash
# Build entire solution
dotnet build MaintenX.sln

# Run unit tests
dotnet test tests/unit/MaintenX.UnitTests.csproj

# Run integration tests
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

## 8. Development & Git Workflow

All work must follow the mandatory workflow:
1. Review `README.md` and repository status.
2. Branch off `main`: `git checkout -b <type>/<feat-id>-<name>` (e.g., `chore/000-bootstrap`).
3. Implement solely the assigned feature.
4. Run builds, lints, and relevant tests.
5. Record changes in `docs/features/FEAT-XXX-<name>.md` and update `README.md`.
6. Verify no secrets or sensitive files are staged.
7. Create a single conventional commit.
8. Push feature branch and open a pull request into `main`. Do not merge automatically.

# MaintenX System Architecture Overview

## 1. Executive Summary

MaintenX is an enterprise-grade multi-tenant facility maintenance SaaS platform designed to streamline work order management, asset tracking, maintenance scheduling, and real-time vendor collaboration. The system is engineered around a **Modular Monolith** architecture pattern, governed by Domain-Driven Design (DDD) and Clean Architecture principles.

---

## 2. System Context & Communication Topology

```mermaid
flowchart TD
    subgraph Clients["Client Layer"]
        Web["Next.js Web Client<br/>(App Router, TypeScript, Tailwind)"]
        Mobile["Flutter Mobile Client<br/>(iOS / Android Field App)"]
    end

    subgraph API_Gateway["Public Gateway / Reverse Proxy"]
        Proxy["Reverse Proxy / Ingress<br/>(TLS Termination, Rate Limiting)"]
    end

    subgraph Backend["Modular Monolith Backend (ASP.NET Core .NET 10 LTS)"]
        Host["API Host / Routing / DI / Middleware"]
        AuthModule["Module: Tenancy & Identity"]
        FacilityModule["Module: Facilities & Locations"]
        AssetModule["Module: Assets & Equipment"]
        WorkOrderModule["Module: Work Orders & Ticketing"]
        ScheduleModule["Module: Preventative Maintenance"]
        NotificationModule["Module: Notifications & Events"]
    end

    subgraph Storage["Persistence & Infrastructure"]
        Postgres[(PostgreSQL 16<br/>Source of Truth)]
        Worker["Background Worker<br/>(Scheduled Jobs & Triggers)"]
    end

    Web -->|HTTPS / REST / JSON| Proxy
    Mobile -->|HTTPS / REST / JSON| Proxy
    Proxy -->|Internal HTTP| Host
    Host --> AuthModule
    Host --> FacilityModule
    Host --> AssetModule
    Host --> WorkOrderModule
    Host --> ScheduleModule
    Host --> NotificationModule

    AuthModule -->|EF Core / Connection Pool| Postgres
    FacilityModule -->|EF Core / Connection Pool| Postgres
    AssetModule -->|EF Core / Connection Pool| Postgres
    WorkOrderModule -->|EF Core / Connection Pool| Postgres
    ScheduleModule -->|EF Core / Connection Pool| Postgres
    Worker -->|Async Polling / Execution| Postgres
```

---

## 3. Architecture Justification: Why Modular Monolith?

MaintenX deliberately adopts a **Modular Monolith** architecture over microservices for several core reasons:

1. **Transactional Integrity & Consistency**: Facility maintenance domain invariants (e.g. assigning work orders to specific assets located in verified facility zones under an active tenant license) require strict relational integrity, atomic transactions, and ACID guarantees provided by PostgreSQL.
2. **Operational Simplicity**: Avoids distributed system pitfalls (distributed tracing overhead, network partitions, multi-service deployments, eventual consistency complexities) during foundational growth.
3. **Strict Domain Encapsulation**: Each domain module maintains its own Clean Architecture boundaries (Domain, Application, Infrastructure, Presentation) and exposes explicit interfaces (`IModule`). Modules do not query other modules' internal database tables directly; communication occurs via public domain interfaces or in-process domain events.
4. **Future Microservices Optionality**: Because module boundaries are strictly decoupled and domain-oriented, high-volume modules (e.g. IoT asset telemetry or real-time notification dispatches) can be extracted into standalone services if and when independent scaling demands it.

---

## 4. Planned Domain Module Boundaries

| Module | Core Responsibility | Key Entities |
|---|---|---|
| **Tenancy** | Organization provisioning, tenant isolation, subscription plans, users, roles & permissions. | `Tenant`, `User`, `Role`, `TenantSubscription` |
| **Facilities** | Multi-tier campus, building, floor, room, and zone management. | `Facility`, `Building`, `Floor`, `Zone` |
| **Assets** | Equipment catalog, serial tracking, warranty, maintenance logs, QR code generation. | `Asset`, `AssetCategory`, `WarrantyInfo` |
| **WorkOrders** | Reactive maintenance ticketing, priority assignment, SLA tracking, status workflows. | `WorkOrder`, `WorkOrderItem`, `TicketComment`, `LaborLog` |
| **MaintenanceSchedules** | Preventative & recurring maintenance calendars, automated ticket triggers. | `MaintenanceSchedule`, `RecurrenceRule`, `Checklist` |
| **Notifications** | Multi-channel dispatch (email, SMS, push) to technicians and property managers. | `NotificationTemplate`, `NotificationLog` |

---

## 5. Dependency Direction & Layering Rules

Each module strictly follows Clean Architecture:

```
[Presentation / API Controllers]
       │
       ▼
[Application Services / MediatR Handlers / DTOs]
       │
       ▼
[Domain Model / Aggregates / Value Objects / Domain Events]
       ▲
       │
[Infrastructure / EF Core DbContexts / External Adapters]
```

- **Domain Layer**: Has zero external package dependencies. Represents enterprise business rules.
- **Application Layer**: Orchestrates use cases, commands, and queries.
- **Infrastructure Layer**: Implements persistence via Entity Framework Core and PostgreSQL.
- **Presentation Layer**: Exposes strongly typed HTTP endpoints adhering to `/api/v{version}/{module}/{resource}` conventions.

---

## 6. Multi-Tenant Isolation Strategy

MaintenX enforces a **Shared Database, Separate Schemas / Row-Level Tenant Isolation** strategy:
- Every tenant-owned entity implements `ITenantEntity` with a required `TenantId (Guid)`.
- Global query filters in EF Core automatically enforce `WHERE TenantId = @CurrentTenantId` on all database reads and writes.
- Tenant ID is resolved securely from authenticated claims (JWT token claims) and verified server-side. Client-supplied tenant IDs are never trusted alone.

---

## 7. Authentication & Security Architecture

The authentication subsystem is implemented as a clean, decoupled bounded context in `MaintenX.Modules.Authentication` governing identity, credentials, sessions, and security audits. For comprehensive rationale, alternatives, and threat mitigations, see [ADR-0003: Authentication, Session Management, and Security Architecture](../adr/ADR-0003-authentication-security-architecture.md).

### 7.1 Layer Responsibilities

- **Presentation Layer (`AuthModule`)**: Minimal API endpoints mapped under `/api/v1/auth/` (`register`, `login`, `refresh`, `logout`, `change-password`). Enforces IP-based sliding-window rate limits for tracked clients (Registration: 5/min, Login: 10/min, Refresh: 30/min; 1-permit fixed-window fallback for unresolvable IPs), redacts sensitive input on DTOs, and returns uniform HTTP `401 Unauthorized` for all credential/lockout failures.
- **Application Layer (`IAuthenticationService`)**: Orchestrates authentication workflows within explicit EF Core execution strategy transactions, executes PBKDF2 password hashing outside database locks, enforces replay-precedence session family revocation, and coordinates security stamp validation.
- **Domain Layer (`User`, `UserSession`, `RefreshToken`, `SecurityAuditEvent`)**: Encapsulates invariants including 15-minute rolling lockout (after 5 failed attempts), single-use refresh token lineage (`ReplacedByTokenHash`), 30-day absolute session expiration, and structured security audit logging that excludes sensitive credentials while recording client IP for forensic tracking.
- **Infrastructure Layer (`EfUserSecurityStampStore`, `MaintenXDbContext`, `JwtTokenService`, `JwtKeyRing`)**: Provides PostgreSQL persistence, parameterized row-level locking (`SELECT ... FOR UPDATE`), HMAC-SHA256 JWT generation with 24-hour retired key retention, and scoped security stamp validation.

### 7.2 Token Refresh & Security Stamp Validation Workflow

```mermaid
sequenceDiagram
    autonumber
    actor Client as Web / Mobile Client
    participant API as API Host / AuthModule
    participant Cache as MemoryCache (Stamp TTL: 60s)
    participant AuthSvc as AuthenticationService
    participant DB as PostgreSQL 16 (platform schema)

    Note over Client,API: 1. Token Refresh Flow (Pessimistic Row Lock)
    Client->>API: POST /api/v1/auth/refresh { refreshToken }
    API->>AuthSvc: RefreshTokensAsync(rawToken, clientIp)
    AuthSvc->>DB: BEGIN Transaction (ReadCommitted)
    AuthSvc->>DB: SELECT * FROM user_sessions WHERE id = @id FOR UPDATE
    AuthSvc->>DB: Query & Validate Refresh Token (Replay Check First)
    AuthSvc->>DB: Revoke Old Token, Insert New Token Hash, Update Session
    AuthSvc->>DB: Insert SecurityAuditEvent (TokenRefreshed)
    AuthSvc->>DB: COMMIT Transaction
    AuthSvc-->>API: Issue new 15-min JWT + 7-day Refresh Token
    API-->>Client: 200 OK { accessToken, refreshToken, expiresIn }

    Note over Client,API: 2. Authenticated Request & Security Stamp Validation
    Client->>API: GET /api/v1/protected-resource (Authorization: Bearer <JWT>)
    API->>API: Validate JWT Signature (IJwtKeyRing)
    API->>Cache: Check Cached Security Stamp (userId)
    alt Cache Miss
        API->>DB: Query User Status & Security Stamp
        DB-->>API: Return User Record
        API->>Cache: Cache Stamp (60s Absolute Expiration)
    end
    alt Stamp Valid & User Active
        API-->>Client: Process Request & Return 200 OK
    else Stamp Mismatched or User Suspended
        API-->>Client: 401 Unauthorized
    end
```

### 7.3 Concurrency Control & Replay Protection

- **Pessimistic Row Locking**: All refresh token exchanges lock the parent session record via `SELECT ... FOR UPDATE` within a `READ COMMITTED` transaction. Hierarchical lock acquisition strictly follows $\text{User} \rightarrow \text{UserSession} \rightarrow \text{RefreshToken}$ to eliminate database deadlock risk.
- **Immediate Replay Revocation**: When an already-rotated refresh token hash is presented, replay attack logic immediately revokes the entire parent session (`TokenReplayDetected`), cancels all active child refresh tokens, and writes a permanent security audit record.
- **Security Stamp Invalidation**: Rotating a user's security stamp (triggered by password change, administrative reset, suspension, reactivation, or deactivation) invalidates all existing JWT access tokens upon local cache eviction or within 60 seconds across all nodes. Single session logout revokes the specific session and its refresh tokens without mutating the global security stamp.
- **Audit Persistence vs Retention**: Security audit events are persisted append-only in `platform.security_audit_events` with JSONB metadata. Immutability is enforced at domain and application levels (no update/delete methods in domain or service layers; database-level append-only triggers are not currently configured). Database persistence is durable and non-cascading; automated event retention purges are governed by operational archival policies rather than runtime deletion jobs.
- **Known Multi-Instance Scaling Considerations**: In-memory rate limiting and the 60-second in-memory security stamp cache operate per-node. Horizontal clustering across multiple containers will introduce Redis for distributed sliding-window rate limiting and distributed stamp invalidation (see [ADR-0003 Section 5](../adr/ADR-0003-authentication-security-architecture.md#5-multi-instance-operational-limitations--future-scale-out)).

---

## 8. Development & Deployment Topology

- **Local Development**:
  - PostgreSQL container running via Docker Compose (`docker-compose up -d postgres`)
  - ASP.NET Core API running locally or containerized on port `5000`
  - Next.js web application running locally on port `3000`
  - Flutter mobile client running on Android/iOS emulators or devices
- **Production Deployment**:
  - Managed PostgreSQL instance with automated backups and read-replicas
  - Containerized ASP.NET Core API deployment running on Linux containers
  - Next.js deployed via Node.js container or edge infrastructure
  - Automated CI/CD pipeline via GitHub Actions for building, testing, linting, and vulnerability scanning.

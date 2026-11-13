# Architecture Decision Record: ADR-0002

## Selection of PostgreSQL 16 and Entity Framework Core 10 for SaaS Persistence

- **Status**: Accepted
- **Deciders**: Principal .NET Backend Architect, PostgreSQL Database Architect, Senior DevOps Engineer
- **Date**: 2026-11-13
- **Feature**: FEAT-001 — PostgreSQL Database Foundation

---

### 1. Context & Problem Statement

MaintenX is a multi-tenant facility maintenance SaaS platform requiring relational data consistency, transactional integrity for work order workflows, asset tracking, and strict tenant isolation. The persistence foundation must support:
- ACID-compliant data storage as the single source of truth.
- Schema evolution through auditable, version-controlled migrations.
- High performance, connection pooling, and optimistic concurrency.
- First-class compatibility with .NET 10 LTS and cloud-native containerized hosting.

---

### 2. Considered Alternatives

1. **Alternative 1: PostgreSQL 16 + Entity Framework Core 10 (Selected)**
2. **Alternative 2: PostgreSQL 16 + Dapper / Raw SQL (Micro-ORM)**
3. **Alternative 3: MongoDB / Document Database**
4. **Alternative 4: Microsoft SQL Server + EF Core**

---

### 3. Decision Outcome

**Chosen Option: PostgreSQL 16 + Entity Framework Core 10 (via Npgsql provider).**

#### Rationale:

1. **Relational Invariants**: Facility maintenance domains are inherently relational (Campuses &rarr; Buildings &rarr; Floors &rarr; Zones &rarr; Assets &rarr; Work Orders). Document stores like MongoDB risk data inconsistency, orphaned references, and lack declarative foreign key integrity across organizations.
2. **PostgreSQL Open Source & Cost Efficiency**: PostgreSQL offers enterprise-grade JSONB capabilities, UUID generation, full-text search, and row-level security without proprietary vendor lock-in or licensing fees required by Microsoft SQL Server or Oracle.
3. **EF Core 10 LTS Alignment**: EF Core 10 delivers state-of-the-art query translation, native AOT compatibility, compile-time model generation, automatic migration tracking, and robust optimistic concurrency support.
4. **Npgsql Ecosystem Maturity**: The Npgsql EF Core provider is one of the most mature, high-performance database providers in the .NET ecosystem, offering native mapping for PostgreSQL UUIDs, timestamptz, schemas, and connection resiliency (`EnableRetryOnFailure`).
5. **Separation of Infrastructure**: Clean Architecture boundaries ensure that domain models remain pure C# aggregates without database dependencies, while EF Core configurations in the infrastructure layer map them cleanly to snake_case tables and columns.

---

### 4. Consequences & Trade-offs

#### Positive:
- **Unified Source of Truth**: Centralized, ACID-compliant database for all domain modules in the modular monolith.
- **Strong Typing & Safety**: Compile-time type safety across queries and schema configurations.
- **Auditable Migrations**: Schema changes are code-reviewed via C# migration classes and idempotent SQL scripts.
- **Connection Resiliency**: Automated transient retry logic prevents service disruption during minor network blips.

#### Negative / Mitigations:
- **ORM Complexity**: Improperly written LINQ queries can result in N+1 query execution. *Mitigation*: Integration tests with query logging, explicit eager loading (`Include`), and query split techniques will be enforced.
- **Production Migrations**: Running migrations automatically on app startup causes race conditions in multi-instance deployments. *Mitigation*: Application startup auto-migration is strictly forbidden; migrations are executed via reviewed deployment scripts or migration bundles.

---

### 5. Compliance Rules

- All timestamps must be stored in UTC (`timestamp with time zone`).
- All primary keys for domain entities must be UUID (`uuid`).
- All table and column names must adhere to `snake_case`.
- Tables must be partitioned into explicit schemas (`platform` for core multi-tenancy, and domain-specific schemas for future modules).
- Optimistic concurrency must be enforced on mutable root entities using a version token.
- Tenant slugs must be normalized lowercase strings conforming to `^[a-z0-9]+(-[a-z0-9]+)*$` and enforced via database check constraints (`ck_tenants_slug`).
- Automated integration tests must run exclusively against isolated disposable databases prefixed with `maintenx_test_` and never against development or production databases.
- Design-time factories and configuration services must fail fast if connection strings are omitted, with zero hardcoded credential fallbacks in source code.

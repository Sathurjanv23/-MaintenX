# Feature Record: FEAT-001 — PostgreSQL Database Foundation

## 1. Feature Metadata
- **Task ID**: FEAT-001
- **Task Name**: PostgreSQL Database Foundation
- **Branch**: `feat/001-database-foundation`
- **Status**: Implemented & Verified
- **Target Framework**: .NET 10 LTS (`net10.0`)
- **Database Engine**: PostgreSQL 16 Alpine
- **ORM / Provider**: Entity Framework Core 10 (`Microsoft.EntityFrameworkCore` 10.0.0, `Npgsql.EntityFrameworkCore.PostgreSQL` 10.0.0)

---

## 2. Summary of Implementation

Built the production-grade PostgreSQL persistence foundation for the MaintenX SaaS platform modular monolith without premature business feature creep.

### Key Deliverables:
1. **EF Core 10 & PostgreSQL Infrastructure**:
   - Integrated `Microsoft.EntityFrameworkCore` 10.0.0, `Microsoft.EntityFrameworkCore.Design` 10.0.0, and `Npgsql.EntityFrameworkCore.PostgreSQL` 10.0.0 into `MaintenX.Api` and `MaintenX.IntegrationTests`.
   - Created `MaintenXDbContext` configured with `platform` default schema, automatic assembly configuration discovery, automatic UTC auditing (`CreatedAtUtc`, `UpdatedAtUtc`), and optimistic concurrency token increments.
   - Implemented `DatabaseServiceExtensions.AddMaintenXPersistence` with connection pooling, command timeouts, and connection resiliency (`EnableRetryOnFailure`).
   - Implemented `MaintenXDesignTimeDbContextFactory` enabling `dotnet-ef` migration generation and inspection outside the running application host.
2. **Foundational Tenant Catalog Entity**:
   - Defined `Tenant` aggregate root in `Domain/Tenants/Tenant.cs` and `TenantStatus` in `Domain/Tenants/TenantStatus.cs`.
   - Mapped to `platform.tenants` with `pk_tenants`, unique index `ix_tenants_slug`, check constraint `ck_tenants_status`, and optimistic concurrency token `version` (`bigint`).
   - Pure domain model without framework package dependencies.
3. **Database Migration & Idempotent SQL**:
   - Generated initial EF Core migration `20261113000000_InitialDatabaseFoundation`.
   - Generated and verified idempotent SQL migration script: `docs/migrations/0001_initial_database_foundation.sql`.
   - Verified that normal API startup does not silently auto-migrate the database.
4. **Comprehensive Real PostgreSQL Integration Tests**:
   - Implemented `DatabaseFoundationIntegrationTests` covering test cases DB-001 through DB-012.
   - Tested against real containerized PostgreSQL 16 (not InMemory provider).
   - Verified clean database migration from scratch using disposable temporary databases (`DB011`).

---

## 3. Test Evidence Matrix

| Test ID | Test Name | Target Invariant | Result |
|---|---|---|---|
| **DB-001** | `DB001_DbContext_ResolvesFromDependencyInjection` | DI resolution and live connection verification | **PASSED** |
| **DB-002** | `DB002_InitialMigration_AppliesSuccessfully` | EF Core migration discovery and execution | **PASSED** |
| **DB-003** | `DB003_Tenant_CanBePersistedAndRetrieved` | Entity CRUD round-trip persistence | **PASSED** |
| **DB-004** | `DB004_DuplicateNormalizedSlug_IsRejected` | Unique slug index and normalization constraint | **PASSED** |
| **DB-005** | `DB005_RequiredDatabaseConstraints_AreEnforced` | Check constraint `ck_tenants_status` enforcement | **PASSED** |
| **DB-006** | `DB006_UuidKeys_PersistCorrectly` | UUID primary key persistence and retrieval | **PASSED** |
| **DB-007** | `DB007_UtcTimestamps_RoundTripCorrectly` | Strict UTC timestamping and millisecond accuracy | **PASSED** |
| **DB-008** | `DB008_OptimisticConcurrencyConflict_IsDetected` | Concurrency conflict detection (`DbUpdateConcurrencyException`) | **PASSED** |
| **DB-009** | `DB009_MigrationHistory_IsPresent` | Schema history recorded in `platform.__EFMigrationsHistory` | **PASSED** |
| **DB-010** | `DB010_ApplyingMigrationsAgain_IsSafe` | Migration re-application safety and idempotency | **PASSED** |
| **DB-011** | `DB011_NewDatabase_CanBeInitializedUsingCommittedMigrations` | Clean database provisioning from committed migrations | **PASSED** |
| **DB-012** | `DB012_PersistenceFailures_DoNotExposeConnectionStringsOrCredentials` | Information disclosure prevention on database failure | **PASSED** |

---

## 4. Known Limitations & Future Work

- **Multi-Tenancy Isolation**: Multi-tenancy authorization and automated row-level filters (`WHERE tenant_id = @current_tenant`) are explicitly scheduled for **FEAT-003: Multi-Tenancy**. FEAT-001 establishes only the root catalog table (`platform.tenants`).
- **No Public CRUD Endpoints**: Public tenant onboarding and management REST endpoints are scheduled for future features to ensure proper authentication (FEAT-002) and authorization guards (FEAT-004) are in place first.

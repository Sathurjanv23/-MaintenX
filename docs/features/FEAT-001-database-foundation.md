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
   - Implemented `MaintenXDesignTimeDbContextFactory` enabling `dotnet-ef` migration generation and inspection outside the running application host, with fail-fast validation when connection strings are omitted and zero hardcoded credentials.
2. **Foundational Tenant Catalog Entity**:
   - Defined `Tenant` aggregate root in `Domain/Tenants/Tenant.cs` and `TenantStatus` in `Domain/Tenants/TenantStatus.cs`.
   - Mapped to `platform.tenants` with `pk_tenants`, unique index `ix_tenants_slug`, check constraints `ck_tenants_status` and `ck_tenants_slug`, and optimistic concurrency token `version` (`bigint`).
   - Implemented domain-level slug validation and normalization (`NormalizeAndValidateSlug`), enforcing lowercase alphanumeric characters and single internal hyphens between words.
3. **Database Migration & Idempotent SQL**:
   - Committed initial EF Core migration `20261113000000_InitialDatabaseFoundation`.
   - Committed additive safe migration `20261113000001_HardenTenantSlugConstraints` adding `ck_tenants_slug`.
   - Generated and verified idempotent SQL migration scripts: `docs/migrations/0001_initial_database_foundation.sql` and `docs/migrations/0002_harden_tenant_slug_constraints.sql`.
   - Verified that normal API startup does not silently auto-migrate the database.
4. **Comprehensive Real PostgreSQL Integration Tests with Strict Isolation & Security**:
   - Implemented `DatabaseFoundationIntegrationTests` running strictly against an isolated disposable database (`maintenx_test_*`).
   - Created safety guard `EnsureSafeTestDatabaseName()` preventing mutation, truncation, or dropping of protected databases (`maintenx_dev`, `maintenx_prod`, `maintenx_staging`, `postgres`, `template1`).
   - Hardened credential separation between administrative maintenance operations (`AdminConnection` / maintenance database `postgres`) and application operations (`DefaultConnection` / `TestConnection`), with fail-fast validation when missing and zero hardcoded credentials in test code.
   - Guaranteed resilient cleanup: immediate drop of disposable database if setup fails, and visible error reporting with re-throw on teardown failure.
   - Added exhaustive slug validation tests (`acme`, `ACME`, `acme-facility`, leading/trailing whitespace rejection, invalid characters, length bounds, duplicate normalized values).
   - Implemented automated migration upgrade test (`DB014`) demonstrating safe non-destructive migration from `0001` to `0002` while preserving existing customer tenant data.
   - Separated low-level driver credential protection (`DB012`) from public HTTP API disclosure protection (`DB013`).

---

## 3. Test Evidence Matrix

| Test ID | Test Name | Target Invariant | Result |
|---|---|---|---|
| **DB-001** | `DB001_DbContext_ResolvesFromDependencyInjection` | DI resolution and live connection verification on isolated test DB | **PASSED** |
| **DB-002** | `DB002_InitialAndAdditiveMigrations_ApplySuccessfully` | EF Core migration discovery and execution (both initial & additive) | **PASSED** |
| **DB-003** | `DB003_Tenant_CanBePersistedAndRetrieved` | Entity CRUD round-trip persistence | **PASSED** |
| **DB-004** | `DB004_DuplicateNormalizedSlug_IsRejected` | Unique slug index and normalization constraint | **PASSED** |
| **DB-005a**| `DB005_TenantSlug_DatabaseCheckConstraint_EnforcesInvariants` | PostgreSQL `ck_tenants_slug` regex check constraint | **PASSED** |
| **DB-005b**| `DB005_TenantSlug_DomainFactory_EnforcesValidationAndNormalization` | Domain factory validation and normalization invariants (rejection of whitespace, case normalization, length 2-100) | **PASSED** |
| **DB-006** | `DB006_UuidKeys_PersistCorrectly` | UUID primary key persistence and retrieval | **PASSED** |
| **DB-007** | `DB007_UtcTimestamps_RoundTripCorrectly` | Strict UTC timestamping and millisecond accuracy | **PASSED** |
| **DB-008** | `DB008_OptimisticConcurrencyConflict_IsDetected` | Concurrency conflict detection (`DbUpdateConcurrencyException`) | **PASSED** |
| **DB-009** | `DB009_MigrationHistory_IsPresent` | Schema history recorded in `platform.__EFMigrationsHistory` | **PASSED** |
| **DB-010** | `DB010_ApplyingMigrationsAgain_IsSafe` | Migration re-application safety and idempotency | **PASSED** |
| **DB-011** | `DB011_NewDatabase_CanBeInitializedUsingCommittedMigrations` | Clean database provisioning from committed migrations using admin credentials | **PASSED** |
| **DB-012** | `DB012_DatabaseDriverException_DoesNotExposeSensitiveCredentials` | Driver/ADO.NET exception credential sanitization | **PASSED** |
| **DB-013** | `DB013_PublicHealthApiEndpoint_WhenDatabaseFails_DoesNotExposeConnectionDetails` | Public HTTP API error disclosure prevention | **PASSED** |
| **DB-014** | `DB014_MigrationUpgrade_PreservesExistingDataAndAppliesSlugConstraint` | Automated upgrade test verifying data survival from migration 0001 to 0002 and enforcement of `ck_tenants_slug` | **PASSED** |
| **DB-015** | `DB015_ConfigurationGuard_RejectsMissingAdminOrTestConnection` | Configuration guard rejects missing admin or test connections without falling back to default | **PASSED** |
| **DB-016** | `DB016_ConfigurationGuard_RejectsUnapprovedHostOrDisabledOptIn` | Fail-closed host allowlist validation (rejects missing, empty, unapproved admin/test hosts) and verifies explicit opt-in requirement | **PASSED** |
| **DB-017** | `DB017_RoleSeparation_ApplicationRole_IsNotSuperuserAndCannotCreateDatabase` | Proves application role has `rolsuper=false`, `rolcreatedb=false`, and `CREATE DATABASE` is denied | **PASSED** |
| **DB-018** | `DB018_RoleSeparation_ApplicationRole_CanManageSchemaAndMigrateOwnedDatabase` | Proves application role can manage schemas and execute DDL in its owned disposable database | **PASSED** |
| **DB-019** | `DB019_SafeCleanup_CleansUpOnSetupFailure` | Proves emergency teardown reliably drops database when setup fails | **PASSED** |
| **DB-020** | `DB020_FixtureInitializationFailure_GuaranteesDatabaseCleanupAndSurfacesError` | Proves real fixture initialization path creates DB, cleans up on post-provision failure, surfaces error to runner, and leaves zero DBs behind | **PASSED** |
| **DB-021** | `DB021_RolePassword_WithApostrophesAndSpecialCharacters_CanAuthenticate` | Proves passwords containing apostrophes, backslashes, dollar signs, semicolons and quotes work and authenticate via dynamic format(%I, %L) | **PASSED** |
| **DB-022** | `DB022_InitRolesScript_IdentifierValidation_EnforcesPostgreSqlIdentifierRules` | Proves role and database identifier allowlist regex strictly accepts valid names and rejects invalid names or SQL injection attempts | **PASSED** |
| **DB-023** | `DB023_HostAllowlist_SupportsBothSemicolonAndCommaDelimiters` | Proves TestDatabase:AllowedHosts parses both semicolon and comma delimiters consistently | **PASSED** |

---

## 4. Known Limitations & Future Work

- **Multi-Tenancy Isolation**: Multi-tenancy authorization and automated row-level filters (`WHERE tenant_id = @current_tenant`) are explicitly scheduled for **FEAT-003: Multi-Tenancy**. FEAT-001 establishes only the root catalog table (`platform.tenants`).
- **No Public CRUD Endpoints**: Public tenant onboarding and management REST endpoints are scheduled for future features to ensure proper authentication (FEAT-002) and authorization guards (FEAT-004) are in place first.

-- ==============================================================================
-- MaintenX Database Migration: 0001_initial_database_foundation.sql
-- Description: Idempotent SQL script creating the 'platform' schema, 
--              '__EFMigrationsHistory' table, and 'platform.tenants' catalog table.
-- ==============================================================================

-- 1. Ensure platform schema exists
CREATE SCHEMA IF NOT EXISTS platform;

-- 2. Ensure EF Core Migration History table exists in platform schema
CREATE TABLE IF NOT EXISTS platform."__EFMigrationsHistory" (
    "MigrationId" character varying(150) NOT NULL,
    "ProductVersion" character varying(32) NOT NULL,
    CONSTRAINT "PK___EFMigrationsHistory" PRIMARY KEY ("MigrationId")
);

-- 3. Execute migration block safely and idempotently
DO $EF$
BEGIN
    IF NOT EXISTS(SELECT 1 FROM platform."__EFMigrationsHistory" WHERE "MigrationId" = '20261113000000_InitialDatabaseFoundation') THEN

        -- Create platform.tenants table
        CREATE TABLE platform.tenants (
            id uuid NOT NULL,
            slug character varying(100) NOT NULL,
            display_name character varying(200) NOT NULL,
            status character varying(50) NOT NULL,
            created_at_utc timestamp with time zone NOT NULL,
            updated_at_utc timestamp with time zone NOT NULL,
            version bigint NOT NULL,
            CONSTRAINT pk_tenants PRIMARY KEY (id),
            CONSTRAINT ck_tenants_status CHECK (status IN ('Active', 'Suspended', 'PendingOnboarding', 'Deactivated'))
        );

        -- Create unique index on normalized slug
        CREATE UNIQUE INDEX ix_tenants_slug ON platform.tenants (slug);

        -- Record migration completion in history table
        INSERT INTO platform."__EFMigrationsHistory" ("MigrationId", "ProductVersion")
        VALUES ('20261113000000_InitialDatabaseFoundation', '10.0.0');

    END IF;
END $EF$;

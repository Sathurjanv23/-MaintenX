-- ==============================================================================
-- MaintenX Database Migration: 0002_harden_tenant_slug_constraints.sql
-- Description: Idempotent migration adding the ck_tenants_slug check constraint
--              to platform.tenants table. Enforces lowercase alphanumeric and
--              single hyphen slug patterns, with length between 2 and 100.
-- ==============================================================================

DO $EF$
BEGIN
    IF NOT EXISTS(SELECT 1 FROM platform."__EFMigrationsHistory" WHERE "MigrationId" = '20261113000001_HardenTenantSlugConstraints') THEN

        -- Add check constraint for normalized slug pattern and length
        ALTER TABLE platform.tenants
        ADD CONSTRAINT ck_tenants_slug
        CHECK (slug ~ '^[a-z0-9]+(-[a-z0-9]+)*$' AND length(slug) >= 2 AND length(slug) <= 100);

        -- Record migration completion in history table
        INSERT INTO platform."__EFMigrationsHistory" ("MigrationId", "ProductVersion")
        VALUES ('20261113000001_HardenTenantSlugConstraints', '10.0.0');

    END IF;
END $EF$;

-- MaintenX PostgreSQL Role Initialization
-- Ensures separate administrator and restricted application roles

DO $$
BEGIN
    IF NOT EXISTS (SELECT FROM pg_catalog.pg_roles WHERE rolname = 'maintenx_app') THEN
        CREATE ROLE maintenx_app WITH LOGIN PASSWORD 'maintenx_dev_password_change_in_prod' NOSUPERUSER NOCREATEDB;
    END IF;
END
$$;

-- Create default development database owned by maintenx_app if not exists
SELECT 'CREATE DATABASE maintenx_dev OWNER maintenx_app'
WHERE NOT EXISTS (SELECT FROM pg_database WHERE datname = 'maintenx_dev')\gexec

GRANT ALL PRIVILEGES ON DATABASE maintenx_dev TO maintenx_app;


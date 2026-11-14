#!/bin/sh
set -eu

# MaintenX PostgreSQL Application Role and Database Initialization
# Dynamically configures the restricted application role from environment variables.

APP_USER="${POSTGRES_APP_USER:-maintenx_app}"
APP_PASS="${POSTGRES_APP_PASSWORD:-}"
APP_DB="${POSTGRES_APP_DB:-maintenx_dev}"

if [ -z "$APP_PASS" ]; then
    echo "================================================================================" >&2
    echo "CRITICAL CONFIGURATION ERROR: POSTGRES_APP_PASSWORD is not set." >&2
    echo "A secure password must be supplied via POSTGRES_APP_PASSWORD in your .env file." >&2
    echo "================================================================================" >&2
    exit 1
fi

psql -v ON_ERROR_STOP=1 --username "$POSTGRES_USER" --dbname "$POSTGRES_DB" <<-EOSQL
    DO \$\$
    BEGIN
        IF NOT EXISTS (SELECT FROM pg_catalog.pg_roles WHERE rolname = '$APP_USER') THEN
            CREATE ROLE "$APP_USER" WITH LOGIN PASSWORD '$APP_PASS' NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT;
        ELSE
            ALTER ROLE "$APP_USER" WITH PASSWORD '$APP_PASS';
        END IF;
    END
    \$\$;

    SELECT 'CREATE DATABASE "$APP_DB" OWNER "$APP_USER"'
    WHERE NOT EXISTS (SELECT FROM pg_database WHERE datname = '$APP_DB')\gexec

    GRANT ALL PRIVILEGES ON DATABASE "$APP_DB" TO "$APP_USER";
EOSQL

echo "MaintenX: Application role '$APP_USER' and database '$APP_DB' initialized successfully."

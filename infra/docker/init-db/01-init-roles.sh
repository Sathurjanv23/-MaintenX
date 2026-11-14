#!/bin/sh
set -eu

# MaintenX PostgreSQL Application Role and Database Initialization
# Dynamically configures the restricted application role from environment variables.
# Strictly validates identifiers and safely passes credentials without SQL injection or log leakage.

APP_USER="${POSTGRES_APP_USER:-maintenx_app}"
APP_PASS="${POSTGRES_APP_PASSWORD:-}"
APP_DB="${POSTGRES_APP_DB:-maintenx_dev}"

# 1. Require POSTGRES_APP_PASSWORD
if [ -z "$APP_PASS" ]; then
    echo "================================================================================" >&2
    echo "CRITICAL CONFIGURATION ERROR: POSTGRES_APP_PASSWORD is not set." >&2
    echo "A secure password must be supplied via POSTGRES_APP_PASSWORD in your .env file." >&2
    echo "================================================================================" >&2
    exit 1
fi

# 2. Strict identifier validation against PostgreSQL standard identifier rules
# Letters or underscore followed by letters, digits, or underscores (max 63 characters).
IDENTIFIER_REGEX='^[a-zA-Z_][a-zA-Z0-9_]{0,62}$'

validate_identifier() {
    name="$1"
    val="$2"
    if ! echo "$val" | grep -Eq "$IDENTIFIER_REGEX"; then
        echo "CRITICAL CONFIGURATION ERROR: Invalid $name '$val'." >&2
        echo "Identifiers must match regex: $IDENTIFIER_REGEX" >&2
        exit 1
    fi
}

validate_identifier "POSTGRES_APP_USER" "$APP_USER"
validate_identifier "POSTGRES_APP_DB" "$APP_DB"

# Export sanitized variables to child process environment for psql \getenv
export POSTGRES_APP_USER="$APP_USER"
export POSTGRES_APP_PASSWORD="$APP_PASS"
export POSTGRES_APP_DB="$APP_DB"

# 3. Execute initialization via psql using \getenv, psql literal escaping, and format(%I, %L)
# Quoted heredoc <<'EOSQL' guarantees zero shell interpolation into SQL statements.
psql -v ON_ERROR_STOP=1 --username "$POSTGRES_USER" --dbname "$POSTGRES_DB" <<'EOSQL'
\getenv app_user POSTGRES_APP_USER
\getenv app_pass POSTGRES_APP_PASSWORD
\getenv app_db   POSTGRES_APP_DB

-- Set temporary session settings using psql's :'var' literal quoting
SET maintenx.app_user = :'app_user';
SET maintenx.app_pass = :'app_pass';
SET maintenx.app_db   = :'app_db';

-- 1. Create or alter restricted application role with strict privilege restrictions
DO $$
DECLARE
    v_user text := current_setting('maintenx.app_user');
    v_pass text := current_setting('maintenx.app_pass');
BEGIN
    IF NOT EXISTS (SELECT FROM pg_catalog.pg_roles WHERE rolname = v_user) THEN
        EXECUTE format('CREATE ROLE %I WITH LOGIN PASSWORD %L NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT', v_user, v_pass);
    ELSE
        EXECUTE format('ALTER ROLE %I WITH PASSWORD %L', v_user, v_pass);
    END IF;
END
$$;

-- 2. Conditionally create application database owned by the restricted application role
SELECT format('CREATE DATABASE %I OWNER %I', current_setting('maintenx.app_db'), current_setting('maintenx.app_user'))
WHERE NOT EXISTS (
    SELECT FROM pg_database WHERE datname = current_setting('maintenx.app_db')
)\gexec

-- 3. Grant full privileges on the database to the application role
SELECT format('GRANT ALL PRIVILEGES ON DATABASE %I TO %I', current_setting('maintenx.app_db'), current_setting('maintenx.app_user'))\gexec

-- Clear session variables to ensure credentials do not remain in session state
RESET maintenx.app_user;
RESET maintenx.app_pass;
RESET maintenx.app_db;
EOSQL

echo "MaintenX: Application role '$APP_USER' and database '$APP_DB' initialized successfully."

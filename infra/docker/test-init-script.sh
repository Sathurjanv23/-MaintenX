#!/bin/sh
set -eu

echo "=== MaintenX PostgreSQL Init Script Test Suite ==="

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
LOCAL_INIT_DIR="$SCRIPT_DIR/init-db"
HOST_INIT_DIR="${HOST_INIT_DIR:-$LOCAL_INIT_DIR}"

# 1. Verify file mode
if [ ! -x "$LOCAL_INIT_DIR/01-init-roles.sh" ]; then
    echo "ERROR: $LOCAL_INIT_DIR/01-init-roles.sh is not executable." >&2
    exit 1
fi
echo "✓ Executable mode verified."

# 2. Test successful initialization with apostrophes and SQL-special characters
CONTAINER="pg-test-init-$(date +%s)-$RANDOM"
TEST_PASS="p'a\"\\\$w;--ord!#%&"

echo "Starting disposable PostgreSQL container..."
docker run -d --name "$CONTAINER" \
    -e POSTGRES_PASSWORD=adminpass \
    -e POSTGRES_APP_USER=maintenx_app \
    -e POSTGRES_APP_DB=maintenx_dev \
    -e "POSTGRES_APP_PASSWORD=$TEST_PASS" \
    -v "$HOST_INIT_DIR:/docker-entrypoint-initdb.d:ro" \
    postgres:16-alpine

# Wait for server readiness
for i in $(seq 1 30); do
    if docker exec "$CONTAINER" pg_isready -U postgres -d postgres >/dev/null 2>&1; then
        break
    fi
    sleep 1
done

# Check logs for secret leakage
LOGS=$(docker logs "$CONTAINER" 2>&1)
if echo "$LOGS" | grep -F "p'a"; then
    echo "ERROR: Password was exposed in container logs!" >&2
    docker rm -f "$CONTAINER"
    exit 1
fi
echo "✓ No credentials leaked in logs."

# Verify role can authenticate with complex password
docker exec -e "PGPASSWORD=$TEST_PASS" "$CONTAINER" psql -U maintenx_app -d maintenx_dev -c "SELECT current_user, current_database();" >/dev/null
echo "✓ Application role authenticated successfully with complex password."

# Verify role restrictions
ROLE_FLAGS=$(docker exec "$CONTAINER" psql -U postgres -d postgres -t -A -c "SELECT rolsuper || ',' || rolcreatedb || ',' || rolcreaterole || ',' || rolinherit FROM pg_roles WHERE rolname = 'maintenx_app';")
if [ "$ROLE_FLAGS" != "false,false,false,false" ] && [ "$ROLE_FLAGS" != "f,f,f,f" ]; then
    echo "ERROR: Role permissions invalid: expected false,false,false,false but got $ROLE_FLAGS" >&2
    docker rm -f "$CONTAINER"
    exit 1
fi
echo "✓ Role permissions strictly verified: NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT."

# Verify database ownership
DB_OWNER=$(docker exec "$CONTAINER" psql -U postgres -d postgres -t -A -c "SELECT r.rolname FROM pg_database d JOIN pg_roles r ON d.datdba = r.oid WHERE d.datname = 'maintenx_dev';")
if [ "$DB_OWNER" != "maintenx_app" ]; then
    echo "ERROR: Database owner invalid: expected maintenx_app but got $DB_OWNER" >&2
    docker rm -f "$CONTAINER"
    exit 1
fi
echo "✓ Database ownership verified: maintenx_dev owned by maintenx_app."

docker rm -f "$CONTAINER" >/dev/null
echo "✓ Disposable container cleaned up."

# 3. Test invalid role name rejection
OUTPUT=$(docker run --rm -e POSTGRES_PASSWORD=adminpass -e "POSTGRES_APP_USER=bad;user" -e POSTGRES_APP_PASSWORD=anypass -v "$HOST_INIT_DIR:/docker-entrypoint-initdb.d:ro" postgres:16-alpine 2>&1 || true)
if echo "$OUTPUT" | grep -q "Invalid POSTGRES_APP_USER"; then
    echo "✓ Invalid role name properly rejected."
else
    echo "ERROR: Invalid role name was not rejected! Output:" >&2
    echo "$OUTPUT" >&2
    exit 1
fi

# 4. Test invalid database name rejection
OUTPUT=$(docker run --rm -e POSTGRES_PASSWORD=adminpass -e POSTGRES_APP_USER=maintenx_app -e "POSTGRES_APP_DB=bad;db" -e POSTGRES_APP_PASSWORD=anypass -v "$HOST_INIT_DIR:/docker-entrypoint-initdb.d:ro" postgres:16-alpine 2>&1 || true)
if echo "$OUTPUT" | grep -q "Invalid POSTGRES_APP_DB"; then
    echo "✓ Invalid database name properly rejected."
else
    echo "ERROR: Invalid database name was not rejected! Output:" >&2
    echo "$OUTPUT" >&2
    exit 1
fi

echo "=== All PostgreSQL Init Script Tests Passed Successfully ==="

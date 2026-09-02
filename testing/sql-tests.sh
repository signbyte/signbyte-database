#!/usr/bin/env bash
# SQL quality gate — the deep test layer, one mechanism for local dev AND CI:
#   1. build a plpgsql_check-capable Postgres (stock images don't ship it)
#   2. provision the full role superset (throwaway, generated passwords)
#   3. apply ALL schema locations into one database via the migration image
#      (the same image deployments run)
#   4. run every SQL unit test (migrations/testing/tests/unit.*.sql)
#   5. run every role-leak acceptance (migrations/testing/roleleak.*.sql)
#   6. plpgsql_check static analysis over every procedure; any 'error'-level
#      finding fails the run (testing/check-linter-error-steps.sh)
#
# Needs Docker only. Container paths stay inside sh -c bodies / colon forms so
# the script runs identically from Git Bash (Windows) and any Linux shell.
set -euo pipefail
cd "$(dirname "$0")/.."

NET=platformdb-sqltest-net
PG=platformdb-sqltest-pg
IMG=platform-migrate:sqltest
PGDEV=platformdb-pgdev:local
PW=sqltestpw
DB=platform

# Every location and every role any deployment shape declares, read from
# testing/deployments.conf. Dependency order: util first, grants last, the rest
# in order of first appearance.
SHAPES=$(grep -v '^#' testing/deployments.conf | grep -v '^[[:space:]]*$')
[ -n "$SHAPES" ] || { echo "FATAL: testing/deployments.conf declares no deployment shape" >&2; exit 1; }
union() { printf '%s\n' "$SHAPES" | cut -d'|' -f"$1" | tr ' ' '\n' | grep -v '^$' | awk '!seen[$0]++' | tr '\n' ' '; }
ALL_LOCATIONS="util $(union 2 | tr ' ' '\n' | grep -vx 'util' | grep -vx 'grants' | tr '\n' ' ')grants"
ROLES=$(for r in $(union 3); do printf '%s:RPW ' "$r"; done)
HUMAN_READ=$(union 4)
HUMAN_WRITE=$(union 5)

cleanup() {
  docker rm -f "$PG" >/dev/null 2>&1 || true
  docker network rm "$NET" >/dev/null 2>&1 || true
}
trap cleanup EXIT
cleanup

echo "== build a plpgsql_check-capable Postgres"
docker build -q -t "$PGDEV" - >/dev/null <<'EOF'
FROM postgres:17
RUN apt-get update \
  && apt-get install -y --no-install-recommends postgresql-17-plpgsql-check \
  && rm -rf /var/lib/apt/lists/*
EOF

echo "== build the migration image"
docker build -q -f Dockerfile.migrate -t "$IMG" . >/dev/null

echo "== throwaway postgres (plpgsql_check-capable)"
docker network create "$NET" >/dev/null
docker run -d --name "$PG" --network "$NET" \
  -e POSTGRES_USER=platform -e POSTGRES_PASSWORD="$PW" -e POSTGRES_DB="$DB" \
  "$PGDEV" >/dev/null
for i in $(seq 1 60); do
  docker exec "$PG" pg_isready -h 127.0.0.1 -U platform >/dev/null 2>&1 && break
  sleep 1
  [ "$i" = 60 ] && { echo "FATAL: postgres never became ready" >&2; exit 1; }
done

echo "== db-init: full role superset + plpgsql_check extension"
docker cp testing/provision-roles.sh "$PG":/provision-roles.sh
docker exec -e PGUSER=platform -e PGDATABASE="$DB" -e RPW=testpw \
  -e SERVICE_ROLES="$ROLES" -e HUMAN_READ_SCHEMAS="$HUMAN_READ" -e HUMAN_WRITE_SCHEMAS="$HUMAN_WRITE" \
  "$PG" sh -c 'sh /provision-roles.sh' >/dev/null
docker exec "$PG" sh -c "psql -U platform -d $DB -v ON_ERROR_STOP=1 -qc 'CREATE EXTENSION IF NOT EXISTS plpgsql_check WITH SCHEMA public'"
echo "   $(echo $ROLES | wc -w) service roles + group roles + plpgsql_check ready"

echo "== apply ALL locations via the migration image"
docker run --rm --network "$NET" \
  -e PGHOST="$PG" -e PGDATABASE="$DB" -e PGUSER=platform -e PGPASSWORD="$PW" \
  -e LOCATIONS="$ALL_LOCATIONS" "$IMG" | tail -1

echo "== SQL unit tests"
docker cp migrations/testing "$PG":/sqltests
for t in migrations/testing/tests/unit.*.sql; do
  name=$(basename "$t")
  docker exec "$PG" sh -c "psql -v ON_ERROR_STOP=1 -U platform -d $DB -q -f /sqltests/tests/$name" >/dev/null \
    || { echo "FATAL: $name failed" >&2; exit 1; }
  echo "   OK: $name"
done

echo "== role-leak acceptance"
for t in migrations/testing/roleleak.*.sql; do
  name=$(basename "$t")
  docker exec "$PG" sh -c "psql -v ON_ERROR_STOP=1 -U platform -d $DB -q -f /sqltests/$name" >/dev/null \
    || { echo "FATAL: $name failed" >&2; exit 1; }
  echo "   OK: $name"
done

echo "== plpgsql_check static analysis (error-level findings fail)"
docker cp testing/lint-pgSQL.sql "$PG":/lint-pgSQL.sql

# The analysis must be PROVEN to have run. Until 2026-08-01 this step piped psql
# without ON_ERROR_STOP into a file and only grepped that file for error-level
# findings — so a query that failed outright produced an empty file and the gate
# reported success. A static-analysis gate that cannot distinguish "clean" from
# "never executed" is not a gate. Two guards now: psql must exit 0, and the
# database must actually contain PL/pgSQL routines for it to have analysed.
ANALYSED=$(docker exec "$PG" sh -c "psql -X -v ON_ERROR_STOP=1 -U platform -d $DB -At -c \"SELECT count(*) FROM pg_proc p JOIN pg_language l ON l.oid = p.prolang WHERE l.lanname = 'plpgsql' AND p.pronamespace <> 'pg_catalog'::regnamespace\"") \
  || { echo "FATAL: could not count PL/pgSQL routines" >&2; exit 1; }
if [ "${ANALYSED:-0}" -lt 1 ]; then
  echo "FATAL: no PL/pgSQL routines found — the analysis would pass vacuously" >&2; exit 1
fi
echo "   analysing $ANALYSED PL/pgSQL routine(s)"

docker exec "$PG" sh -c "psql -X -x -v ON_ERROR_STOP=1 -U platform -d $DB -f /lint-pgSQL.sql" > /tmp/output.txt \
  || { echo "FATAL: plpgsql_check query failed to execute — analysis did NOT run" >&2; exit 1; }
sh testing/check-linter-error-steps.sh

docker builder prune -f >/dev/null 2>&1 || true
echo "SQL-TESTS: ALL PASSED"

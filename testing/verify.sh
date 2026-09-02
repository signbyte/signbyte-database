#!/usr/bin/env bash
# End-to-end verify against a throwaway Postgres (Docker):
#   1. build the ONE migration image from this repo
#   2. provision the full role superset on a fresh postgres:17-alpine
#   3. migrate each deployment shape declared in testing/deployments.conf with
#      ITS LOCATIONS list —
#      twice (the second run must be a no-op: idempotency)
#   4. assert the expected schemas + one Flyway history table per location
#   5. prove fail-closed: a bogus location and a missing LOCATIONS both refuse
#
# Container paths are kept inside sh -c bodies / colon forms deliberately, so
# the script runs identically from Git Bash (Windows) and any Linux shell.
set -euo pipefail
cd "$(dirname "$0")/.."

NET=platformdb-verify-net
PG=platformdb-verify-pg
IMG=platform-migrate:verify
PW=verifypw

cleanup() {
  docker rm -f "$PG" >/dev/null 2>&1 || true
  docker network rm "$NET" >/dev/null 2>&1 || true
}
trap cleanup EXIT
cleanup

echo "== build the migration image"
docker build -q -f Dockerfile.migrate -t "$IMG" . >/dev/null

echo "== throwaway postgres"
docker network create "$NET" >/dev/null
docker run -d --name "$PG" --network "$NET" \
  -e POSTGRES_USER=platform -e POSTGRES_PASSWORD="$PW" -e POSTGRES_DB=postgres \
  postgres:17-alpine >/dev/null
for i in $(seq 1 60); do
  docker exec "$PG" pg_isready -h 127.0.0.1 -U platform >/dev/null 2>&1 && break
  sleep 1
  [ "$i" = 60 ] && { echo "FATAL: postgres never became ready" >&2; exit 1; }
done

# The deployment shapes live in testing/deployments.conf (one row per shape:
# name | locations | service roles | human read schemas | human write schemas).
# Roles are cluster-wide, so the union over every row is provisioned once.
SHAPES=$(grep -v '^#' testing/deployments.conf | grep -v '^[[:space:]]*$')
[ -n "$SHAPES" ] || { echo "FATAL: testing/deployments.conf declares no deployment shape" >&2; exit 1; }
union() { printf '%s\n' "$SHAPES" | cut -d'|' -f"$1" | tr ' ' '\n' | grep -v '^$' | awk '!seen[$0]++' | tr '\n' ' '; }
echo "== provision the role union of every deployment shape (cluster-wide)"
ROLES=$(for r in $(union 3); do printf '%s:RPW ' "$r"; done)
# Human group roles are per schema (least privilege). Each shape declares a
# representative spread — deliberately NOT every schema, so the "a schema with no
# role simply gets no human grant" path is exercised too — and where a shape names
# a write schema the break-glass branch is covered as well.
HUMAN_READ=$(union 4)
HUMAN_WRITE=$(union 5)
docker cp testing/provision-roles.sh "$PG":/provision-roles.sh
docker exec -e PGUSER=platform -e PGDATABASE=postgres -e RPW=testpw \
  -e SERVICE_ROLES="$ROLES" -e HUMAN_READ_SCHEMAS="$HUMAN_READ" -e HUMAN_WRITE_SCHEMAS="$HUMAN_WRITE" \
  "$PG" sh -c 'sh /provision-roles.sh' >/dev/null
echo "   $(echo $ROLES | wc -w) service roles + $(echo $HUMAN_READ | wc -w) read + $(echo $HUMAN_WRITE | wc -w) write group role(s) provisioned"

# migrate <db> "<locations>" — run the image twice, assert schemas + history tables
migrate() {
  db="$1"; locations="$2"
  echo "== deployment '$db': LOCATIONS=$locations"
  docker exec "$PG" sh -c "psql -U platform -d postgres -qc 'CREATE DATABASE $db OWNER platform'"
  for pass in 1 2; do
    out=$(docker run --rm --network "$NET" \
      -e PGHOST="$PG" -e PGDATABASE="$db" -e PGUSER=platform -e PGPASSWORD="$PW" \
      -e LOCATIONS="$locations" "$IMG" 2>&1) \
      || { echo "FATAL: migrate pass $pass failed for $db:"; echo "$out" | tail -20; exit 1; }
    if [ "$pass" = 2 ] && ! echo "$out" | grep -q "No migration necessary"; then
      echo "FATAL: second run for $db was not a no-op:"; echo "$out" | tail -20; exit 1
    fi
  done
  n_loc=$(echo "$locations" | wc -w)
  # location -> schema name: identical except the legacy signflow -> signing
  # pairing; grants creates no schema of its own.
  schemas=$(echo "$locations" | sed 's/\bsignflow\b/signing/' | tr ' ' '\n' | grep -v '^grants$' | tr '\n' ' ')
  want_schemas=$(echo "$schemas" | wc -w)
  got_schemas=$(docker exec "$PG" sh -c "psql -U platform -d $db -tAc \
    \"SELECT count(*) FROM information_schema.schemata WHERE schema_name = ANY(string_to_array(trim('$schemas'),' '))\"")
  got_hist=$(docker exec "$PG" sh -c "psql -U platform -d $db -tAc \
    \"SELECT count(*) FROM information_schema.tables WHERE table_name LIKE 'flyway_schema_history_%'\"")
  [ "$got_schemas" = "$want_schemas" ] || { echo "FATAL: $db expected $want_schemas schemas, got $got_schemas" >&2; exit 1; }
  [ "$got_hist" = "$n_loc" ] || { echo "FATAL: $db expected $n_loc history tables, got $got_hist" >&2; exit 1; }
  # Hardening assertions read the live catalog, so they catch drift introduced by
  # any route — not only by a migration.
  # The append-only table list is declared per location (testing/append-only/
  # <location>.list); every file present is handed in, the assertion skips tables
  # this shape did not migrate.
  append_only=$(cat testing/append-only/*.list 2>/dev/null | grep -v '^#' | tr '\n' ' ')
  docker cp testing/assert-hardening.sql "$PG":/assert-hardening.sql >/dev/null
  docker exec -e APPEND_ONLY="$append_only" "$PG" sh -c "psql -X -q -v ON_ERROR_STOP=1 -U platform -d $db -c \"SET hardening.append_only = '\$APPEND_ONLY'\" -f /assert-hardening.sql" >/dev/null 2>/tmp/harden.$db.err \
    || { echo "FATAL: hardening assertions failed for $db:" >&2; sed 's/^/     /' /tmp/harden.$db.err >&2; exit 1; }
  echo "   OK: $got_schemas schemas · $got_hist history tables · second run no-op · hardening asserted"
}

while IFS='|' read -r name locations _roles _hr _hw; do
  migrate "$name" "$locations"
done <<EOF_SHAPES
$SHAPES
EOF_SHAPES

echo "== fail-closed proofs"
if docker run --rm --network "$NET" -e PGHOST="$PG" -e PGDATABASE=postgres \
  -e PGUSER=platform -e PGPASSWORD="$PW" -e LOCATIONS="util nosuchschema" "$IMG" >/dev/null 2>&1; then
  echo "FATAL: bogus location was NOT refused" >&2; exit 1
fi
echo "   OK: unknown location refused before touching the database"
if docker run --rm --network "$NET" -e PGHOST="$PG" -e PGDATABASE=postgres \
  -e PGUSER=platform -e PGPASSWORD="$PW" "$IMG" >/dev/null 2>&1; then
  echo "FATAL: missing LOCATIONS was NOT refused" >&2; exit 1
fi
echo "   OK: missing LOCATIONS refused"

docker builder prune -f >/dev/null 2>&1 || true
echo "VERIFY: ALL PASSED"

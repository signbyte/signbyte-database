#!/usr/bin/env bash
# SQL quality gate — the deep test layer, one mechanism for local dev AND CI:
#   1. build a plpgsql_check-capable Postgres (stock images don't ship it)
#   2. provision the full role superset (throwaway, generated passwords)
#   3. apply ALL schema locations into one database via the migration image
#      (the same image deployments run)
#   4. run every SQL unit test (migrations/testing/tests/unit.*.sql)
#   5. run every role-leak acceptance (migrations/testing/roleleak.*.sql)
#   6. run every migration fixture (migrations/testing/fixtures/) — a migration
#      that carries a data statement, applied to a database that already has
#      rows in it, which no other gate here does
#   7. plpgsql_check static analysis over every procedure; any 'error'-level
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
# The one-shot that applies a staged, partial migration set for a fixture. Named
# rather than anonymous so a run that dies mid-fixture still gets cleaned up.
FIXC=platformdb-sqltest-stage

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
  docker rm -f "$FIXC" >/dev/null 2>&1 || true
  docker network rm "$NET" >/dev/null 2>&1 || true
  rm -rf testing/.fixture-stage
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

# --- migration fixtures: a data-carrying migration, observed against rows -----
# Every other gate here applies the migration set to an EMPTY database — the rows
# are created afterwards, by the tests. So a migration that carries a data
# statement (a backfill, a counter seeded from work already there, a column made
# NOT NULL once it is filled) runs against nothing, and its correctness is READ
# rather than measured. Worse, a constraint added in the same migration as the
# data that must satisfy it cannot fail when there is no data.
#
# Such a migration gets a pair of files; a migration with no data statement gets
# none and costs nothing:
#
#   migrations/testing/fixtures/<location>/V<N>.seed.sql     raw INSERTs
#   migrations/testing/fixtures/<location>/V<N>.assert.sql   what V<N> claims
#
# This step gives that migration a database that is already in use: the location's
# V files BELOW N and nothing else, then the seed, then the real migration set —
# the same image, the same runner, the same order a deployment uses.
#
# The seed is raw INSERTs and never a procedure call. Repeatable (R__) files are
# not versioned, so "the procedures as they were before version N" does not exist
# on disk, and today's procedures already write what version N is about to
# introduce. Tables ARE versioned, so rows written straight into them depend on
# nothing but the schema at N-1.
#
# A tree that declares no fixtures has nothing to run here, and the step says so
# rather than passing quietly.
echo "== migration fixtures (a data migration, applied to a database already in use)"
FIXTURES=migrations/testing/fixtures
STAGE=testing/.fixture-stage
SEEDS=$(ls "$FIXTURES"/*/V*.seed.sql 2>/dev/null || true)
if [ -z "$SEEDS" ]; then
  echo "   none declared under $FIXTURES/ — no migration in this tree carries a data statement"
else
  rm -rf "$STAGE"
  docker cp "$FIXTURES" "$PG":/fixtures >/dev/null
  for seed in $SEEDS; do
    loc=$(basename "$(dirname "$seed")")
    ver=$(basename "$seed" .seed.sql); ver=${ver#V}
    assert="$FIXTURES/$loc/V${ver}.assert.sql"
    [ -f "$assert" ] || { echo "FATAL: $seed has no V${ver}.assert.sql beside it — a seed that asserts nothing is not a gate" >&2; exit 1; }
    mig=$(ls "migrations/$loc/V${ver}__"*.sql 2>/dev/null | head -1 || true)
    [ -n "$mig" ] || { echo "FATAL: fixture $seed names V$ver of location '$loc', which does not exist" >&2; exit 1; }

    # Which locations this one is applied after — read from the first deployment
    # shape that declares it, so the order is the one a deployment really uses
    # and no second list has to be kept in step.
    row=$(printf '%s\n' "$SHAPES" | awk -F'|' -v l="$loc" '{n=split($2,a," "); for(i=1;i<=n;i++) if(a[i]==l){print; exit}}' || true)
    [ -n "$row" ] || { echo "FATAL: location '$loc' is in no deployment shape — nothing declares what is applied before it" >&2; exit 1; }
    locations=$(printf '%s' "$row" | cut -d'|' -f2)
    deps=$(printf '%s' "$locations" | awk -v l="$loc" '{for(i=1;i<=NF;i++){ if($i==l) exit; printf "%s ", $i }}')
    db="fixture_${loc}_v${ver}"

    mkdir -p "$STAGE/$loc"
    staged=0
    for f in "migrations/$loc/V"*.sql; do
      n=$(basename "$f"); n=${n#V}; n=${n%%__*}
      if [ "$n" -lt "$ver" ]; then cp "$f" "$STAGE/$loc/"; staged=$((staged+1)); fi
    done
    [ "$staged" -gt 0 ] || { echo "FATAL: V$ver is the first migration of '$loc' — there is no earlier state for a database to be in" >&2; exit 1; }

    docker exec "$PG" sh -c "psql -X -v ON_ERROR_STOP=1 -U platform -d $DB -qc 'CREATE DATABASE $db OWNER platform'" >/dev/null

    # 1. everything this location is applied after, from the image itself
    if [ -n "$deps" ]; then
      docker run --rm --network "$NET" -e PGHOST="$PG" -e PGDATABASE="$db" -e PGUSER=platform \
        -e PGPASSWORD="$PW" -e LOCATIONS="$deps" "$IMG" >/dev/null \
        || { echo "FATAL: fixture $loc/V$ver — applying '$deps' failed" >&2; exit 1; }
    fi

    # 2. the location as it stood one version earlier. The staged copy is handed
    #    to the same runner through MIGRATIONS_DIR, so Flyway records exactly the
    #    history a database that stopped below V$ver would carry, and step 4
    #    continues it instead of re-applying anything.
    docker rm -f "$FIXC" >/dev/null 2>&1 || true
    #    MSYS_NO_PATHCONV: this is the one container path that cannot hide
    #    inside an sh -c body or a colon form, and Git Bash rewrites a bare
    #    /staged into a Windows path before docker ever sees it. The variable
    #    means nothing on Linux, so the line runs identically in both shells.
    MSYS_NO_PATHCONV=1 docker create --name "$FIXC" --network "$NET" -e PGHOST="$PG" -e PGDATABASE="$db" \
      -e PGUSER=platform -e PGPASSWORD="$PW" -e LOCATIONS="$loc" -e MIGRATIONS_DIR=/staged "$IMG" >/dev/null
    docker cp "$STAGE" "$FIXC":/staged >/dev/null
    docker start -a "$FIXC" >/dev/null 2>&1 \
      || { echo "FATAL: fixture $loc/V$ver — applying the $staged migration(s) below V$ver failed:" >&2; docker logs "$FIXC" 2>&1 | tail -20 >&2; exit 1; }
    docker rm -f "$FIXC" >/dev/null

    # 3. the rows. Proven by the count psql reports, never by the absence of an
    #    error: a seed that silently wrote nothing makes every assertion below
    #    vacuous, and it would still exit 0.
    out=$(docker exec "$PG" sh -c "psql -X -v ON_ERROR_STOP=1 -U platform -d $db -f /fixtures/$loc/V${ver}.seed.sql" 2>&1) \
      || { echo "FATAL: fixture $loc/V$ver — the seed failed:" >&2; printf '%s\n' "$out" | tail -20 >&2; exit 1; }
    rows=$(printf '%s\n' "$out" | awk '/^INSERT 0 [0-9]+$/ { s += $3 } END { print s+0 }')
    [ "$rows" -gt 0 ] || { echo "FATAL: fixture $loc/V$ver — the seed wrote 0 rows, so nothing that follows observes anything" >&2; exit 1; }

    # 4. the real set, V$ver included, onto a database with work in it
    docker run --rm --network "$NET" -e PGHOST="$PG" -e PGDATABASE="$db" -e PGUSER=platform \
      -e PGPASSWORD="$PW" -e LOCATIONS="$locations" "$IMG" >/dev/null \
      || { echo "FATAL: fixture $loc/V$ver — the migration set failed against a database that already had rows" >&2; exit 1; }

    # 5. what the migration claims. The script must reach its own PASS notice —
    #    an assertion file that ran but asserted nothing is not evidence.
    out=$(docker exec "$PG" sh -c "psql -X -v ON_ERROR_STOP=1 -U platform -d $db -f /fixtures/$loc/V${ver}.assert.sql" 2>&1) \
      || { echo "FATAL: fixture $loc/V$ver — the assertions failed:" >&2; printf '%s\n' "$out" | tail -20 >&2; exit 1; }
    printf '%s\n' "$out" | grep -q 'PASS' \
      || { echo "FATAL: fixture $loc/V$ver — the assertions never reached their PASS notice" >&2; exit 1; }
    echo "   OK: $loc/V$ver — $staged migration(s) below it, $rows seeded row(s), then V$ver asserted"
    rm -rf "$STAGE"
  done
fi

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

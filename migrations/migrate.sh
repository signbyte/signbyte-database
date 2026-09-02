#!/bin/sh
# Apply database migrations with Flyway — one location per schema, each with its
# own history table so the schemas version independently.
#
# ONE self-contained step, identical in local dev, CI, and every deployed
# environment: run this script inside the Flyway image with this repository's
# migrations directory present. This repository holds the migrations for EVERY
# platform schema; a deployment applies only the locations it declares.
#
#   LOCATIONS   REQUIRED — ordered, space-separated list of the schema locations
#               this deployment applies, e.g.:
#                 LOCATIONS="util identity rolebyte flowbyte estimating grants"
#               List order IS the apply order: `util` (shared primitives) first,
#               `grants` (cross-schema human grants) last. A requested location
#               that is not present is a HARD ERROR — fail closed: a partial
#               artifact must never silently produce a database with missing
#               schemas.
#
#   PGHOST      database host        (default: postgres)
#   PGPORT      database port        (default: 5432)
#   PGDATABASE  database name        (required)
#   PGUSER      migrating role       (required — migrations run AS the owner, not
#                                     a superuser, so objects are owned by the
#                                     deployment role and privileges stay correct)
#   PGPASSWORD  its password         (required, unless PGPASSWORD_FILE is set)
#   PGPASSWORD_FILE  path to a file holding the password — read when PGPASSWORD
#                    is unset (Docker/Swarm secret convention: the migration
#                    reads the same mounted secret file as the database itself)
#   CONNECT_RETRIES  how many times to retry the initial database connection
#                    (default 10). Compose can order this after a healthcheck;
#                    an orchestrator that starts the one-shot alongside the
#                    database cannot, and a race must not read as a failure.
#
# The EXECUTE-only service roles are created beforehand by
# testing/provision-roles.sh (or the deployment's own role one-shot); the
# versioned migrations only assign privileges and carry no credentials.
set -e

: "${PGHOST:=postgres}"
: "${PGPORT:=5432}"

if [ -z "${LOCATIONS:-}" ]; then
  echo "ERROR: LOCATIONS is required — the ordered list of schema locations this deployment applies (e.g. \"util identity estimating grants\")" >&2
  exit 2
fi

if [ -z "${PGPASSWORD:-}" ] && [ -n "${PGPASSWORD_FILE:-}" ]; then
  PGPASSWORD=$(cat "${PGPASSWORD_FILE}")
  export PGPASSWORD
fi

DIR=$(cd "$(dirname "$0")" && pwd)
: "${MIGRATIONS_DIR:=$DIR}"

# Fail closed BEFORE touching the database: every requested location must exist.
for schema in $LOCATIONS; do
  if [ ! -d "${MIGRATIONS_DIR}/${schema}" ]; then
    echo "ERROR: required location '${schema}' is not present under ${MIGRATIONS_DIR} — refusing to migrate" >&2
    exit 3
  fi
done

# Folder name == schema name == history-table suffix. baselineOnMigrate lets
# each later location create its own history table against a database the
# earlier ones already populated (a no-op for the first).
#
# -defaultSchema is stated explicitly and must stay that way. Without it Flyway
# puts its history table in whatever the connection's search_path resolves first,
# which makes the bookkeeping depend on a session setting: point the database
# default somewhere else and Flyway silently writes its history to a different
# schema, finds no history on the next run, and re-applies every migration. The
# history tables live in `public`; the migrations themselves never rely on a
# search_path, because every object they touch is schema-qualified.
for schema in $LOCATIONS; do
  echo "==> flyway migrate: ${schema}"
  flyway \
    -url="jdbc:postgresql://${PGHOST}:${PGPORT}/${PGDATABASE}" \
    -user="${PGUSER}" \
    -password="${PGPASSWORD}" \
    -locations="filesystem:${MIGRATIONS_DIR}/${schema}" \
    -table="flyway_schema_history_${schema}" \
    -defaultSchema=public \
    -baselineOnMigrate=true \
    -baselineVersion=0 \
    -connectRetries="${CONNECT_RETRIES:-10}" \
    migrate
done

echo "migrations: complete (applied: ${LOCATIONS})"

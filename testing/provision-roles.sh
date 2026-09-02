#!/bin/sh
# Provision the Postgres roles a deployment of this platform database needs,
# from the environment.
#
# Lives in the DB repo (not the deployment glue) so the repo is a self-contained
# bring-up: create roles -> migrate, all in one place, deployable by anyone.
#
# Why roles are created here (not in a versioned migration): a role's
# *credentials* are an operational concern, not a schema one. The migrations
# therefore only assign privileges (GRANT EXECUTE / REVOKE FROM PUBLIC); this
# one-shot creates the roles with passwords sourced from the environment and
# MUST run BEFORE migrate. Result: versioned migrations carry zero credentials,
# and the same env var feeds both the role password here AND the service DSN
# (single source, cannot drift). In production this step reads from a secret
# manager.
#
#   SERVICE_ROLES  REQUIRED — the deployment's service roles as
#                  "<role>:<ENV_VAR_HOLDING_ITS_PASSWORD>" entries, space
#                  separated, mirroring the deployment's LOCATIONS choice, e.g.:
#                    SERVICE_ROLES="authbyte_public:AUTHBYTE_PUBLIC_PW \
#                                   estimating_public:ESTIMATING_PUBLIC_PW"
#                  Each named env var must be set; an empty one is fatal.
#
# Idempotent: create a role if absent, else re-apply its password (rotation on
# the next run). Connects as the DB owner/superuser via the PG* env vars.
set -eu

if [ -z "${SERVICE_ROLES:-}" ]; then
  echo "FATAL: SERVICE_ROLES is required — the deployment's \"role:PASSWORD_ENV\" list" >&2
  exit 2
fi

# --- 1. Per-service EXECUTE-only LOGIN roles ---------------------------------
# The service connects ONLY with its own role (never the owner); the migrations
# grant each role EXECUTE on its schema's procedures and nothing else.
for entry in $SERVICE_ROLES; do
  role="${entry%%:*}"
  var="${entry#*:}"
  eval "pw=\${$var:-}"
  [ -n "$pw" ] || { echo "FATAL: \$$var is empty -- set it in the environment" >&2; exit 1; }
  if psql -v ON_ERROR_STOP=1 -tAc "SELECT 1 FROM pg_roles WHERE rolname='$role'" | grep -q 1; then
    psql -v ON_ERROR_STOP=1 -c "ALTER ROLE \"$role\" WITH LOGIN PASSWORD '$pw'"
    echo "  role $role: password synced"
  else
    psql -v ON_ERROR_STOP=1 -c "CREATE ROLE \"$role\" LOGIN PASSWORD '$pw'"
    echo "  role $role: created"
  fi
done

# --- 2. Human/operator group roles, ONE PER SCHEMA ----------------------------
# NON-LOGIN, NOINHERIT group roles carrying human access (helpdesk, operators,
# reporting) — a separate axis from the service roles. Named per-person login
# roles are granted INTO them out-of-band; nobody connects as the owner or a
# service role. They carry no password, so they are created here purely to keep
# every role definition in one place; the repeatable grant migration then assigns
# each one privileges on ITS OWN schema and nowhere else.
#
# Scoped per schema on purpose. A single database-wide read role would let anyone
# who needs to read one schema also read identity PII, the GDPR access records and
# the signing-evidence trail — the opposite of least privilege, and the first thing
# a GDPR/NIS2 assessor asks about. So a person is granted exactly the schemas their
# job needs, and "who can read the signing evidence?" is answered by listing one
# role's members.
#
#   HUMAN_READ_SCHEMAS   optional — schemas that get a "<schema>_read_role"
#                        (SELECT). Space separated. Naming them explicitly rather
#                        than deriving one per schema is deliberate: a schema
#                        nobody has a reason to read should have no human role at
#                        all, and that must be a decision, not a default.
#   HUMAN_WRITE_SCHEMAS  optional — schemas that additionally get a
#                        "<schema>_write_role" (CRUD). Break-glass, rare, audited:
#                        a direct human write BYPASSES the procedures' invariants.
#                        Normally empty.
make_group_role() {
  if psql -v ON_ERROR_STOP=1 -tAc "SELECT 1 FROM pg_roles WHERE rolname='$1'" | grep -q 1; then
    echo "  group role $1: present"
  else
    psql -v ON_ERROR_STOP=1 -c "CREATE ROLE \"$1\" NOLOGIN NOINHERIT"
    echo "  group role $1: created"
  fi
}

for s in ${HUMAN_READ_SCHEMAS:-}; do
  make_group_role "${s}_read_role"
done
for s in ${HUMAN_WRITE_SCHEMAS:-}; do
  make_group_role "${s}_write_role"
done

echo "pg-roles: provisioning complete"

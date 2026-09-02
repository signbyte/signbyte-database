# signbyte-database

The PostgreSQL data layer of **[signbyte](https://github.com/signbyte)**, the eIDAS
qualified-signature platform — **one database, a schema per domain**, authored as
[Flyway](https://flyway.org) migrations and packaged as a single **migration image**.
To create or upgrade any signbyte database, you run the image against it. There is no
other step, and no other way the platform's schemas are applied.

The migration set is **database-name and owner-name free** — connection and identity
come entirely from the environment, so the same files deploy under any database name
or owner (dev, CI, or a named production database) with no SQL edits. Services never
touch tables: every schema is consumed only through its `SECURITY DEFINER` procedures,
and each consuming service's own repository says which schema it calls.

## The image

CI runs the full verification below as its publish gate, then builds, SBOMs, scans,
pushes and cosign-signs (keyless, GitHub OIDC) the image:

```
ghcr.io/signbyte/signbyte-database:<sha>     every green build (immutable pin)
ghcr.io/signbyte/signbyte-database:vX.Y.Z    a version tag = the schema version
ghcr.io/signbyte/signbyte-database:latest    the newest version tag
ghcr.io/signbyte/signbyte-database:develop   the moving develop-branch build
ghcr.io/signbyte/signbyte-database:main      the moving main-branch build
```

Deployments pin a `:sha` or a version tag — never `:develop` / `:latest` — so a
database's migration set is exactly reproducible.

## Running the migrations

### Generate the passwords

Eight passwords are needed: one for the database superuser (`signbyte` in the examples
below — any name works) and one per service role. Generate each by running this in a
bash shell, once per password:

```sh
LC_ALL=C tr -dc 'A-Za-z0-9' </dev/urandom | head -c 32; echo
```

| Password for | Used by |
| :-- | :-- |
| `signbyte` (superuser) | the `signbyte_postgres_password` secret + the database owner |
| `authbyte_public` | role `authbyte_public` (auth service) — and later its DSN secret |
| `document_public` | role `document_public` (document service) — and later its DSN secret |
| `signing_public` | role `signing_public` (signflow orchestrator) — and later its DSN secret |
| `envelope_public` | role `envelope_public` (envelope service) — and later its DSN secret |
| `eidas_audit_public` | role `eidas_audit_public` (eIDAS-audit sink) — and later its DSN secret |
| `access_audit_public` | role `access_audit_public` (GDPR-audit sink) — and later its DSN secret |
| `trust_anchor_public` | role `trust_anchor_public` (trust-anchor) — and later its DSN secret |

> Keep all eight somewhere safe (a password manager). You will **reuse the seven role passwords**
> when you configure the services' database connections (their DSN secrets) — they must match
> exactly. They are alphanumeric on purpose: no characters that would break a connection string or
> an SQL statement. The **group roles** (see Roles below) carry no password — they are NOLOGIN,
> so no entry here.

### Create the database-password secret

Register the `signbyte` superuser password as a secret. For example, in Portainer:
**Secrets → Add secret** — name it `signbyte_postgres_password` and paste the superuser
password you just generated as the value.

### Create the database roles

The platform uses **seven** EXECUTE-only login roles (one per service) plus NOLOGIN
**group roles** for human/operator access, named **per schema**
(`<schema>_read_role` / `<schema>_write_role`). The migration grants privileges to
whichever group roles exist and skips the absent ones, so create the set your
operation needs — the block below creates the tested default: read on `identity`,
`document` and `eidas_audit`, break-glass write on `document`.

Connect to the prepared PostgreSQL database as the superuser you created. Paste the
block below, replacing each `PASSWORD_n` with the matching role password from
"Generate the passwords":

```sh
# Per-service EXECUTE-only LOGIN roles (empty for now — the migration GRANTs them EXECUTE).
psql -U signbyte -d signbyte -c "CREATE ROLE authbyte_public      LOGIN ENCRYPTED PASSWORD 'PASSWORD_1'";
psql -U signbyte -d signbyte -c "CREATE ROLE document_public      LOGIN ENCRYPTED PASSWORD 'PASSWORD_2'";
psql -U signbyte -d signbyte -c "CREATE ROLE signing_public       LOGIN ENCRYPTED PASSWORD 'PASSWORD_3'";
psql -U signbyte -d signbyte -c "CREATE ROLE envelope_public      LOGIN ENCRYPTED PASSWORD 'PASSWORD_4'";
psql -U signbyte -d signbyte -c "CREATE ROLE eidas_audit_public   LOGIN ENCRYPTED PASSWORD 'PASSWORD_5'";
psql -U signbyte -d signbyte -c "CREATE ROLE access_audit_public  LOGIN ENCRYPTED PASSWORD 'PASSWORD_6'";
psql -U signbyte -d signbyte -c "CREATE ROLE trust_anchor_public  LOGIN ENCRYPTED PASSWORD 'PASSWORD_7'";

# Human/operator group roles — NOLOGIN, NOINHERIT, no password, named per schema.
# Named per-person login roles are granted INTO these out-of-band (helpdesk /
# operators / reporting). Create the ones you need; the migration skips absent ones.
psql -U signbyte -d signbyte -c "CREATE ROLE identity_read_role    NOLOGIN NOINHERIT";
psql -U signbyte -d signbyte -c "CREATE ROLE document_read_role    NOLOGIN NOINHERIT";
psql -U signbyte -d signbyte -c "CREATE ROLE eidas_audit_read_role NOLOGIN NOINHERIT";
psql -U signbyte -d signbyte -c "CREATE ROLE document_write_role   NOLOGIN NOINHERIT";
```

> The seven `*_public` roles are intentionally **empty** right now — they can log in but hold no
> privileges. The migration step (next section) grants each one EXECUTE on its schema's stored
> procedures, and grants each created group role its privileges within its schema. Roles first,
> migrations second — that order is on purpose.
> The group roles are a **separate axis** from the service roles: `<schema>_read_role` = SELECT
> within that schema (read-only operators); `<schema>_write_role` = CRUD within that schema (rare,
> audited, break-glass — a direct human write BYPASSES the procedures' invariants, so it is
> exceptional). Nobody connects *as* a group role or the owner; people get a named login role
> granted INTO a group. Full admins are separate named superusers.
> Inside the PostgreSQL container, `psql` reaches Postgres over the local socket as the `signbyte`
> superuser, so no password is asked here. (If it ever prompts, it is the superuser password.)

### Verify

List the roles:

```sh
psql -U signbyte -d signbyte -c "\du"
```

Expect the seven `*_public` roles each with a **blank Attributes column** — that is correct. `psql`
prints `Cannot login` only for roles that *cannot* log in, so a **blank line means the role has
`LOGIN`**. (The `signbyte` superuser row does not say "Login" either, yet it obviously can — same
reason.) A `*_public` role should **never** show `Cannot login`; if one does, it was created without
`LOGIN` — drop it and re-create it.

Expect every group role you created (`identity_read_role`, `document_read_role`,
`eidas_audit_read_role`, `document_write_role` in the default set) to show **`Cannot login`** —
that is *correct* for them (they are NOLOGIN by design). If one can log in, drop and re-create it
NOLOGIN.

Confirm the database:

```sh
psql -U signbyte -d signbyte -c "\l signbyte"
```

Expect owner `signbyte`, encoding `UTF8`.

### Apply the migrations

Connection + identity come from the environment (12-factor):

| Var | Meaning |
|---|---|
| `LOCATIONS` | **required** — the ordered list of locations to apply (see the schema table; the full signbyte list is in `testing/deployments.conf`) |
| `PGHOST` / `PGPORT` | database host / port (default `postgres` / `5432`) |
| `PGDATABASE` | database name (required) |
| `PGUSER` | the owner role migrations run as (required) |
| `PGPASSWORD` | its password (required, unless `PGPASSWORD_FILE` is set) |
| `PGPASSWORD_FILE` | path to a file holding the password (Docker/Swarm secret convention) |

An example one-shot `migrate` service for a compose/stack deployment:

```yaml
version: "3.8"

services:
  migrate:
    image: ghcr.io/signbyte/signbyte-database:<sha-or-version-tag>
    environment:
      PGHOST: postgres
      PGPORT: "5432"
      PGDATABASE: signbyte
      # Migrate AS the owner (also the superuser here), never a service role — so
      # objects are owned by the deployment role, pgcrypto can be installed, and
      # the GRANTs to the service roles succeed.
      PGUSER: signbyte
      # Reads the SAME secret the database uses — never an inline password.
      PGPASSWORD_FILE: /run/secrets/signbyte_postgres_password
      # REQUIRED: the locations this deployment applies, in order.
      LOCATIONS: "util identity document signflow envelope eidas_audit access_audit verify_audit trust_anchor grants"
      CONNECT_RETRIES: "30"
    secrets:
      - signbyte_postgres_password
    deploy:
      restart_policy:
        condition: none          # one-shot: run once, do not restart on exit
      resources:
        limits: { cpus: "0.5", memory: 256M }

secrets:
  signbyte_postgres_password:
    external: true
```

Or straight from the command line — the published image, this database's locations:

```sh
docker run --rm \
  -e LOCATIONS="util identity document signflow envelope eidas_audit access_audit verify_audit trust_anchor grants" \
  -e PGHOST=... -e PGDATABASE=signbyte -e PGUSER=signbyte -e PGPASSWORD=... \
  ghcr.io/signbyte/signbyte-database:<sha-or-version-tag>
```

A requested location that is not in the image is a **hard error before any database
contact** (fail closed). Running the image twice is a no-op.

## Data-layer model

Every schema follows one model: a **schema per domain**, `SECURITY DEFINER`
procedures as the only entry point, a uniform JSONB `(pi_data, INOUT po_data)`
envelope, `EXECUTE`-only service roles (no table access), a pinned `search_path`,
and ULID primary keys. Services only `CALL` the procedures, which run as the owner.
The tables and columns are the source of truth for the data model; the service code
only knows procedure names.

## Security model

Every property below is enforced by something in this tree — a role definition, a test,
a CI gate — not promised in prose:

- **Services cannot read or write data directly.** A service role holds `EXECUTE` on its
  own schema's procedures and nothing else — no table privileges anywhere, its own schema
  included. Every access goes through a `SECURITY DEFINER` procedure with a pinned
  `search_path`. A leaked service credential therefore exposes one narrow procedure API,
  not the database. The role-leak acceptance test (`testing/sql-tests.sh`) fails the build
  if a service role can see any table.

- **No powerful credentials at runtime, none in the files.** The owner — the only role
  that can change schemas — is used when migrations run, never by a running service. And
  the migrations themselves carry no credentials at all: every role and password comes
  from the deployment environment at provisioning time.

- **Human access is per schema, composed per person.** No role reads everything. An
  operator's named login is granted into `<schema>_read_role` for exactly the schemas
  their job needs, so "who can read the signing evidence?" is the member list of one
  role. Write roles are break-glass, per schema, and normally not provisioned at all.
  The hardening assertions fail the build if any human role holds a privilege outside
  its own schema.

- **The audit trails are hardened against their own operators.** Append-only is enforced
  by guard triggers regardless of anyone's grants (asserted by `testing/verify.sh`); the
  signing-evidence trail is hash-chained; the personal-data access log carries per-row
  HMAC seals and per-period checkpoints — tampering stays evident even after retention
  purges delete the underlying documents.

- **One server or several — the deployment decides.** A schema per domain, with no
  cross-schema foreign keys and nothing in any domain schema referencing the audit
  schemas, keeps the layout modular: everything in one database, or the audit locations
  on a separate server under separate control. The same image migrates every shape —
  each target gets its own `LOCATIONS` list (`util` travels to each), and a location the
  image does not know is refused before any database contact.

## Schemas

Apply order is the `LOCATIONS` order: `util` first, `grants` last.

| Location | Schema(s) | Holds / does |
|---|---|---|
| `util` | `util` | Shared primitives: `generate_ulid()`, the `result_success` / `result_error` JSON envelope, `pgcrypto`. Everything depends on it. |
| `identity` | `identity` | Natural person + credential store — one person keyed on the eIDAS national id, many auth-method handles resolving to one stable subject. |
| `document` | `document` | Document metadata (bytes + hashes live in object storage). ACL, inner files, one-container-per-chain guard, signed-PDF store. |
| `signflow` | `signing`, `validation` | Signing jobs, signature records, per-chain lock, and the validation report. |
| `envelope` | `envelope` | Multi-signer workflow: envelope, attached documents, signer slots, and the draft → sent → in_progress → completed / declined / cancelled / expired state machine. |
| `eidas_audit` | `eidas_audit` | Append-only, hash-chained signing-evidence trail (who signed what, when, at what assurance). |
| `access_audit` | `access_audit` | Append-only, subject-indexed personal-data access log (GDPR): per-row HMAC seal + per-period checkpoints for purge-safe tamper evidence. |
| `verify_audit` | `verify_audit` | Append-only abuse evidence for the public (anonymous) document-verification surface: request metadata + upload hash, own short retention sweep. |
| `trust_anchor` | `trust_anchor` | Versioned trust snapshot / bootstrap store for the EU trust-list (LOTL/TL) ingester. |
| `grants` | *(cross-schema)* | The human/operator group-role grants, applied last. |

## Roles

Roles are created **outside** the migrations — by hand as in the runbook above, or by
`testing/provision-roles.sh` from the environment (the route CI and the local harness
use) — so no versioned migration carries a credential. The migrations only assign
privileges, and only to roles that exist.

| Role | Login | Purpose |
|---|---|---|
| *(owner)* | yes (CI/CD) | Owns every schema + object; migrations run as it; `SECURITY DEFINER` procedures execute as it. Never a service runtime identity. Its name comes from the connection env. |
| `authbyte_public` | yes | The authorization server — `EXECUTE` on `identity` procedures only. |
| `document_public` | yes | The document store — `EXECUTE` on `document` procedures only. |
| `signing_public` | yes | The signing orchestrator — `EXECUTE` on `signing` + `validation` procedures only. |
| `envelope_public` | yes | The envelope/workflow service — `EXECUTE` on `envelope` procedures only. |
| `eidas_audit_public` | yes | The signing-evidence sink — `EXECUTE` on `eidas_audit` procedures only (append-only). |
| `access_audit_public` | yes | The audit sink — `EXECUTE` on `access_audit` + `verify_audit` procedures only (append-only; one binary hosts both purpose-scoped surfaces). |
| `trust_anchor_public` | yes | The trust-anchor store — `EXECUTE` on `trust_anchor` procedures only. |
| `<schema>_read_role` / `<schema>_write_role` | no (group) | Human/operator access, **per schema**: read-only by default, writes are break-glass. Named per-person login roles are granted into them out-of-band. |

## Verifying locally

Docker is the only requirement — both scripts run everything in throwaway containers,
and CI runs the same two as its gate:

```sh
testing/verify.sh      # builds the image from this tree, migrates the signbyte shape ×2
                       # (idempotency), asserts schemas + history tables + append-only
                       # hardening, and proves the fail-closed behaviour
testing/sql-tests.sh   # the deep gate: every SQL unit test + role-leak acceptance,
                       # plpgsql_check over every procedure
```

## Conventions

Versioned (`V__`) migrations are **immutable once applied** — Flyway checksums them,
so an edit silently diverges environments. New schema changes ship as a new `V*.sql`;
repeatable `R__` procedure files are re-applied when their checksum changes. CI
enforces this: every push and pull request is checked for modified or deleted `V__`
files against every base available — the `schema-baseline` tag and the incoming
change — and fails if any base shows one.

## Project files

- [CHANGELOG.md](CHANGELOG.md) — what each release changes, written for whoever runs the image
- [CONTRIBUTING.md](CONTRIBUTING.md) — issues welcome, why pull requests are closed here
- [SECURITY.md](SECURITY.md) — the **private** route for anything exploitable, never a public issue
- [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md)

## Licence

GNU AGPL-3.0-only — see [LICENSE](LICENSE).

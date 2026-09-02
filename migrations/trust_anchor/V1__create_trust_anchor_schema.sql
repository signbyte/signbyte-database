-- V1: trust-anchor snapshot/bootstrap store — the `trust_anchor` schema.
--
-- Implements the dual-mode store's PostgreSQL backend on the platform's
-- thick-procedure data layer: a per-domain `trust_anchor` schema, the
-- owner/service-role split, and access ONLY via SECURITY DEFINER procedures
-- (R__trust_anchor_procedures.sql), invoked by the EXECUTE-only service role
-- `trust_anchor_public`. The schema (and its tables/procedures) is owned — via
-- implicit ownership — by whichever role runs this migration (the single DB
-- owner / CI-CD migration role), so the same script deploys under any owner/DB
-- name without edits. The migration MUST connect as the intended owner.
--
-- Prerequisite: the shared `util` schema + the DB owner (generate_ulid /
-- result_success / result_error) created by the platform util migration
-- (the shared `util` location). trust-anchor REUSES util rather
-- than duplicating the ULID + result-envelope primitives. Apply this location
-- with its own Flyway metadata table so its V-versions stay independent (README).
--
-- Scope: backs the CURRENT 4-method store.Store contract — versioned
-- `snapshot` and `bootstrap` objects, each with a "latest" (the newest row). The
-- multi-source projection tables (SOURCE / RAW_LIST / ANCHOR / RP_ENTRY)
-- arrive in later phases and are intentionally NOT created here.

-- No explicit AUTHORIZATION/OWNER: objects are owned by the migrating role
-- (implicit ownership), keeping the script owner-name-free and portable.
CREATE SCHEMA IF NOT EXISTS trust_anchor;

-- The migrating owner owns this schema and `util` (the shared location), so its
-- SECURITY DEFINER procedures here can call util.generate_ulid / util.result_success /
-- util.result_error directly — no extra grants needed (one owner across schemas).

-- ---------------------------------------------------------------------------
-- Tables. Append-only, versioned; "latest" = the highest `seq`. The full
-- serialized object is the SOURCE OF TRUTH (`content` jsonb); the extracted
-- columns are a queryable projection, never the authority.
-- ---------------------------------------------------------------------------

-- Versioned trust snapshots (store.SaveSnapshot / LoadLatestSnapshot).
CREATE TABLE IF NOT EXISTS trust_anchor.snapshot (
    row_id        text        PRIMARY KEY DEFAULT util.generate_ulid(),
    seq           bigint      GENERATED ALWAYS AS IDENTITY,
    snapshot_id   text        NOT NULL,             -- content-addressed Snapshot.ID (SHA-256)
    prev_id       text        NULL,
    generated_at  timestamptz NOT NULL,
    lotl_sequence bigint      NOT NULL DEFAULT 0,
    content       jsonb       NOT NULL,             -- full serialized trust.Snapshot (source of truth)
    created_at    timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_trust_anchor_snapshot_seq ON trust_anchor.snapshot (seq DESC);

-- Versioned approved bootstrap / pinned-signer set (store.SaveBootstrap /
-- LoadLatestBootstrap). The trust ROOT — operator-approved only.
CREATE TABLE IF NOT EXISTS trust_anchor.bootstrap (
    row_id       text        PRIMARY KEY DEFAULT util.generate_ulid(),
    seq          bigint      GENERATED ALWAYS AS IDENTITY,
    version      integer     NOT NULL,              -- monotonic Bootstrap.Version
    oj_reference text        NOT NULL DEFAULT '',
    seeded       boolean     NOT NULL DEFAULT false,
    activated_at timestamptz NOT NULL,
    content      jsonb       NOT NULL,              -- full serialized trust.Bootstrap (incl. CertsDER)
    created_at   timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_trust_anchor_bootstrap_latest ON trust_anchor.bootstrap (version DESC, seq DESC);

-- ---------------------------------------------------------------------------
-- Service role + least-privilege grants.
-- `trust_anchor_public` is the ONLY role the running trust-anchor service uses
-- (its `TRUST_STORE_DSN`): it can connect and EXECUTE the schema's procedures,
-- and has NO privileges on tables. Separation of duty: the owner runs
-- migrations; `trust_anchor_public` runs the service. The dev password is a
-- placeholder; production sets it from Vault and never commits it.
-- (Human/operator access is the per-schema `trust_anchor_read_role`, assigned by
-- the grants location if the deployment provisioned it; admins are superusers.)
-- ---------------------------------------------------------------------------
-- Role `trust_anchor_public` is provisioned (with its password) by the pg-roles init service from the
-- external .env, keeping credentials out of versioned migrations. This migration only
-- assigns its privileges below.

REVOKE ALL ON SCHEMA trust_anchor FROM PUBLIC;
REVOKE ALL ON ALL TABLES IN SCHEMA trust_anchor FROM PUBLIC;
REVOKE ALL ON trust_anchor.snapshot  FROM trust_anchor_public;
REVOKE ALL ON trust_anchor.bootstrap FROM trust_anchor_public;

GRANT USAGE ON SCHEMA trust_anchor TO trust_anchor_public;
-- Procedure EXECUTE grants live in the repeatable migration (R__).

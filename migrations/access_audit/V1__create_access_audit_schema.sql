-- V1: access-audit (GDPR-audit — GDPR personal-data access) store — the
-- `access_audit` schema.
--
-- Backs the reusable access-audit service: the synchronous, subject-indexed GDPR
-- access log that records WHO accessed WHOSE personal data, WHEN, and on what
-- lawful basis. It is built on the thick-procedure data layer: a per-domain
-- `access_audit` schema, the owner/service-role split, and access ONLY via
-- SECURITY DEFINER procedures (R__access_audit_procedures.sql) invoked by the
-- EXECUTE-only service role `access_audit_public`. The schema is owned by the
-- migrating role (the single DB owner / migration role).
--
-- Prerequisite: the shared `util` schema and its owner (generate_ulid /
-- result_success / result_error). access-audit REUSES util rather than
-- duplicating the ULID + result-envelope primitives. Apply this location with
-- its own Flyway metadata table so its V-versions stay independent.
--
-- Integrity model: this log is itself PII and is PURGED at
-- the end of a configurable accountability window, so it canNOT use eIDAS-audit's
-- single continuous hash-chain (deleting rows would snap it). Instead it is:
--   * append-only — UPDATE always blocked; DELETE only inside the purge procedure
--     (REVOKE + a guard trigger);
--   * per-row SEALED — `seal` is an HMAC-SHA256 the SERVICE computes over the
--     record's canonical bytes with a key held in Vault (NEVER in the DB), so a
--     party with only table access cannot forge a matching seal; and
--   * CHECKPOINTED per retention period — a sealed digest over a period's row
--     set, so a retained period can be proven intact even after older periods are
--     dropped (purge-compatible, see `checkpoint`).
-- The DB stores seals/checkpoints as opaque values; it never holds the HMAC key.

CREATE SCHEMA IF NOT EXISTS access_audit;

-- The migrating role owns this schema and `util`, so its
-- SECURITY DEFINER procedures here can call util.generate_ulid /
-- util.result_success / util.result_error directly — no extra grants needed (one
-- owner across schemas).

-- ---------------------------------------------------------------------------
-- Tables.
-- The full broker.Envelope is stored verbatim in `content` jsonb (the
-- record as the producer sent it — the bytes the seal is computed over); the
-- extracted columns are a queryable projection for subject-indexed DSAR lookups
-- and retention, never the authority. `source_service` / `system` are derived
-- by the service from the AUTHENTICATED identity, never from the record body,
-- and are outside the seal (server annotations).
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS access_audit.access_record (
    row_id           text         PRIMARY KEY DEFAULT util.generate_ulid(),
    seq              bigint       GENERATED ALWAYS AS IDENTITY,
    event_id         text         NOT NULL,            -- producer ULID; idempotency key
    occurred_at      timestamptz  NOT NULL,
    retention_period date         NOT NULL,            -- month bucket = date_trunc('month', occurred_at)
    event_type       text         NOT NULL,            -- event taxonomy (e.g. document.access)
    operation        text,                             -- read|create|update|delete|export
    outcome          text         NOT NULL,            -- success|failure|denied
    actor_id         text,                             -- acting identity / service id
    actor_type       text,                             -- "user" | "service"
    data_subjects    text[]       NOT NULL DEFAULT '{}', -- pseudonymous internal refs (DSAR index)
    resource_type    text,
    resource_id      text,
    lawful_basis     text,                             -- GDPR Art. 6 basis
    purpose          text,
    source_service   text,                             -- authenticated caller (derived, NOT from body)
    system           text         NOT NULL DEFAULT 'default', -- optional tenant/system dimension
    seal             text         NOT NULL,            -- hex HMAC-SHA256 over canonical bytes (key in Vault)
    content          jsonb        NOT NULL,            -- full broker.Envelope verbatim (sealed bytes' source)
    recorded_at      timestamptz  NOT NULL DEFAULT now(),
    CONSTRAINT uq_access_record_event UNIQUE (event_id)
);


-- Subject-indexed for DSAR ("every access to THIS person's data") — GIN over the
-- pseudonymous-ref array supports `:subject = ANY(data_subjects)`.
CREATE INDEX IF NOT EXISTS idx_access_record_subjects ON access_audit.access_record USING GIN (data_subjects);
-- Retention bucketing + checkpoint/purge scans.
CREATE INDEX IF NOT EXISTS idx_access_record_period   ON access_audit.access_record (retention_period);
-- Chronological listing within a DSAR / verify.
CREATE INDEX IF NOT EXISTS idx_access_record_occurred ON access_audit.access_record (occurred_at);

-- Per-retention-period sealed checkpoint. A single signed
-- digest over the period's row set (count + per-row seals, computed by the
-- service that holds the HMAC key), letting a retained period be proven intact
-- independently of any other period — the property that makes per-period purge
-- safe. Write-once per period (a closed period receives no new writes).
CREATE TABLE IF NOT EXISTS access_audit.checkpoint (
    retention_period date         PRIMARY KEY,
    row_count        bigint       NOT NULL,
    checkpoint_seal  text         NOT NULL,            -- hex HMAC-SHA256 over the period's ordered seals
    sealed_at        timestamptz  NOT NULL DEFAULT now()
);


-- Legal hold: records touching a held data subject are skipped by retention
-- purge (respect legal hold; the fact of deletion is itself retained for
-- everything else). Keyed by the pseudonymous subject ref.
CREATE TABLE IF NOT EXISTS access_audit.legal_hold (
    subject     text         PRIMARY KEY,
    reason      text         NOT NULL DEFAULT '',
    placed_by   text         NOT NULL DEFAULT '',
    placed_at   timestamptz  NOT NULL DEFAULT now()
);


-- ---------------------------------------------------------------------------
-- Append-only guard. Defense-in-depth on top of the role grants:
-- UPDATE is never allowed; DELETE is allowed ONLY when the purge procedure has
-- set the session-local `access_audit.allow_purge` flag (see purge_expired). Any
-- other UPDATE/DELETE — even by a role that somehow held the privilege — raises.
-- ---------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION access_audit.guard_append_only()
RETURNS trigger
LANGUAGE plpgsql
SET search_path = access_audit, pg_temp
AS $$
BEGIN
    IF TG_OP = 'UPDATE' THEN
        RAISE EXCEPTION '%', util.result_error('access_audit:append_only', 'access records are immutable') USING ERRCODE = 'P0001';
    END IF;
    -- DELETE: permitted only from the retention-purge path.
    IF current_setting('access_audit.allow_purge', true) IS DISTINCT FROM 'on' THEN
        RAISE EXCEPTION '%', util.result_error('access_audit:append_only', 'access records may only be removed by retention purge') USING ERRCODE = 'P0001';
    END IF;
    RETURN OLD;
END
$$;


DROP TRIGGER IF EXISTS trg_access_record_append_only ON access_audit.access_record;
CREATE TRIGGER trg_access_record_append_only
    BEFORE UPDATE OR DELETE ON access_audit.access_record
    FOR EACH ROW EXECUTE FUNCTION access_audit.guard_append_only();

-- ---------------------------------------------------------------------------
-- Service role + least-privilege grants.
-- `access_audit_public` is the ONLY role the running access-audit service uses
-- (its `ACCESS_AUDIT_STORE_DSN`): it can connect and EXECUTE the schema's
-- procedures, and has NO privileges on tables. Separation of duty: the migrating
-- role (owner) runs migrations; `access_audit_public` runs the service. The role
-- itself is created (with its password) outside the migrations by
-- provision-roles.sh from the environment, keeping credentials out of versioned
-- migrations; this migration only assigns its privileges. (Human/operator access
-- is the per-schema `access_audit_read_role` (SELECT within this schema only);
-- admins are superusers. This
-- schema holds PII + the accountability trail — grant per person, prefer read-only.)
-- ---------------------------------------------------------------------------

REVOKE ALL ON SCHEMA access_audit FROM PUBLIC;
REVOKE ALL ON ALL TABLES IN SCHEMA access_audit FROM PUBLIC;
REVOKE ALL ON access_audit.access_record FROM access_audit_public;
REVOKE ALL ON access_audit.checkpoint    FROM access_audit_public;
REVOKE ALL ON access_audit.legal_hold    FROM access_audit_public;

GRANT USAGE ON SCHEMA access_audit TO access_audit_public;
-- Procedure EXECUTE grants live in the repeatable migration (R__).

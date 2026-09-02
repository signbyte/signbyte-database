-- V1: eidas-audit (eIDAS-audit — eIDAS/ETSI signing evidence) store — the
-- `eidas_audit` schema.
--
-- Backs the eidas-audit service: the
-- lean, append-only, HASH-CHAINED legal record of material signing events that
-- proves WHO applied WHICH signature to WHICH document, WHEN, at what assurance
-- level. Producers (eparaksts-signer today; the Portal Signing Orchestrator later)
-- emit the frozen broker.Envelope to the broker topic `audit.signing` via the
-- go-eidas-audit library; the eidas-audit service CONSUMES that stream and lands
-- each event here. Built on the thick-procedure data layer: a per-domain
-- `eidas_audit` schema, the owner/service-role split, and access ONLY via
-- SECURITY DEFINER procedures (R__eidas_audit_procedures.sql) invoked by the
-- EXECUTE-only service role `eidas_audit_public`. The schema is owned by the
-- migrating role (the single DB owner / migration role).
--
-- This is its OWN schema + OWN role (least privilege): the
-- eIDAS-audit signing-evidence store never shares or reaches into the GDPR-audit GDPR
-- `access_audit` schema. The append-only event table is scoped to the
-- `eidas_audit` schema for isolation.
--
-- Prerequisite: the shared `util` schema and its owner (generate_ulid /
-- result_success / result_error). eidas-audit REUSES util rather than
-- duplicating the ULID + result-envelope primitives. Apply this location with
-- its own Flyway metadata table so its V-versions stay independent.
--
-- Integrity model: a single continuous HASH-CHAIN. Each row
-- carries `prev_hash` (the previous row's `hash`) and `hash`, both COMPUTED IN GO
-- by the sink over the event's canonical bytes; `eidas_audit.append_event` VERIFIES
-- the submitted `prev_hash` against the current chain head before inserting, so a
-- gap or re-order is rejected. The table is append-only — UPDATE always blocked,
-- DELETE only from the (deferred) retention-purge path (REVOKE + a guard trigger).
-- The full envelope is stored verbatim in `content` jsonb (the bytes
-- the hash is computed over); the extracted columns are a queryable projection,
-- never the authority. Unlike GDPR-audit's access_audit, there is NO per-row HMAC
-- seal / per-period checkpoint — the chain IS the tamper-evidence here.

CREATE SCHEMA IF NOT EXISTS eidas_audit;

-- The migrating role owns this schema and `util`, so its SECURITY
-- DEFINER procedures here call util.generate_ulid / util.result_success /
-- util.result_error directly — one owner across schemas, no extra grants.

-- ---------------------------------------------------------------------------
-- Table.
-- The full broker.Envelope is stored verbatim in `content` jsonb (the bytes
-- the Go sink computed `hash` over). The extracted columns are a lean queryable
-- projection (references only: no document bytes, certs,
-- OCSP/CRL, signatures, private keys; the go-eidas-audit emitter already strips
-- these). `source_service` is derived by the sink from the broker context, not the
-- record body. `seq` (identity) is the chain/insert order; `prev_hash`/`hash` are
-- the chain links.
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS eidas_audit.audit_event (
    row_id           text         PRIMARY KEY DEFAULT util.generate_ulid(),
    seq              bigint       GENERATED ALWAYS AS IDENTITY,
    event_id         text         NOT NULL,            -- producer ULID; idempotency key
    occurred_at      timestamptz  NOT NULL,
    source_service   text,                             -- publishing service (from broker context)
    event_type       text         NOT NULL,            -- e.g. signing.initiated/redirect/callback/applied
    categories       text[]       NOT NULL DEFAULT '{}', -- category[] (expect "signing")
    operation        text,                             -- read|create|update|delete|export|sign
    outcome          text         NOT NULL,            -- success|failure|denied
    actor_id         text,                             -- signer / service identity (pseudonymous)
    actor_type       text,                             -- "user" | "service"
    actor_assurance  text,                             -- LoA where relevant
    resource_type    text,                             -- e.g. document / envelope / job
    resource_id      text,
    correlation_id   text,
    trace_id         text,
    ip               text,
    device           text,
    data_subjects    text[]       NOT NULL DEFAULT '{}', -- pseudonymous internal refs (future GDPR-audit cross-ref)
    prev_hash        text         NOT NULL DEFAULT '',   -- previous row's hash ('' for the genesis event)
    hash             text         NOT NULL,              -- SHA-256(canonical(event) || prev_hash), computed in Go
    content          jsonb        NOT NULL,              -- full broker.Envelope verbatim (hashed bytes' source)
    received_at      timestamptz  NOT NULL DEFAULT now(),
    CONSTRAINT uq_audit_event_event UNIQUE (event_id),
    CONSTRAINT uq_audit_event_hash  UNIQUE (hash)
);


-- Chain-head lookup (ORDER BY seq DESC LIMIT 1) + verify scans.
CREATE INDEX IF NOT EXISTS idx_audit_event_seq      ON eidas_audit.audit_event (seq DESC);
-- Chronological listing.
CREATE INDEX IF NOT EXISTS idx_audit_event_occurred ON eidas_audit.audit_event (occurred_at);
-- Forward-looking: subject lookup for a future cross-reference to the GDPR access-audit store / DSAR.
CREATE INDEX IF NOT EXISTS idx_audit_event_subjects ON eidas_audit.audit_event USING GIN (data_subjects);

-- NOTE: physical native monthly range-partitioning of `audit_event` is DEFERRED
-- (same posture as access_audit shipped with) — today it is one table with an
-- `occurred_at` index. Retention/purge (`sweep_retention`) is a stub; when it
-- lands it will drop whole closed partitions. The hash-chain is GLOBAL (single
-- continuous chain), which a future partitioning scheme must preserve.

-- ---------------------------------------------------------------------------
-- Append-only guard. Defense-in-depth over the role grants: UPDATE
-- is never allowed; DELETE is allowed ONLY when the (future) purge path has set
-- the session-local `eidas_audit.allow_purge` flag. Any other UPDATE/DELETE — even
-- by a role that somehow held the privilege — raises. A tamper attempt that quietly
-- edits a row would also break the hash-chain on the next verify.
-- ---------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION eidas_audit.guard_append_only()
RETURNS trigger
LANGUAGE plpgsql
SET search_path = eidas_audit, pg_temp
AS $$
BEGIN
    IF TG_OP = 'UPDATE' THEN
        RAISE EXCEPTION '%', util.result_error('eidas_audit:append_only', 'audit events are immutable') USING ERRCODE = 'P0001';
    END IF;
    -- DELETE: permitted only from the retention-purge path.
    IF current_setting('eidas_audit.allow_purge', true) IS DISTINCT FROM 'on' THEN
        RAISE EXCEPTION '%', util.result_error('eidas_audit:append_only', 'audit events may only be removed by retention purge') USING ERRCODE = 'P0001';
    END IF;
    RETURN OLD;
END
$$;


DROP TRIGGER IF EXISTS trg_audit_event_append_only ON eidas_audit.audit_event;
CREATE TRIGGER trg_audit_event_append_only
    BEFORE UPDATE OR DELETE ON eidas_audit.audit_event
    FOR EACH ROW EXECUTE FUNCTION eidas_audit.guard_append_only();

-- ---------------------------------------------------------------------------
-- Service role + least-privilege grants.
-- `eidas_audit_public` is the ONLY role the running eidas-audit service uses (its
-- `EIDAS_AUDIT_STORE_DSN`): it can connect and EXECUTE the schema's procedures, and
-- has NO privileges on the table. Separation of duty: the migrating role (owner) runs
-- migrations; `eidas_audit_public` runs the service. The role itself is created
-- (with its password) outside the migrations by provision-roles.sh from the
-- environment, keeping credentials out of versioned migrations; this migration only
-- assigns its privileges. (Human/operator access is the per-schema
-- `eidas_audit_read_role` — scoped here and nowhere else, so reading the evidence
-- trail is a distinct grant; admins are named superusers. This schema is the legal evidence
-- trail — grant per person, prefer read-only; the append-only revoke protects it regardless.)
-- ---------------------------------------------------------------------------

REVOKE ALL ON SCHEMA eidas_audit FROM PUBLIC;
REVOKE ALL ON ALL TABLES IN SCHEMA eidas_audit FROM PUBLIC;
REVOKE ALL ON eidas_audit.audit_event FROM eidas_audit_public;

GRANT USAGE ON SCHEMA eidas_audit TO eidas_audit_public;
-- Procedure EXECUTE grants live in the repeatable migration (R__).

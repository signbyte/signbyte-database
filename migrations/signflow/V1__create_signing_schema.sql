-- V1: signflow (Signing Orchestrator) — the `signing` schema.
--
-- Backs the signflow service: the portal's signing conductor. This schema holds
-- the DURABLE portal-side state the Orchestrator owns:
--   * signing_job       — the slot↔eparaksts-signer jobId mapping, persisted BEFORE
--                         the user-driven redirect so reconciliation survives it
--                         (the idempotency key is the job_id PK).
--   * signature_record  — the lifecycle record of an applied signature, carrying the
--                         at-signing validation pass/fail, the flow used, format/level,
--                         the container ref, the qualified-timestamp ref, and the
--                         preservation class.
--
-- The SignAPI session/job aggregate lives in eparaksts-signer's Redis — NOT here.
-- Document BYTES live in the document-store (S3) — NOT here. signflow is byte-free
-- for hash-only XAdES.
--
-- Built on a thick-procedure data layer: access ONLY via SECURITY DEFINER procedures
-- (R__signflow_procedures.sql) invoked by the EXECUTE-only `signing_public` role. The
-- schema is owned by the migrating role (the single DB owner / migration role).
-- signflow owns both the `signing` and `validation` schemas and connects with the one
-- `signing_public` role.
--
-- Prerequisite: the shared `util` schema + its owner role (generate_ulid /
-- result_success / result_error), the `util` schema migration. The
-- `signing_public` role is provisioned (with its password) by the pg-roles init job
-- from the external .env (SIGNING_PUBLIC_PW); this migration only assigns privileges.
-- No cross-schema FKs (envelope/slot/document/validation refs are plain ids).

CREATE SCHEMA IF NOT EXISTS signing;

-- ---------------------------------------------------------------------------
-- Table `signing.signing_job` — slot ↔ eparaksts-signer jobId mapping.
-- Persisted before the redirect; reconciled idempotently on return (job_id PK is
-- the idempotency key). caller_sub carries the authenticated person through for the
-- login↔signing binding.
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS signing.signing_job (
    job_id      text         PRIMARY KEY,                 -- eparaksts-signer jobId (idempotency key)
    envelope_id text         NOT NULL,                    -- plain id (no cross-schema FK)
    slot_id     text         NOT NULL,                    -- plain id
    flow        text         NOT NULL,                    -- eid | eidScan | mobile | cloudEseal | csc
    sig_format  text         NOT NULL,                    -- PAdES | XAdES
    state       text         NOT NULL DEFAULT 'PREPARING',-- mirrors eparaksts-signer job state (reconciled)
    caller_sub  text         NOT NULL,                    -- authenticated person sub (binding)
    created_at  timestamptz  NOT NULL DEFAULT now(),
    updated_at  timestamptz  NOT NULL DEFAULT now(),
    CONSTRAINT ck_signing_job_flow   CHECK (flow IN ('eid', 'eidScan', 'mobile', 'cloudEseal', 'csc')),
    CONSTRAINT ck_signing_job_format CHECK (sig_format IN ('PAdES', 'XAdES'))
);


CREATE INDEX IF NOT EXISTS idx_signing_job_envelope ON signing.signing_job (envelope_id);
CREATE INDEX IF NOT EXISTS idx_signing_job_slot     ON signing.signing_job (slot_id);

-- ---------------------------------------------------------------------------
-- Table `signing.signature_record` — the applied-signature lifecycle record.
-- One row per applied signature (co-signing adds a second row). Carries the
-- at-signing validation result + a ref to the normalized validation report
-- (validation.report, plain id — no cross-schema FK).
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS signing.signature_record (
    id                 text         PRIMARY KEY DEFAULT util.generate_ulid(),
    job_id             text         NOT NULL,             -- → signing_job.job_id (plain id)
    envelope_id        text         NOT NULL,
    slot_id            text         NOT NULL,
    flow_used          text         NOT NULL,             -- which flow delivered it
    sig_format         text         NOT NULL,             -- PAdES | XAdES
    level              text,                              -- QES | AdES (from normalized DSS)
    signed_document_ref text,                             -- document-store signed-output id (an ASiC container for XAdES, a signed PDF for PAdES)
    timestamp_ref      text,                              -- qualified signature timestamp
    validated          boolean      NOT NULL DEFAULT false, -- at-signing validation pass/fail
    validation_id      text,                              -- → validation.report.id (plain id)
    preservation_class text         NOT NULL DEFAULT 'none', -- none | b_lt | preservation
    created_at         timestamptz  NOT NULL DEFAULT now(),
    CONSTRAINT ck_sigrec_format CHECK (sig_format IN ('PAdES', 'XAdES')),
    CONSTRAINT ck_sigrec_presv  CHECK (preservation_class IN ('none', 'b_lt', 'preservation'))
);


CREATE INDEX IF NOT EXISTS idx_sigrec_job      ON signing.signature_record (job_id);
CREATE INDEX IF NOT EXISTS idx_sigrec_envelope ON signing.signature_record (envelope_id);
CREATE INDEX IF NOT EXISTS idx_sigrec_slot     ON signing.signature_record (slot_id);

-- Keep updated_at current on signing_job mutations.
CREATE OR REPLACE FUNCTION signing.touch_updated_at()
RETURNS trigger
LANGUAGE plpgsql
SET search_path = signing, pg_temp
AS $$
BEGIN
    NEW.updated_at := now();
    RETURN NEW;
END
$$;


DROP TRIGGER IF EXISTS trg_signing_job_touch ON signing.signing_job;
CREATE TRIGGER trg_signing_job_touch
    BEFORE UPDATE ON signing.signing_job
    FOR EACH ROW EXECUTE FUNCTION signing.touch_updated_at();

-- ---------------------------------------------------------------------------
-- Service role + least-privilege grants. `signing_public` is the
-- ONLY role the running signflow service uses (its SIGNING_STORE_DSN): USAGE on the
-- schema + EXECUTE on its procedures (granted in R__), and NO privileges on
-- tables/sequences. The role is created (with its password) by the pg-roles init
-- job from the external .env; this migration only assigns privileges.
-- ---------------------------------------------------------------------------
REVOKE ALL ON SCHEMA signing FROM PUBLIC;
REVOKE ALL ON ALL TABLES IN SCHEMA signing FROM PUBLIC;
REVOKE ALL ON signing.signing_job        FROM signing_public;
REVOKE ALL ON signing.signature_record   FROM signing_public;

GRANT USAGE ON SCHEMA signing TO signing_public;
-- Procedure EXECUTE grants live in the repeatable migration (R__).

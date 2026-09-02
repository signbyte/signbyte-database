-- V1: envelope (Envelope/Workflow service) — the `envelope` schema.
--
-- Backs the envelope service: the portal's WORKFLOW BRAIN.
-- It owns the durable, authoritative workflow state — the multi-document, multi-signer
-- envelope, its signer slots, the signing order, and the state machine:
--   * envelope          — the transaction: owner, status, order_policy, optimistic
--                         `version` for compare-and-set transitions.
--   * envelope_document — the document refs (document-store ULIDs, plain ids) + the
--                         content_hash pinned at attach (the "both parties sign the
--                         same document" invariant — no cross-schema FK to document).
--   * signer_slot       — one row per signer position: order_index, role, the intended
--                         flow + required assurance, status, and the linkage back to
--                         the signing orchestrator's signing_job / signature_record
--                         (job_id / signature_id / signed_doc_ref) set when signing
--                         starts and on the slot-signed callback.
--
-- The envelope holds NO document bytes (document-store / S3 owns those) and NO
-- signature crypto/evidence (signflow + eparaksts-signer own that). It references
-- documents + signing jobs by plain id — no cross-schema FKs.
--
-- Built on the thick-procedure data layer: access
-- ONLY via SECURITY DEFINER procedures (R__envelope_procedures.sql) invoked by the
-- EXECUTE-only `envelope_public` role. The schema is owned by the migrating role (the
-- single DB owner / migration role).
--
-- Prerequisite: the shared `util` schema + its owner (generate_ulid /
-- result_success / result_error), the `util` schema migration. The
-- `envelope_public` role is provisioned (with its password) by the pg-roles init job
-- from the external .env (ENVELOPE_PUBLIC_PW); this migration only assigns privileges.

CREATE SCHEMA IF NOT EXISTS envelope;

-- ---------------------------------------------------------------------------
-- Table `envelope.envelope` — the signing transaction + its state machine.
-- `version` is the optimistic-concurrency token: every transition is a CAS
-- (apply_transition) that bumps it, so concurrent BFF actions + the orchestrator
-- callback can't lose/double a transition. owner = the person sub
-- (owner-filtered, no IDOR — mirrors document-store).
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS envelope.envelope (
    id           text         PRIMARY KEY DEFAULT util.generate_ulid(),
    owner        text         NOT NULL,                  -- person sub (owner-filtered)
    tenant_id    text,                                   -- nullable; B2B-readiness seam
    title        text,
    status       text         NOT NULL DEFAULT 'draft',
    order_policy text         NOT NULL DEFAULT 'parallel',
    profile      text,                                   -- signing profile/preset (seam)
    expiry       timestamptz,
    version      integer      NOT NULL DEFAULT 0,        -- optimistic CAS token
    created_at   timestamptz  NOT NULL DEFAULT now(),
    updated_at   timestamptz  NOT NULL DEFAULT now(),
    CONSTRAINT ck_env_status CHECK (status IN
      ('draft', 'sent', 'in_progress', 'completed', 'declined', 'expired', 'cancelled')),
    CONSTRAINT ck_env_order  CHECK (order_policy IN ('parallel', 'sequential'))
);


CREATE INDEX IF NOT EXISTS idx_envelope_owner  ON envelope.envelope (owner);
CREATE INDEX IF NOT EXISTS idx_envelope_status ON envelope.envelope (status);
CREATE INDEX IF NOT EXISTS idx_envelope_expiry ON envelope.envelope (expiry);

-- ---------------------------------------------------------------------------
-- Table `envelope.envelope_document` — the document refs in an envelope.
-- content_hash is pinned at attach (read from document-store on-behalf-of the user):
-- the machine-checkable "same document" invariant. No bytes here.
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS envelope.envelope_document (
    envelope_id  text         NOT NULL REFERENCES envelope.envelope(id) ON DELETE CASCADE,
    document_id  text         NOT NULL,                  -- document-store ULID (plain id)
    content_hash text         NOT NULL,                  -- SHA-256/base64, pinned at attach
    added_at     timestamptz  NOT NULL DEFAULT now(),
    PRIMARY KEY (envelope_id, document_id)
);


-- ---------------------------------------------------------------------------
-- Table `envelope.signer_slot` — one signer position in the envelope.
-- order_index drives sequential ordering; the job_id / signature_id / signed_doc_ref
-- columns are the linkage to the signing orchestrator (set when signing starts and on
-- the slot-signed callback). role allows the P2 approver/observer values in
-- the enum (seam) though MVP only creates 'signer'.
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS envelope.signer_slot (
    id             text         PRIMARY KEY DEFAULT util.generate_ulid(),
    envelope_id    text         NOT NULL REFERENCES envelope.envelope(id) ON DELETE CASCADE,
    order_index    integer      NOT NULL,
    identity_ref   text,                                 -- nullable, low-PII
    role           text         NOT NULL DEFAULT 'signer',
    flow           text,                                 -- intended flow (camelCase)
    required_loa   text,                                 -- assurance gate at sign (nullable)
    status         text         NOT NULL DEFAULT 'draft',
    job_id         text,                                 -- → signing.signing_job.job_id (plain id)
    signature_id   text,                                 -- → signing.signature_record.id (plain id)
    signed_doc_ref text,                                 -- → document-store signed-container id
    signed_at      timestamptz,
    CONSTRAINT ck_slot_status CHECK (status IN
      ('draft', 'sent', 'in_progress', 'signed', 'declined')),
    CONSTRAINT ck_slot_role   CHECK (role IN ('signer', 'approver', 'observer')),
    CONSTRAINT ck_slot_flow   CHECK (flow IS NULL OR flow IN
      ('webEid', 'eidScan', 'eparakstsMobile', 'eparakstsMobileEseal', 'csc')),
    CONSTRAINT uq_slot_order  UNIQUE (envelope_id, order_index)
);


CREATE INDEX IF NOT EXISTS idx_slot_envelope ON envelope.signer_slot (envelope_id);

-- Keep envelope.updated_at current on any envelope mutation.
CREATE OR REPLACE FUNCTION envelope.touch_updated_at()
RETURNS trigger
LANGUAGE plpgsql
SET search_path = envelope, pg_temp
AS $$
BEGIN
    NEW.updated_at := now();
    RETURN NEW;
END
$$;


DROP TRIGGER IF EXISTS trg_envelope_touch ON envelope.envelope;
CREATE TRIGGER trg_envelope_touch
    BEFORE UPDATE ON envelope.envelope
    FOR EACH ROW EXECUTE FUNCTION envelope.touch_updated_at();

-- ---------------------------------------------------------------------------
-- Service role + least-privilege grants. `envelope_public` is the
-- ONLY role the running envelope service uses (its ENVELOPE_STORE_DSN): USAGE on the
-- schema + EXECUTE on its procedures (granted in R__), and NO privileges on
-- tables/sequences. The role is created (with its password) by the pg-roles init job
-- from the external .env; this migration only assigns privileges.
-- ---------------------------------------------------------------------------
REVOKE ALL ON SCHEMA envelope FROM PUBLIC;
REVOKE ALL ON ALL TABLES IN SCHEMA envelope FROM PUBLIC;
REVOKE ALL ON envelope.envelope          FROM envelope_public;
REVOKE ALL ON envelope.envelope_document FROM envelope_public;
REVOKE ALL ON envelope.signer_slot       FROM envelope_public;

GRANT USAGE ON SCHEMA envelope TO envelope_public;
-- Procedure EXECUTE grants live in the repeatable migration (R__).

-- V1: document store — the `document` schema.
--
-- Backs the document-store service: the single source of truth for document
-- BYTES and HASHES. The service owns ingest, the canonical SHA-256, encrypted S3
-- storage with a 24h TTL, ASiC-E assembly/completion, and retention; this schema
-- is the METADATA layer. It is built on the thick-procedure data layer: a
-- per-domain `document` schema, the owner/service-role split, and access ONLY via
-- SECURITY DEFINER procedures (R__document_procedures.sql) invoked by the
-- EXECUTE-only service role `document_public`. The schema is owned by the
-- migrating role (the single DB owner / migration role).
--
-- This is its OWN schema + OWN role (least privilege): it never shares or reaches
-- into another domain's schema, and the service connects only with
-- `document_public` via its `DOCUMENT_STORE_DSN`.
--
-- Prerequisite: the shared `util` schema + the migrating role (generate_ulid /
-- result_success / result_error) created by the `util` schema migration.
-- document REUSES util rather than duplicating the ULID + result-envelope
-- primitives. Apply this location with its own migration-history table so its
-- V-versions stay independent.
--
-- BYTES LIVE ELSEWHERE. This schema holds NO document content: bytes are
-- envelope-encrypted in S3 (byte-ownership) and reachable only via the
-- `storage_ref` (S3 object key) + `encryption_key_ref` (the KMS-wrapped per-object
-- data key). The canonical `content_hash` is the digest the signing orchestrator
-- fetches — it never recomputes one.

CREATE SCHEMA IF NOT EXISTS document;

-- The migrating role owns this schema and `util`, so its
-- SECURITY DEFINER procedures here call util.generate_ulid / util.result_success /
-- util.result_error directly — one owner across schemas, no extra grants.

-- ---------------------------------------------------------------------------
-- Table `document.document`.
--
-- Base columns for the document metadata model. The rows flagged "(addition)"
-- are extensions to that base model:
--   * kind / parent_id    — uploaded `source` vs assembled `container`.
--   * preservation_class  — long-term preservation selection seam (B-LT vs preservation).
--   * filename            — the original upload name, required by the ASiC-E
--                           packager (asice.CheckReferences matches count +
--                           FILENAME + SHA-256) and for download Content-Disposition.
--
-- NO cross-schema FKs (references such as `owner`/`tenant_id`/
-- `parent_id` are plain ids). `parent_id` is a self-reference (container→source),
-- intentionally NOT a hard FK so a purged source never blocks a container row.
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS document.document (
    id                  text         PRIMARY KEY DEFAULT util.generate_ulid(),
    owner               text         NOT NULL,                     -- authenticated person `sub`; ownership filter (no IDOR)
    tenant_id           text,                                      -- B2B-ready (Phase 4); plain id, no cross-schema FK
    kind                text         NOT NULL DEFAULT 'source',    -- (addition) source | container
    parent_id           text,                                      -- (addition) container → its source document (self-ref, plain id)
    filename            text         NOT NULL DEFAULT '',          -- (addition) original upload name (ASiC-E manifest match + download)
    storage_ref         text,                                      -- S3 object key (NULL once purged)
    content_hash        text         NOT NULL,                     -- canonical SHA-256 — base64; the digest the orchestrator fetches
    mime                text         NOT NULL,
    size                bigint       NOT NULL,
    status              text         NOT NULL DEFAULT 'received',  -- received | signing | signed | expired | deleted
    encryption_key_ref  text,                                      -- KMS-wrapped per-object data-key ref (NULL once destroyed)
    preservation_class  text         NOT NULL DEFAULT 'none',      -- (addition) none | b_lt | preservation
    retention_until     timestamptz  NOT NULL,                     -- 24h TTL clock — distinct from the SignAPI session TTL
    legal_hold          boolean      NOT NULL DEFAULT false,       -- blocks purge
    created_at          timestamptz  NOT NULL DEFAULT now(),
    updated_at          timestamptz  NOT NULL DEFAULT now(),
    CONSTRAINT ck_document_kind   CHECK (kind IN ('source', 'container')),
    CONSTRAINT ck_document_status CHECK (status IN ('received', 'signing', 'signed', 'expired', 'deleted')),
    CONSTRAINT ck_document_presv  CHECK (preservation_class IN ('none', 'b_lt', 'preservation'))
);


-- Indexes: owner-scoped listing + no-IDOR get, status filters, the
-- retention sweep scan, and container→source lookups.
CREATE INDEX IF NOT EXISTS idx_document_owner          ON document.document (owner);
CREATE INDEX IF NOT EXISTS idx_document_status         ON document.document (status);
CREATE INDEX IF NOT EXISTS idx_document_retention      ON document.document (retention_until);
CREATE INDEX IF NOT EXISTS idx_document_parent         ON document.document (parent_id);

-- Keep updated_at current on every row mutation (the procedures always go through
-- the table owner, so a trigger is the simplest single source of truth).
CREATE OR REPLACE FUNCTION document.touch_updated_at()
RETURNS trigger
LANGUAGE plpgsql
SET search_path = document, pg_temp
AS $$
BEGIN
    NEW.updated_at := now();
    RETURN NEW;
END
$$;


DROP TRIGGER IF EXISTS trg_document_touch ON document.document;
CREATE TRIGGER trg_document_touch
    BEFORE UPDATE ON document.document
    FOR EACH ROW EXECUTE FUNCTION document.touch_updated_at();

-- ---------------------------------------------------------------------------
-- Service role + least-privilege grants.
-- `document_public` is the ONLY role the running document-store service uses (its
-- `DOCUMENT_STORE_DSN`): it can connect and EXECUTE the schema's procedures, and
-- has NO privileges on the table/sequences. Separation of duty: the migrating
-- role (owner) runs migrations; `document_public` runs the service. (Human/operator
-- access is the per-schema `document_read_role` / `document_write_role`, granted by
-- the grants location only if the deployment provisioned them; admins are named
-- superusers.)
-- ---------------------------------------------------------------------------
-- The role itself is created (with its password) outside the migrations by
-- provision-roles.sh from the environment, keeping credentials out of versioned
-- migrations. This migration only assigns its privileges below.

REVOKE ALL ON SCHEMA document FROM PUBLIC;
REVOKE ALL ON ALL TABLES IN SCHEMA document FROM PUBLIC;
REVOKE ALL ON document.document FROM document_public;

GRANT USAGE ON SCHEMA document TO document_public;
-- Procedure EXECUTE grants live in the repeatable migration (R__).

-- V2: document store — the multi-party access-control list (`document_acl`).
--
-- Adds standing, reference-counted access to a document CHAIN for parties beyond
-- its creator: the people invited to co-sign it. Until now a document was
-- reachable only by its `owner` sub (the no-IDOR owner filter). A co-signed
-- document is ONE shared container (not a copy per party): every participating
-- author holds standing read + co-sign access to it, keyed on their eIDAS
-- identity, and a delete removes only the caller's own access — the bytes live
-- while any access remains (reference count), honouring legal hold. The creator
-- is just one entry, so a personal document is a single-entry list that behaves
-- exactly as the owner filter did before (additive — no behaviour change for the
-- solo case).
--
-- Access is anchored on the logical CHAIN ROOT (the original source document id),
-- so one entry covers the source and every co-signed container derived from it
-- (the blob is replaced on each co-sign; access must hang off the stable root).
-- The list holds NO bytes or keys — it is purely the access layer, orthogonal to
-- the signature evidence inside the container.
--
-- Prerequisite: V1 (the `document` schema + the `document_public` role) + the
-- shared `util` schema (generate_ulid). NO cross-schema FKs (plain ids), and
-- `chain_root_id` is intentionally not a hard FK so a purged source never blocks
-- the access rows of a container that outlived it.

CREATE TABLE IF NOT EXISTS document.document_acl (
    id              text         PRIMARY KEY DEFAULT util.generate_ulid(),
    chain_root_id   text         NOT NULL,                     -- the chain root (original source id); plain id, no FK
    principal_kind  text         NOT NULL,                     -- sub | serial
    principal_id    text         NOT NULL,                     -- the token sub (creator) or the normalized eIDAS serial (invited co-signer)
    rights          text[]       NOT NULL,                     -- subset of {read, cosign}
    tenant_id       text,                                      -- B2B-ready (Phase 4); plain id, no cross-schema FK
    granted_by      text         NOT NULL,                     -- who granted: the creator sub at upload, or the workflow service at send
    granted_at      timestamptz  NOT NULL DEFAULT now(),
    CONSTRAINT ck_document_acl_kind   CHECK (principal_kind IN ('sub', 'serial')),
    CONSTRAINT ck_document_acl_rights CHECK (rights <@ ARRAY['read', 'cosign']::text[] AND cardinality(rights) > 0),
    CONSTRAINT uq_document_acl_principal UNIQUE (chain_root_id, principal_kind, principal_id)
);


-- Authorization lookups hit the chain root (the get/cosign/delete path) and the
-- principal (the "my documents" list scan).
CREATE INDEX IF NOT EXISTS idx_document_acl_root      ON document.document_acl (chain_root_id);
CREATE INDEX IF NOT EXISTS idx_document_acl_principal ON document.document_acl (principal_kind, principal_id);

-- Access is via SECURITY DEFINER procedures (R__), which run as the owner;
-- the EXECUTE-only service role gets no direct table privilege.
REVOKE ALL ON document.document_acl FROM PUBLIC;
REVOKE ALL ON document.document_acl FROM document_public;

-- ---------------------------------------------------------------------------
-- Backfill: every existing chain root gets a creator entry for its owner, so the
-- new ACL authorization is a strict SUPERSET of the prior owner filter — no
-- already-stored document becomes unreachable. The chain root is the source id
-- (a row's parent_id, else its own id); the owner is preserved across a chain
-- (a co-signed container stays owned by the document owner), so one entry per
-- root suffices and covers containers whose source row was already purged.
-- Idempotent: re-running (or running after rows already have entries from the
-- V2 insert path) is a no-op via the unique constraint.
-- ---------------------------------------------------------------------------
INSERT INTO document.document_acl (chain_root_id, principal_kind, principal_id, rights, tenant_id, granted_by)
SELECT DISTINCT
    COALESCE(NULLIF(d.parent_id, ''), d.id) AS chain_root_id,
    'sub',
    d.owner,
    ARRAY['read', 'cosign']::text[],
    d.tenant_id,
    d.owner
FROM document.document d
WHERE d.status <> 'deleted'
ON CONFLICT (chain_root_id, principal_kind, principal_id) DO NOTHING;

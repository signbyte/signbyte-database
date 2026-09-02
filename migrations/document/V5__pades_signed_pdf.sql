-- PAdES (PDF) signing storage. A PAdES signature is embedded IN the PDF (no
-- ASiC-E container), so the finished signed PDF is stored directly as its own
-- artifact form: kind='pdf'. `kind` names the signed artifact FORM (source =
-- an unsigned upload of any type · container = a signed ASiC-E · pdf = a signed
-- PDF); `status` carries signed-ness, `parent_id` the chain lineage. An unsigned
-- upload stays 'source', so kind='pdf' only ever appears for a signed output
-- (set at signing, never at upload) — a single PDF signs to a 'pdf', while
-- multiple files bundle to a 'container'.

-- 1. Allow the new form. Widen the kind check to include 'pdf'.
ALTER TABLE document.document DROP CONSTRAINT IF EXISTS ck_document_kind;
ALTER TABLE document.document
    ADD CONSTRAINT ck_document_kind CHECK (kind IN ('source', 'container', 'pdf'));

-- 2. One live signed PDF per chain (the PAdES analog of uq_one_container_per_chain).
-- PAdES co-signing is a sequential incremental update: each co-signer signs the
-- CURRENT signed PDF, producing a new one that embeds the prior signatures and
-- supersedes it (keep-latest; the prior is marked deleted, its bytes purge). Two
-- parties who sign the same base at the exact same moment cannot be merged (unlike
-- ASiC-E), so this index makes the second concurrent creation fail — the insert
-- procedure turns that into the chain-advanced signal, and the loser re-resolves
-- the now-current signed PDF and re-signs. Scoped to live rows so a purged/
-- superseded (deleted) PDF never blocks a fresh one.
CREATE UNIQUE INDEX IF NOT EXISTS uq_one_signed_pdf_per_chain
    ON document.document (parent_id)
    WHERE kind = 'pdf' AND status <> 'deleted';

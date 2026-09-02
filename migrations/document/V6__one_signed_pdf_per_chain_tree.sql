-- One live signed PDF per chain TREE, not per parent_id.
--
-- An uploaded already-signed PDF is ingested as its own chain root (kind='pdf',
-- status='signed', no parent). The per-parent uniqueness missed that shape: the
-- signed root (parent NULL) and a signed child under it (parent = root) carry
-- different index keys, so signing an uploaded pre-signed PDF left the chain
-- with TWO live signed rows — the root orphaned once the child superseded it as
-- the head. The real invariant is per chain tree: at most one live signed PDF
-- under COALESCE(parent_id, id).

-- 1. Collapse existing pile-ups. Where a live signed child exists, the signed
-- root it hangs off is the superseded prior version: a PDF co-signature is an
-- incremental update over the current bytes, so the child embeds every
-- signature the root carried — marking the root deleted loses nothing
-- (keep-latest semantics, applied late). The blob refs are deliberately KEPT:
-- a deleted row's bytes are destroyed at delete time by the application, which
-- a migration cannot do, so the retained refs are the pointer an operator uses
-- to destroy the stray stored objects out-of-band
--   (SELECT id, storage_ref FROM document.document
--     WHERE status = 'deleted' AND kind = 'pdf' AND storage_ref IS NOT NULL).
UPDATE document.document r
   SET status = 'deleted'
 WHERE r.kind = 'pdf'
   AND r.status <> 'deleted'
   AND NULLIF(r.parent_id, '') IS NULL
   AND EXISTS (
       SELECT 1 FROM document.document c
       WHERE c.parent_id = r.id AND c.kind = 'pdf' AND c.status <> 'deleted'
   );

-- 2. Re-scope the uniqueness to the chain tree. Same live-rows predicate as
-- before (a purged/superseded PDF never blocks a fresh one); the key becomes
-- the chain root, so a signed root and a child under it now collide — the
-- insert procedure turns that into the chain-advanced signal and the caller
-- supersedes the current signed PDF in place instead.
DROP INDEX IF EXISTS document.uq_one_signed_pdf_per_chain;
CREATE UNIQUE INDEX IF NOT EXISTS uq_one_signed_pdf_per_chain
    ON document.document ((COALESCE(NULLIF(parent_id, ''), id)))
    WHERE kind = 'pdf' AND status <> 'deleted';

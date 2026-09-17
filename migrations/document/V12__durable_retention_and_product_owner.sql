-- V12: a document may be kept until its owner releases it, and its owner may be a
-- product acting for an organisation rather than a person.
--
-- Two capabilities arrive together because neither is usable alone.
--
-- 1. WHO DECIDES THE RETENTION DATE.
--    Every document so far has been given a date by the service at the moment it was
--    stored, and swept once that date passed. That suits a document a person uploads
--    to sign and forget. It does not suit a file attached to a piece of work, which
--    has to still be there next year.
--    `retention_class` records who decides the date, and NOT whether a date exists:
--      * `ttl`     — the service sets it at insert, exactly as before. The default,
--                    so every row already stored keeps its present behaviour.
--      * `durable` — the owner sets it. The owner may leave it unset, and then
--                    nothing removes the document until the owner releases it; or
--                    the owner may set a date of its own, because an organisation's
--                    own data-protection policy may bound how long it holds a file.
--    An owner-set date is enforced by the same sweep as any other: it is the owner's
--    own instruction, carried out later. A retention limit that depends on the caller
--    remembering to come back is a promise, not a control.
--    This is deliberately NOT `preservation_class`, which says how well a SIGNATURE is
--    preserved. A document can be signature-preserved and short-lived, or unsigned and
--    kept for years; folding the two together would make an archive-timestamp refresh
--    silently change how long a document is held.
--
-- 2. WHO OWNS IT.
--    An access entry has named either a person's subject or an invited signatory's
--    identity code. A file attached to a piece of work belongs to neither: it belongs
--    to the PRODUCT that stored it, acting for one organisation. `product` is that
--    third kind of principal. Its id names the product and the organisation together,
--    and is derived from the calling credential rather than from anything in the
--    request — so rotating that credential leaves ownership untouched, and a document
--    stored for one organisation can never be reached by a token belonging to another.
--    A document nobody is left able to release is a document nobody can ever delete,
--    which is why the owner must outlive the credential.

-- ---------------------------------------------------------------------------
-- 1. The retention class.
-- ---------------------------------------------------------------------------
ALTER TABLE document.document
    ADD COLUMN IF NOT EXISTS retention_class text NOT NULL DEFAULT 'ttl';

DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_constraint
         WHERE conname = 'ck_document_retention_class'
           AND conrelid = 'document.document'::regclass
    ) THEN
        ALTER TABLE document.document
            ADD CONSTRAINT ck_document_retention_class
            CHECK (retention_class IN ('ttl', 'durable'));
    END IF;
END $$;

-- A durable document that its owner has not dated carries no date at all. Storing a
-- placeholder instead would be storing something untrue, and a later reader — or a
-- later sweep — would eventually believe it.
--
-- Idempotent by nature: dropping a NOT NULL that is already gone is a no-op.
ALTER TABLE document.document
    ALTER COLUMN retention_until DROP NOT NULL;

-- ---------------------------------------------------------------------------
-- 2. The product principal.
-- ---------------------------------------------------------------------------
-- The existing canonical-identity constraint stays as it is: it applies only when the
-- principal is an identity code, so a product principal passes it untouched. That
-- conditionality is the reason this migration does not have to revisit it.
DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_constraint
         WHERE conname = 'ck_document_acl_kind'
           AND conrelid = 'document.document_acl'::regclass
           AND pg_get_constraintdef(oid) LIKE '%product%'
    ) THEN
        ALTER TABLE document.document_acl DROP CONSTRAINT IF EXISTS ck_document_acl_kind;
        ALTER TABLE document.document_acl
            ADD CONSTRAINT ck_document_acl_kind
            CHECK (principal_kind IN ('sub', 'serial', 'product'));
    END IF;
END $$;

-- ---------------------------------------------------------------------------
-- 3. Make room for the authorization helper to learn the third principal.
-- ---------------------------------------------------------------------------
-- `document.acl_allows` gains a parameter, which means a new signature: replacing it
-- in the repeatable file would leave the old three-principal version standing beside
-- the new one and every call ambiguous. It is dropped here so the repeatable file
-- recreates exactly one. Its callers resolve it at run time, and the repeatable file
-- is applied after this one, so nothing is left pointing at a function that is gone.
DROP FUNCTION IF EXISTS document.acl_allows(text, text, text, text);

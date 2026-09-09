-- V11: an ACL entry that names a person by their identity code stores that code in
-- one canonical spelling, and the database refuses any other.
--
-- `document_acl` is what makes a co-signed document reachable by the people invited
-- to it: a `serial` principal is an eIDAS identity code, and access is granted by
-- comparing it with the code of whoever is asking. Compared as text, the same person
-- granted access under one spelling and arriving with another was refused — and
-- refused as `:not_found`, deliberately indistinguishable from a document that does
-- not exist, so nothing about the failure said "your access is here, spelled
-- differently".
--
-- `document.normalize_serial` was always the seam for this: its own comment promised
-- that "fuller cross-border normalization (country prefixes, separators) is a planned
-- extension behind THIS seam". This migration is that extension arriving — the
-- function now delegates to the one platform-wide implementation (`R__`), and the
-- constraint below makes the stored side of the comparison uniform so the seam has
-- something to be uniform about.
--
-- `UNIQUE (chain_root_id, principal_kind, principal_id)`, the ON CONFLICT upsert in
-- `document.grant_acl` and the principal index are deliberately UNCHANGED: with one
-- spelling at rest, matching stays plain equality.

-- 1. Convert what is already stored, BEFORE the constraint exists.
--
-- Only `serial` principals are identity codes. A `sub` principal is this platform's
-- own internal person subject — an opaque id that is not an identity code and must
-- never be rewritten as though it were; the WHERE clause is what keeps this
-- migration off it.
--
-- On a fresh database this is a no-op. It stays here because it is what keeps the
-- constraint from failing on a database that is NOT fresh — an environment brought
-- up before this migration landed. The WHERE clause makes it idempotent: a second
-- run matches no rows.
--
-- If two entries on the same chain canonicalise to the SAME value they are one
-- person granted twice, and the UNIQUE key stops this migration. Collapsing them
-- means choosing which grant's rights survive — a decision that must not be made
-- silently inside a migration. A value that cannot be canonicalised at all is left
-- exactly as it was and then refused by the constraint below, naming the row.
UPDATE document.document_acl
   SET principal_id = util.canonical_identity(principal_id)
 WHERE principal_kind = 'serial'
   AND principal_id IS DISTINCT FROM util.canonical_identity(principal_id);

-- 2. Require a serial principal to be canonical from here on.
--
-- The constraint is CONDITIONAL on the principal kind, and that is the whole point:
-- `principal_id` holds an identity code only when the kind is `serial`. The other
-- kind is an internal subject with a shape of its own, and an unconditional
-- constraint would refuse every document its own creator uploaded.
--
-- The predicate is `util.is_canonical_identity`, so the recognised identity types
-- live in exactly one place (util) and widening them never means editing a
-- constraint. Guarded for replay against a database that already has it.
DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_constraint
         WHERE conname = 'ck_document_acl_serial_canonical'
           AND conrelid = 'document.document_acl'::regclass
    ) THEN
        ALTER TABLE document.document_acl
            ADD CONSTRAINT ck_document_acl_serial_canonical
            CHECK (principal_kind <> 'serial' OR util.is_canonical_identity(principal_id));
    END IF;
END $$;

-- V2: a person's national id is stored in one canonical spelling, and the
-- database refuses any other.
--
-- The same person's identity code reaches the platform written several ways —
-- with the identity type and country a certificate or provider puts on it, with
-- the separator dropped, or as a person writes their national code. Compared as
-- text those were different people: this table's UNIQUE key is that text, so one
-- human arriving two ways became two persons, each with its own subject, and the
-- documents signed under one were unreachable from the other.
--
-- The fix is not a looser comparison but a stricter column. Every write path
-- canonicalises before storing (see `identity.upsert`), and the constraint below
-- requires the stored value to BE canonical — so a write path that forgets is
-- refused at the moment it writes, including one added years from now. That is
-- the half no amount of testing today can cover, because the path that matters
-- is the one nobody has written yet.
--
-- `UNIQUE (national_id)` and the `ON CONFLICT (national_id)` in the procedures
-- are deliberately UNCHANGED: with one spelling at rest, matching stays plain
-- equality, and every query, index and support lookup reads as it always did.

-- 1. Convert what is already stored, BEFORE the constraint exists.
--
-- On a fresh database this is a no-op. It stays here because it is what keeps the
-- constraint from failing on a database that is NOT fresh — an environment
-- brought up before this migration landed. The WHERE clause makes it idempotent:
-- a second run matches no rows.
--
-- Two outcomes are deliberate rather than handled:
--   * If two rows canonicalise to the SAME value, they are the same person stored
--     twice, and the UNIQUE key stops this migration. Merging them needs a human
--     decision about which subject survives and what already references it — it
--     must not happen silently inside a migration.
--   * A value that cannot be canonicalised at all (a bare code with no country in
--     it, an identity type this platform does not know) is left exactly as it was
--     and then refused by the constraint below, naming the row. Also correct: the
--     database cannot invent the country, and guessing one would file a person
--     under the wrong nationality.
UPDATE identity.person
   SET national_id = util.canonical_identity(national_id)
 WHERE national_id IS DISTINCT FROM util.canonical_identity(national_id);

-- 2. Require the column to be canonical from here on.
--
-- The predicate is `util.is_canonical_identity`, so the recognised identity types
-- live in exactly one place (util) and widening them never means editing a
-- constraint. Guarded for replay against a database that already has it.
DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_constraint
         WHERE conname = 'person_national_id_canonical'
           AND conrelid = 'identity.person'::regclass
    ) THEN
        ALTER TABLE identity.person
            ADD CONSTRAINT person_national_id_canonical
            CHECK (util.is_canonical_identity(national_id));
    END IF;
END $$;

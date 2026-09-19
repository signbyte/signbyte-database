-- V8: a signer slot's identity code is stored in one canonical spelling, and the
-- database refuses any other.
--
-- `identity_ref` is how an invited co-signer is recognised: the eIDAS identity
-- code on the slot is compared with the code of whoever is logged in, and a match
-- is what makes the envelope theirs to read, to sign and to decline. Compared as
-- text, the same person invited by one spelling and arriving with another matched
-- NOTHING — the invitation was in front of them and unreachable, with no error to
-- explain it, because a non-match is deliberately indistinguishable from an
-- envelope that does not exist.
--
-- The fix is not a looser comparison but a uniform column. Every write path
-- canonicalises before storing (see `envelope.add_slot`), the constraint below
-- requires the stored value to BE canonical, and the read paths canonicalise the
-- CALLER's value before comparing — so an odd spelling arriving at the door gets
-- a match rather than a miss, and a write path that forgets to canonicalise is
-- refused at the moment it writes rather than quietly inviting nobody.
--
-- The signer-inbox index (`V3`) is deliberately UNTOUCHED: with one spelling at
-- rest the lookup stays plain equality on the column, so the index that serves it
-- keeps working exactly as before.

-- 1. Convert what is already stored, BEFORE the constraint exists.
--
-- On a fresh database this is a no-op. It stays here because it is what keeps the
-- constraint from failing on a database that is NOT fresh — an environment brought
-- up before this migration landed. The WHERE clause makes it idempotent: a second
-- run matches no rows.
--
-- Unlike the person table there is no UNIQUE key here to collide, because two
-- slots may legitimately name the same person on different envelopes. A value that
-- cannot be canonicalised at all (a bare code with no country in it, an identity
-- type this platform does not know) is left exactly as it was and then refused by
-- the constraint below, naming the row — the database cannot invent the country,
-- and guessing one would invite the wrong person.
UPDATE envelope.signer_slot
   SET identity_ref = util.canonical_identity(identity_ref)
 WHERE identity_ref IS NOT NULL
   AND identity_ref IS DISTINCT FROM util.canonical_identity(identity_ref);

-- 2. Require the column to be canonical from here on.
--
-- The predicate is `util.is_canonical_identity`, so the recognised identity types
-- live in exactly one place (util) and widening them never means editing a
-- constraint. It is NULL-in/NULL-out, and a CHECK is satisfied by NULL — which is
-- exactly right here: the owner's own slot carries no identity_ref, and an empty
-- slot must stay as free to create as it is today.
--
-- Guarded for replay against a database that already has it.
DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_constraint
         WHERE conname = 'ck_slot_identity_canonical'
           AND conrelid = 'envelope.signer_slot'::regclass
    ) THEN
        ALTER TABLE envelope.signer_slot
            ADD CONSTRAINT ck_slot_identity_canonical
            CHECK (util.is_canonical_identity(identity_ref));
    END IF;
END $$;

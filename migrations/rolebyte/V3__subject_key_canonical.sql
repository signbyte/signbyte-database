-- V3: the identity code inside a person's register key is stored in one canonical
-- spelling, and the database refuses any other — for that key type, and no other.
--
-- `subject_key` is how a person is recognised across every tenant they belong to.
-- It is TYPED, and that typing is the model's central promise (V2): `pno:<code>`
-- for a person known by their national identity code, `oidc:<issuer>:<subject>` or
-- `invite:<email>` later, and `svc:<client id>` for a service account today — "a new
-- credential type is a new key prefix, not a migration".
--
-- The register had a real hole. The login path builds the key from the identity code
-- in the caller's token; the admin invite path stored the key the caller typed,
-- verbatim. So an administrator inviting a colleague by their bare national code
-- created a member key that the colleague's own login could never produce — an
-- invitation that could not be claimed, by a person who was in the register the
-- whole time, with nothing anywhere to say why.
--
-- THE CONSTRAINT COVERS ONLY THE `pno:` VARIETY. This is not caution, it is the
-- typing promise being kept: a service account's `svc:<client id>` is not an identity
-- code and never will be, and an unconditional constraint would refuse every service
-- account in the register — including the ones the role-leak acceptance writes. The
-- key types that are not identity codes are left entirely alone here, so adding one
-- stays what V2 promised it would be: a new prefix, not a migration.
--
-- `UNIQUE (tenant_id, subject_key)` and the lookups in `R__` are deliberately
-- UNCHANGED: with one spelling at rest, matching stays plain equality.

-- The identity code inside a register key, or NULL when the key is not of the kind
-- that carries one. This is the ONE home of which key types are identity-typed:
-- everything below asks this function rather than repeating the prefix test, so the
-- day a second identity-bearing key type appears it is widened here and the
-- conversion, the constraint and the procedures follow without being touched.
--
-- The prefix is matched exactly as the services emit it. A key with some other
-- prefix — or the same word in another case, which is a prefix this platform does
-- not define — is not an identity key, and is left alone rather than guessed at.
CREATE OR REPLACE FUNCTION rolebyte.subject_key_identity(p_key text)
RETURNS text
LANGUAGE sql
IMMUTABLE
RETURNS NULL ON NULL INPUT
SET search_path = pg_temp
AS $$
    SELECT substring(p_key FROM 5) WHERE p_key LIKE 'pno:%';
$$;

-- The canonical spelling of a register key: the type prefix kept exactly as it came,
-- the identity code inside it canonicalised. A key of any other type is returned
-- unchanged, and so is an identity code that cannot be canonicalised — never a
-- guess. Handing the value back unchanged is what makes the conversion below safe to
-- run over a column it does not fully understand: what it cannot canonicalise is
-- left exactly as it was, for the constraint to refuse by name.
CREATE OR REPLACE FUNCTION rolebyte.canonical_subject_key(p_key text)
RETURNS text
LANGUAGE sql
IMMUTABLE
RETURNS NULL ON NULL INPUT
SET search_path = rolebyte, pg_temp
AS $$
    SELECT CASE
             WHEN rolebyte.subject_key_identity(p_key) IS NULL THEN p_key
             ELSE 'pno:' || util.canonical_identity(rolebyte.subject_key_identity(p_key))
           END;
$$;

-- Whether a value may be STORED as a register key: an identity-typed key must carry
-- an identity code this platform can key on; every other key type is unconstrained,
-- which is the typing promise above.
--
-- The predicate for the identity half is `util.is_canonical_identity`, so the
-- recognised identity types live in exactly one place (util) and widening them never
-- means editing a constraint.
CREATE OR REPLACE FUNCTION rolebyte.is_canonical_subject_key(p_key text)
RETURNS boolean
LANGUAGE sql
IMMUTABLE
RETURNS NULL ON NULL INPUT
SET search_path = rolebyte, pg_temp
AS $$
    SELECT rolebyte.subject_key_identity(p_key) IS NULL
        OR util.is_canonical_identity(rolebyte.subject_key_identity(p_key));
$$;

-- Least privilege: these are called from inside the SECURITY DEFINER procedures,
-- which run as the owner, so the register's EXECUTE-only role needs no grant.
REVOKE ALL ON FUNCTION rolebyte.subject_key_identity(text)     FROM PUBLIC;
REVOKE ALL ON FUNCTION rolebyte.canonical_subject_key(text)    FROM PUBLIC;
REVOKE ALL ON FUNCTION rolebyte.is_canonical_subject_key(text) FROM PUBLIC;

-- 1. Convert what is already stored, BEFORE the constraint exists.
--
-- On a fresh database this is a no-op. It stays here because it is what keeps the
-- constraint from failing on a database that is NOT fresh — an environment brought
-- up before this migration landed. The WHERE clause makes it idempotent: a second
-- run matches no rows.
--
-- If two members of ONE tenant canonicalise to the same key they are one person
-- invited twice, and the UNIQUE key stops this migration. Merging them means
-- deciding which member row's roles and history survive — a decision that must not
-- be made silently inside a migration. A key whose identity code cannot be
-- canonicalised at all is left exactly as it was and then refused by the constraint
-- below, naming the row.
UPDATE rolebyte.user_account
   SET subject_key = rolebyte.canonical_subject_key(subject_key)
 WHERE subject_key IS DISTINCT FROM rolebyte.canonical_subject_key(subject_key);

-- 2. Require an identity-typed key to be canonical from here on.
--
-- Guarded for replay against a database that already has it.
DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_constraint
         WHERE conname = 'user_account_subject_key_canonical'
           AND conrelid = 'rolebyte.user_account'::regclass
    ) THEN
        ALTER TABLE rolebyte.user_account
            ADD CONSTRAINT user_account_subject_key_canonical
            CHECK (rolebyte.is_canonical_subject_key(subject_key));
    END IF;
END $$;

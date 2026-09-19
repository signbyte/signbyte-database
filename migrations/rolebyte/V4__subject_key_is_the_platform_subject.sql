-- V4: a person's register key is the platform subject, and the register no longer
-- knows what an identity code is.
--
-- `subject_key` is how a person is recognised across every tenant they belong to,
-- and it is TYPED. Until now a person was keyed `pno:<national identity code>` —
-- the code copied out of the identity store into every membership row, every
-- event, and from there into every consumer that keys on the register. That put
-- personal data into the one value that is designed to be immutable and to travel,
-- and it could not key a person the platform knows by anything other than a
-- national code.
--
-- From here a person is keyed `sub:<person id>`: the identifier the identity store
-- keys the person on, which is also the `sub` claim of every token issued for them.
-- The identity code stays exactly where it was — an attribute of the person in the
-- identity store, stored canonical and unique, matched at login — and nowhere else.
-- A service account stays `svc:<client id>`. A person has exactly one key kind.
--
-- The register therefore stops carrying identity-code rules of its own: the V3
-- constraint and its three helpers go, and one shape rule takes their place.
--
-- NO CONVERSION OF EXISTING PERSON KEYS. A `pno:` member has no platform subject
-- to be converted to without the identity store, and no deployed database exists:
-- a database that still holds `pno:` rows is a development database, and it is
-- recreated. The check below therefore refuses to run over such rows instead of
-- guessing, and says so. (A conversion that merged or invented keys would decide,
-- silently and inside a migration, which rights and history survive.)
--
-- `UNIQUE (tenant_id, subject_key)` and the lookups in `R__` are UNCHANGED:
-- matching stays plain equality on the stored key.

-- 1. The identity-code rule leaves the register — constraint first (it calls the
--    predicate), then the helpers in dependency order. Guarded for replay.
ALTER TABLE rolebyte.user_account DROP CONSTRAINT IF EXISTS user_account_subject_key_canonical;
DROP FUNCTION IF EXISTS rolebyte.is_canonical_subject_key(text);
DROP FUNCTION IF EXISTS rolebyte.canonical_subject_key(text);
DROP FUNCTION IF EXISTS rolebyte.subject_key_identity(text);

-- 2. The ONE home of which key kinds the register defines: a person by their
--    platform subject, a machine by its client id. Everything else — the
--    constraint, the write doors in `R__` — asks this function rather than
--    repeating the shapes, so a new key kind is added here and nowhere else.
--
--    The person id is a ULID as the platform generates it: 26 characters of the
--    Crockford base32 alphabet (digits and upper-case letters without I, L, O, U),
--    matched exactly as emitted. A key with any other prefix, the same word in
--    another case, or a `sub:` value of another shape is a kind this register does
--    not define, and is refused rather than stored unconstrained.
CREATE OR REPLACE FUNCTION rolebyte.is_typed_subject_key(p_key text)
RETURNS boolean
LANGUAGE sql
IMMUTABLE
RETURNS NULL ON NULL INPUT
SET search_path = pg_temp
AS $$
    SELECT p_key ~ '^svc:.+$'
        OR p_key ~ '^sub:[0-9A-HJKMNP-TV-Z]{26}$';
$$;

-- Least privilege: called from inside the SECURITY DEFINER procedures, which run
-- as the owner, so the register's EXECUTE-only role needs no grant.
REVOKE ALL ON FUNCTION rolebyte.is_typed_subject_key(text) FROM PUBLIC;

-- 3. Refuse, by count and tenant, a database that still holds keys of a kind the
--    register no longer defines — BEFORE the constraint would fail on them with a
--    message that names nothing. On a fresh database this matches no rows. The
--    keys themselves are deliberately not printed: a `pno:` key carries a
--    national identity code, and this text reaches logs.
DO $$
DECLARE
    v_n       integer;
    v_tenants text;
BEGIN
    SELECT count(*), string_agg(DISTINCT tenant_id, ', ' ORDER BY tenant_id)
      INTO v_n, v_tenants
      FROM rolebyte.user_account
     WHERE NOT rolebyte.is_typed_subject_key(subject_key);
    IF v_n > 0 THEN
        RAISE EXCEPTION
            '% register row(s) in tenant(s) % carry a subject key of a kind this register no longer defines (a person is keyed sub:<person id>, a service account svc:<client id>). Such rows are not converted: a database holding them predates this model and is recreated, not migrated.',
            v_n, v_tenants;
    END IF;
END $$;

-- 4. Require every stored key to be of a kind the register defines, from here on.
--    Guarded for replay against a database that already has it.
DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_constraint
         WHERE conname = 'user_account_subject_key_typed'
           AND conrelid = 'rolebyte.user_account'::regclass
    ) THEN
        ALTER TABLE rolebyte.user_account
            ADD CONSTRAINT user_account_subject_key_typed
            CHECK (rolebyte.is_typed_subject_key(subject_key));
    END IF;
END $$;

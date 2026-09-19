-- V3: what a person is shown keeps their country and their identity type.
--
-- `util.identity_display` (V2) returned the bare national identifier for every
-- code except a Latvian personal number. So five different principals holding the
-- same digits rendered as ONE identical string:
--
--     PNOEE-23456789012  ->  23456789012        an Estonian person
--     PNOLT-23456789012  ->  23456789012        a Lithuanian person
--     NTREE-23456789012  ->  23456789012        an Estonian ORGANISATION
--     PASEE-23456789012  ->  23456789012        a passport
--     IDCEE-23456789012  ->  23456789012        an identity card
--
-- The country is part of the identity — the whole reason it is kept in the stored
-- key is that the same digits in two countries belong to two people, and
-- cross-border co-signing is in scope. A screen that renders them alike asks
-- somebody to approve a counterparty they cannot tell apart. The identity type
-- separates a natural person from an organisation and its seal, which matters for
-- the same reason.
--
-- From here the rule is: where a country's own way of writing the number is known,
-- that spelling is used and identifies the code on its own — "123456-78901" reads
-- as a personal number to a Latvian and to nobody else. Everywhere else the code
-- is shown EXACTLY AS STORED. The Latvian case, which is what the function was
-- written for, is unchanged.
--
-- Writing the country in front of the identifier instead ("EE 23456789012") was
-- considered and rejected on measurement: a space and a hyphen are both separators
-- to `util.canonical_identity`, so a person retyping what they were shown would
-- have had the country absorbed into the identifier and resolved to a DIFFERENT
-- key — silently, with no error. Showing the stored code round-trips.
--
-- Nothing compares a displayed value, so no key, index or comparison is affected;
-- this changes what a screen shows and nothing else. The shared library's
-- `identitycode.Display` changes to match in the same breath — the two must agree
-- exactly, and the same defect was in both, because the SQL was written to mirror
-- the library and mirrored this too.
--
-- A new `V` rather than an edit to V2: V2 has been applied, and a versioned
-- migration is checksummed once it has.

CREATE OR REPLACE FUNCTION util.identity_display(p_value text)
RETURNS text
LANGUAGE plpgsql
IMMUTABLE
RETURNS NULL ON NULL INPUT
SET search_path = util, pg_temp
AS $$
DECLARE
    v_body text;
BEGIN
    IF NOT util.is_canonical_identity(p_value) THEN
        RETURN p_value;
    END IF;

    v_body := substring(p_value FROM 7);

    -- Latvia writes a personal number as six digits, a hyphen and five. The
    -- leading group was once a date of birth and since 2017 need not be, so the
    -- split is on length alone and never on what the digits mean.
    --
    -- Only a country whose separator placement is known appears here. Anywhere
    -- else there is no national spelling to fall back on, and the stored code is
    -- what a person is shown.
    IF substring(p_value FROM 1 FOR 3) = 'PNO'
       AND substring(p_value FROM 4 FOR 2) = 'LV'
       AND v_body ~ '^[0-9]{11}$' THEN
        RETURN substring(v_body FROM 1 FOR 6) || '-' || substring(v_body FROM 7);
    END IF;

    -- V2 guarded here against an identifier that itself opens like an identity
    -- type, so that a person was never shown a string typing back as somebody
    -- else. The guard is gone because it can no longer fire: the fallback IS the
    -- whole code, and the split above applies only to an all-digit identifier,
    -- which cannot open with five letters.
    RETURN p_value;
END
$$;

-- The grant is as V2 left it; restated because a replaced function is a new
-- object as far as privileges are concerned, and nothing in util is public.
REVOKE ALL ON FUNCTION util.identity_display(text) FROM PUBLIC;

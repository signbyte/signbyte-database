-- V2: one canonical spelling for an identity code, and the predicate that
-- enforces it.
--
-- A person's identity code reaches this platform written several ways: with the
-- identity type and country a certificate or an identity provider puts on it
-- ("PNOLV-123456-78901"), with the separator dropped ("PNOLV-12345678901"), as a
-- person writes their national code ("123456-78901"), or in the "LV/LV/…" shape a
-- cross-border login carries. Compared as text those are different people, and
-- the one who signed a document under one spelling cannot find it under another.
--
-- These functions define the single stored spelling — the identity type, the
-- country, a hyphen, and the national code with its separators removed —
-- so every store can compare identity with plain equality. `is_canonical_identity`
-- is what the domain constraints call: a column is *required* to hold the
-- canonical form, so a write path that forgets to canonicalise is refused at the
-- moment it writes rather than quietly creating a second person.
--
-- The country is never guessed here. A country stated in the value is honoured;
-- a bare code with no country in it is left alone and refused by the predicate,
-- because a wrong identity key is the wrong person's documents. Supplying the
-- country is the calling service's job, from the nearest fact about the person —
-- the country chosen on their screen, the country in their signing certificate,
-- the country recorded for the system that sent it.
--
-- The same rule is implemented in the services' shared library, and the two must
-- agree exactly. Two details of this file exist for that reason and should not be
-- "simplified":
--
--   * Only the ASCII letters and digits are accepted. An identity code is written
--     in them, and a letter from another alphabet that merely looks like one must
--     not be able to pass as it. The test is `octet_length = char_length`, which
--     is exact and does not depend on the database collation — and because it runs
--     BEFORE upper-casing, the case fold is ASCII-only by construction. Otherwise
--     `upper()` would fold some non-ASCII letters onto ASCII ones here while the
--     library refuses them, and the two implementations would disagree.
--   * The no-break space is stripped explicitly. The library treats every Unicode
--     space as a separator; PostgreSQL's own `[[:space:]]` and `\s` match neither
--     it nor any other non-ASCII space (measured on 17.11), so listing it keeps
--     the common case identical instead of leaving a value the library accepts and
--     this file refuses.

-- The identity type a value states, or NULL when it states none this platform
-- knows. This is the ONE home of the recognised set: the types come from the
-- standard semantics for a signing certificate's serial number — a national
-- personal number, a national trade-register number (organisations and the seals
-- they sign with), a passport number, a national identity card number, and a tax
-- identification number.
--
-- Everything else here asks this function rather than repeating the list. That is
-- deliberate and was proved necessary: while mutation-testing this file, widening
-- the list in one place and not the other left the two disagreeing, and only a
-- second hardcoded list happened to catch it. Widening the set is now an edit to
-- this function and nothing else.
--
-- The hyphen the standard puts after the country is required. Without it there is
-- no telling an identity type from a national code that happens to begin with
-- letters, and reading one as the other is how a person becomes two.
CREATE OR REPLACE FUNCTION util.identity_type(p_value text)
RETURNS text
LANGUAGE sql
IMMUTABLE
RETURNS NULL ON NULL INPUT
SET search_path = pg_temp
AS $$
    SELECT upper(substring(btrim(p_value) FROM 1 FOR 3))
     WHERE btrim(p_value) ~ '^[A-Za-z]{3}[A-Za-z]{2}-'
       AND upper(substring(btrim(p_value) FROM 1 FOR 3))
           IN ('PNO', 'NTR', 'PAS', 'IDC', 'TIN');
$$;

-- The part after the identity type and country, reduced to the form that is
-- stored: separators gone, ASCII letters upper-cased. NULL when nothing is left
-- or when it is not written in ASCII letters and digits — the callers below turn
-- that into "cannot be canonicalised", never into a guess.
CREATE OR REPLACE FUNCTION util.identity_body(p_value text)
RETURNS text
LANGUAGE sql
IMMUTABLE
RETURNS NULL ON NULL INPUT
SET search_path = pg_temp
AS $$
    WITH stripped AS (
        SELECT regexp_replace(p_value, '[[:space:]' || chr(160) || './-]', '', 'g') AS v
    )
    SELECT CASE
             WHEN v = ''                                THEN NULL
             -- Not ASCII. The alphanumeric test below already rejects every
             -- non-ASCII letter under this database's collation, so no input can
             -- currently tell the two apart — mutation-testing this file confirmed
             -- it. The test stays because bracket RANGES are collation-dependent
             -- in principle, and this one is not: it is what guarantees the
             -- upper-casing below can never fold a non-ASCII letter onto an ASCII
             -- one, whatever collation the database is created with.
             WHEN octet_length(v) <> char_length(v)     THEN NULL
             WHEN v !~ '^[0-9A-Za-z]+$'                 THEN NULL
             ELSE upper(v)
           END
      FROM stripped;
$$;

-- The canonical spelling of an identity code, or the value itself when it cannot
-- be canonicalised — never a guess, and never a different non-canonical form.
-- Handing the value back unchanged is what makes the conversion in a domain
-- migration safe to run over a column it does not fully understand: a value it
-- cannot canonicalise is left exactly as it was, for the constraint to refuse by
-- name.
CREATE OR REPLACE FUNCTION util.canonical_identity(p_value text)
RETURNS text
LANGUAGE plpgsql
IMMUTABLE
RETURNS NULL ON NULL INPUT
SET search_path = util, pg_temp
AS $$
DECLARE
    v_value   text := btrim(p_value);
    -- A country the VALUE ITSELF states. It is not a hint and not a default:
    -- nothing here invents one.
    v_country text := NULL;
    v_type    text;
    v_body    text;
BEGIN
    -- The cross-border login form states the country of the code first and the
    -- country that asked for it second — "LV/LV/123456-78901". Only the first
    -- says anything about the person; the second is discarded.
    --
    -- The form can nest, and every pass shortens the value, so the loop
    -- terminates. Note what nesting resolves to: each pass overwrites the
    -- country, so the one that survives is the leading country of the INNERMOST
    -- pair — "LV/LV/EE/EE/123456-78901" is Estonian, not Latvian. That is the
    -- library's behaviour too (measured, not assumed), which is what matters
    -- here: the two must agree, and they do. Real identifiers do not nest, so
    -- the case is a curiosity rather than a rule anyone relies on.
    WHILE v_value ~ '^[A-Za-z]{2}/[A-Za-z]{2}/.+$' LOOP
        v_country := upper(substring(v_value FROM 1 FOR 2));
        v_value   := btrim(substring(v_value FROM 7));
    END LOOP;

    -- A code that states its own identity type and country.
    v_type := util.identity_type(v_value);
    IF v_type IS NOT NULL THEN
        v_body := util.identity_body(substring(v_value FROM 7));
        IF v_body IS NULL THEN
            RETURN v_value;
        END IF;

        RETURN v_type || upper(substring(v_value FROM 4 FOR 2)) || '-' || v_body;
    END IF;

    -- A code shaped like an identity type whose type this platform does not know,
    -- and the locally defined form (two letters and a colon), are both left alone
    -- rather than mistaken for a national code. The predicate refuses them.
    IF v_value ~ '^[A-Za-z]{3}[A-Za-z]{2}-' OR v_value ~ '^[A-Za-z]{2}:[A-Za-z]{2}-' THEN
        RETURN v_value;
    END IF;

    -- A bare national code, with a country the value itself stated. Anything
    -- opening with five letters is refused rather than typed, because that is the
    -- shape of an identity type and a country and the two cannot be told apart.
    IF v_country IS NOT NULL THEN
        v_body := util.identity_body(v_value);
        IF v_body IS NULL OR v_body ~ '^[A-Za-z]{5}' THEN
            RETURN v_value;
        END IF;

        RETURN 'PNO' || v_country || '-' || v_body;
    END IF;

    -- A bare code and no country anywhere. The database does not guess one.
    RETURN v_value;
END
$$;

-- Whether a value may be STORED as an identity code: it is exactly its own
-- canonical form and it carries an identity type this platform knows. This is
-- the predicate the domain constraints call, so the recognised set lives in one
-- place — widening it is a change to `canonical_identity` above and nothing else.
--
-- NULL in, NULL out, so a nullable identity column is unconstrained when empty
-- and the column's own NOT NULL decides whether that is allowed.
CREATE OR REPLACE FUNCTION util.is_canonical_identity(p_value text)
RETURNS boolean
LANGUAGE sql
IMMUTABLE
RETURNS NULL ON NULL INPUT
SET search_path = util, pg_temp
AS $$
    SELECT p_value = util.canonical_identity(p_value)
       AND util.identity_type(p_value) IS NOT NULL
       AND p_value ~ '^[A-Z]{3}[A-Z]{2}-[0-9A-Z]+$';
$$;

-- The spelling to show a person: their own national code, written the way their
-- country writes it, without the identity type the platform keys on. A value that
-- is not a canonical identity code is returned unchanged — a display is cosmetic,
-- and showing the raw value serves a person better than showing nothing.
--
-- Only a country whose separator placement is known appears here; everywhere else
-- the code is shown as stored, which is how the countries that use no separator
-- write it anyway. A wrong entry here is a wrong label, never a wrong person,
-- because nothing compares a displayed value.
CREATE OR REPLACE FUNCTION util.identity_display(p_value text)
RETURNS text
LANGUAGE plpgsql
IMMUTABLE
RETURNS NULL ON NULL INPUT
SET search_path = util, pg_temp
AS $$
DECLARE
    v_type text;
    v_body text;
BEGIN
    IF NOT util.is_canonical_identity(p_value) THEN
        RETURN p_value;
    END IF;

    v_type := substring(p_value FROM 1 FOR 3);
    v_body := substring(p_value FROM 7);

    -- An identifier that itself opens with five letters would read as an identity
    -- type on its own, so the code is shown whole: a person must never be shown a
    -- string that types back as somebody else.
    IF v_body ~ '^[A-Z]{5}' THEN
        RETURN p_value;
    END IF;

    -- Latvia writes a personal number as six digits, a hyphen and five. The
    -- leading group was once a date of birth and since 2017 need not be, so the
    -- split is on length alone and never on what the digits mean.
    IF v_type = 'PNO'
       AND substring(p_value FROM 4 FOR 2) = 'LV'
       AND v_body ~ '^[0-9]{11}$' THEN
        RETURN substring(v_body FROM 1 FOR 6) || '-' || substring(v_body FROM 7);
    END IF;

    RETURN v_body;
END
$$;

-- Least privilege, as for everything in util: nothing here is public. The domain
-- schemas' SECURITY DEFINER procedures run as the owner, which owns these, so
-- they need no grant of their own.
REVOKE ALL ON FUNCTION util.identity_type(text)         FROM PUBLIC;
REVOKE ALL ON FUNCTION util.identity_body(text)         FROM PUBLIC;
REVOKE ALL ON FUNCTION util.canonical_identity(text)    FROM PUBLIC;
REVOKE ALL ON FUNCTION util.is_canonical_identity(text) FROM PUBLIC;
REVOKE ALL ON FUNCTION util.identity_display(text)      FROM PUBLIC;

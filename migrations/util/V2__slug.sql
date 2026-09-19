-- V2: `util.slug()` — turn a label a person wrote into a machine name.
--
-- Every tenant-authored list in this data layer (kinds of work, priorities,
-- field definitions, list values, templates …) carries a stable `key` beside
-- its label: the label may be renamed freely, while the key is what recorded
-- rows hang off and what an API address and a configuration export are written
-- in. Until now that key was typed by whoever authored the row, which asked an
-- administrator to invent a machine name before they could name a thing in
-- their own words. It is derivable, so it is derived here instead.
--
-- The function is pure: it maps a label to a candidate key and says nothing
-- about uniqueness. Each calling procedure disambiguates against its own
-- table's own scope, because the scope differs (a key is unique per tenant for
-- a kind of work, per definition for one of its list values, and so on), and
-- the table's unique constraint remains the thing that actually decides — two
-- concurrent creates of the same name still end as a conflict, not a duplicate.

-- Latin letters carrying a diacritic are folded to the letter underneath, so a
-- company writing in its own language gets a readable key rather than one with
-- every accented letter dropped out of it: `Frēzēšana` becomes `frezesana`, not
-- `frzana`. The set covers the Baltic languages and the two Nordic vowels that
-- appear beside them; anything outside it (a label written in Cyrillic, say)
-- folds to nothing, which is a case the caller handles rather than this
-- function guessing at a transliteration it cannot do well.
--
-- The two strings are position-for-position: 40 characters each. They are kept
-- on one line apiece precisely so that stays checkable at a glance.
CREATE OR REPLACE FUNCTION util.slug(pi_label text)
RETURNS text
LANGUAGE plpgsql
IMMUTABLE
-- Body references only built-ins, but the search_path is pinned all the same:
-- "every routine pins a search_path" is a rule a linter can check, and a habit
-- is not.
SET search_path = pg_temp
AS $$
DECLARE
    -- 40 characters, folded to the 40 on the line below it.
    c_from CONSTANT text := 'āčēģīķļņšūžąęėįųäöõüĀČĒĢĪĶĻŅŠŪŽĄĘĖĮŲÄÖÕÜ';
    c_to   CONSTANT text := 'acegiklnsuzaeeiuaoouACEGIKLNSUZAEEIUAOOU';
    -- Long enough that no realistic label is cut, short enough that a key is
    -- still something a person can read in an address. A label that does hit
    -- the cap is disambiguated by its caller like any other collision.
    c_max  CONSTANT int  := 64;
    v_text text;
    v_word text;
    v_out  text := '';
BEGIN
    v_text := translate(COALESCE(pi_label, ''), c_from, c_to);

    -- Everything that is not an unaccented letter or a digit becomes a word
    -- boundary. Punctuation, spaces and any character the fold above did not
    -- reach all leave the same way, so there is one rule rather than a list.
    v_text := btrim(regexp_replace(v_text, '[^a-zA-Z0-9]+', ' ', 'g'));

    IF v_text = '' THEN
        RETURN '';
    END IF;

    -- The house style for these keys is one word, lower case, with each further
    -- word capitalised: `Work order` reads back as `workOrder`, which is what a
    -- person would have typed by hand.
    FOREACH v_word IN ARRAY regexp_split_to_array(v_text, '\s+') LOOP
        IF v_out = '' THEN
            v_out := lower(v_word);
        ELSE
            v_out := v_out || upper(left(v_word, 1)) || lower(substr(v_word, 2));
        END IF;
    END LOOP;

    RETURN left(v_out, c_max);
END;
$$;

-- Least privilege, as everything else in this schema: nothing here is public,
-- and the domain schemas' SECURITY DEFINER procedures run as the owner, so they
-- can call it without a grant of their own.
REVOKE ALL ON FUNCTION util.slug(text) FROM PUBLIC;

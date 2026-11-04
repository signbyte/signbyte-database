-- V4: the words a company configures — a name per language beside the name as
-- entered, and the number that identifies an item of a configured list.
--
-- Every list a company configures (its stages, kinds of work, priorities,
-- fields and the rest) keeps one name as the administrator typed it, in the
-- workspace's language, and a map of names in the other languages the app
-- speaks. A reader sees the name in their language where one was given, and the
-- name as entered otherwise. These helpers are the one place each list's
-- procedures read and check that map, so every list answers the same refusals
-- in the same words.

-- app_languages — the languages the app speaks, as the codes a name is kept
-- under. A name in any other language could never be shown to anyone, so it is
-- refused rather than stored. A language the app gains is added here, in a
-- migration that re-creates this function.
CREATE OR REPLACE FUNCTION util.app_languages() RETURNS text[]
LANGUAGE sql
IMMUTABLE
SET search_path = pg_temp
AS $$
    SELECT ARRAY['en', 'lv']::text[];
$$;

REVOKE ALL ON FUNCTION util.app_languages() FROM PUBLIC;

-- labels_refusal — why a write's names in languages cannot be taken, or NULL
-- when they can. Absent (SQL NULL, or a JSON null) is fine: it means "leave
-- them". Otherwise it
-- must be an object whose members are languages the app speaks, each holding a
-- name or null; null removes that language's name. A name is trimmed before it
-- is judged, and one that is empty after trimming is refused rather than read
-- as a removal: removing is said with null, and a blank box is not a name.
CREATE OR REPLACE FUNCTION util.labels_refusal(p_labels jsonb) RETURNS text
LANGUAGE plpgsql
IMMUTABLE
SET search_path = util, pg_temp
AS $$
DECLARE
    r record;
BEGIN
    IF p_labels IS NULL OR jsonb_typeof(p_labels) = 'null' THEN
        RETURN NULL;
    END IF;
    IF jsonb_typeof(p_labels) <> 'object' THEN
        RETURN 'labels must be an object of names by language';
    END IF;
    FOR r IN SELECT e.key, e.value FROM jsonb_each(p_labels) e ORDER BY e.key LOOP
        IF NOT (r.key = ANY (util.app_languages())) THEN
            RETURN 'labels: ' || r.key || ' is not a language the app speaks ('
                || array_to_string(util.app_languages(), ', ') || ')';
        END IF;
        IF jsonb_typeof(r.value) = 'null' THEN
            CONTINUE;
        END IF;
        IF jsonb_typeof(r.value) <> 'string' THEN
            RETURN 'labels: the name in ' || r.key || ' must be text, or null to remove it';
        END IF;
        IF trim(r.value #>> '{}') = '' THEN
            RETURN 'labels: the name in ' || r.key || ' is empty; send null to remove it';
        END IF;
    END LOOP;
    RETURN NULL;
END;
$$;

REVOKE ALL ON FUNCTION util.labels_refusal(jsonb) FROM PUBLIC;

-- labels_merge — the names a row holds after a write: each language the write
-- names is set to its trimmed name, or removed where it holds null; a language
-- the write does not name is left as it was. So a screen editing one language
-- cannot erase another it did not show. The write is judged by labels_refusal
-- first; this function assumes it passed.
CREATE OR REPLACE FUNCTION util.labels_merge(p_current jsonb, p_labels jsonb) RETURNS jsonb
LANGUAGE sql
IMMUTABLE
SET search_path = pg_temp
AS $$
    WITH w AS (
        SELECT CASE WHEN jsonb_typeof(p_current) = 'object' THEN p_current ELSE '{}'::jsonb END AS cur,
               CASE WHEN jsonb_typeof(p_labels)  = 'object' THEN p_labels  ELSE '{}'::jsonb END AS chg
    )
    SELECT COALESCE(jsonb_object_agg(m.k, m.v), '{}'::jsonb)
      FROM (
        SELECT c.key AS k, c.value AS v
          FROM w, jsonb_each(w.cur) c
         WHERE NOT (w.chg ? c.key)
        UNION ALL
        SELECT l.key, to_jsonb(trim(l.value #>> '{}'))
          FROM w, jsonb_each(w.chg) l
         WHERE jsonb_typeof(l.value) = 'string'
      ) m;
$$;

REVOKE ALL ON FUNCTION util.labels_merge(jsonb, jsonb) FROM PUBLIC;

-- list_number — an item's number as a caller sent it, or NULL when what was
-- sent is not one. An item of a configured list is identified by a whole number
-- from 1, handed out per workspace; a JSON number and a string of digits are
-- both read (a number from a path or a query string arrives as text), and
-- anything else — a fraction, a sign, a leading zero, a word — is not a number
-- of any item. Nine digits at most, so the value always fits.
CREATE OR REPLACE FUNCTION util.list_number(p jsonb) RETURNS int
LANGUAGE sql
IMMUTABLE
SET search_path = pg_temp
AS $$
    SELECT CASE
        WHEN jsonb_typeof(p) IN ('number', 'string') AND (p #>> '{}') ~ '^[1-9][0-9]{0,8}$'
            THEN (p #>> '{}')::int
    END;
$$;

REVOKE ALL ON FUNCTION util.list_number(jsonb) FROM PUBLIC;

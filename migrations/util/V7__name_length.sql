-- V7: a name is at most 100 characters, in every language it is given in.
--
-- `util.name_refusal()` — what is wrong with a thing's name, or NULL when
-- nothing is. A name is drawn on a screen and said back by refusals, so it is
-- held to 100 characters, the length a field's name already had. Absence is
-- each caller's own rule, as each says it in its own words.
--
-- `util.labels_refusal()` holds the names given in other languages to the same
-- length, and cuts what it says back of a key that is not a language to 20
-- characters, so a refusal never repeats a long input whole. Otherwise as V4
-- and V5 left it: STABLE, as the sentence listing the app's languages is.

CREATE OR REPLACE FUNCTION util.name_refusal(p_name text) RETURNS text
LANGUAGE sql
IMMUTABLE
SET search_path = pg_temp
AS $$
    SELECT CASE WHEN char_length(p_name) > 100 THEN 'a name is at most 100 characters' END;
$$;

REVOKE ALL ON FUNCTION util.name_refusal(text) FROM PUBLIC;

CREATE OR REPLACE FUNCTION util.labels_refusal(p_labels jsonb) RETURNS text
LANGUAGE plpgsql
STABLE
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
            RETURN 'labels: ' || left(r.key, 20) || ' is not a language the app speaks ('
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
        IF char_length(trim(r.value #>> '{}')) > 100 THEN
            RETURN 'labels: the name in ' || r.key || ' is at most 100 characters';
        END IF;
    END LOOP;
    RETURN NULL;
END;
$$;

REVOKE ALL ON FUNCTION util.labels_refusal(jsonb) FROM PUBLIC;

-- V6: `util.file_name_refusal()` — what is wrong with a stored file's name, or
-- NULL when nothing is.
--
-- A file's name is drawn as text wherever the file is listed, so it may hold
-- only text. Refused: a control character (U+0001–U+001F, U+007F–U+009F), which
-- is not text, and a character that turns the direction the text around it is
-- drawn in — the embeddings, overrides and isolates (U+202A–U+202E,
-- U+2066–U+2069) and the direction marks (U+200E, U+200F, U+061C). With a
-- right-to-left override, "invoice_<RLO>fdp.exe" reads as "invoice_exe.pdf".
-- A line or paragraph separator (U+2028, U+2029) is refused too: it breaks the
-- name across lines, so a list drawn on one line can show "invoice.pdf" and
-- hide what follows. The joiners some scripts write words with (U+200C, U+200D)
-- are text, and pass.
--
-- The refusal names the first such character by its code point, so whoever is
-- told can find it. Refused rather than removed: removing it would store a name
-- other than the one the file was given, without saying so.

CREATE OR REPLACE FUNCTION util.file_name_refusal(p_name text) RETURNS text
LANGUAGE sql
IMMUTABLE
SET search_path = pg_temp
AS $$
    SELECT 'a file''s name holds only text, and U+' || upper(lpad(to_hex(ascii(m[1])), 4, '0')) || ' is '
        || CASE WHEN m[1] ~ '[\u0001-\u001f\u007f-\u009f]' THEN 'a control character'
                WHEN m[1] ~ '[\u2028\u2029]' THEN 'a line-break character'
                ELSE 'a text-direction character' END
        || '; rename the file without it'
      FROM regexp_match(p_name, '([\u0001-\u001f\u007f-\u009f\u061c\u200e\u200f\u202a-\u202e\u2066-\u2069\u2028\u2029])') AS m;
$$;

REVOKE ALL ON FUNCTION util.file_name_refusal(text) FROM PUBLIC;

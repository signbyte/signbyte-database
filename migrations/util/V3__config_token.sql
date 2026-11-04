-- V3: `util.config_token()` — the version of a section of configuration, one
-- helper for every location that holds configuration, instead of a copy in each.

-- config_token — the version of a section of configuration: "sha256:" and the
-- hex SHA-256 of the section's schema name (the name its payload travels under,
-- `<section>-config/1`), a line break, the scope, a line break and the section
-- as its owner renders it. The schema name keeps two sections apart; the scope
-- keeps two holders of the same configuration apart, and a section held per
-- tenant passes the tenant. Same bytes, same token; any change to what the
-- section says, by any writer, is a different token. Opaque to every reader:
-- compared for equality and nothing else.
CREATE OR REPLACE FUNCTION util.config_token(pi_schema text, pi_scope text, pi_section jsonb)
RETURNS text
LANGUAGE sql
IMMUTABLE
-- Body references only built-ins, but the search_path is pinned all the same:
-- "every routine pins a search_path" is a rule a linter can check, and a habit
-- is not.
SET search_path = pg_temp
AS $$
    SELECT 'sha256:' || encode(sha256(convert_to(
        pi_schema || chr(10) || pi_scope || chr(10) || pi_section::text, 'UTF8')), 'hex');
$$;

-- Least privilege, as everything else in this schema: nothing here is public,
-- and the domain schemas' SECURITY DEFINER procedures run as the owner, so they
-- can call it without a grant of their own.
REVOKE ALL ON FUNCTION util.config_token(text, text, jsonb) FROM PUBLIC;

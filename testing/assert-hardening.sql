-- Hardening assertions, run against a MIGRATED database.
--
-- Everything asserted here is also stated in the migrations, but stating a rule
-- and holding it are different things: a hand-run GRANT, a forgotten REVOKE or a
-- routine added without a pinned search_path changes the database without
-- changing a file, and file review cannot see that. These queries read the live
-- catalog, so they fail on drift introduced by ANY route.
--
-- Raises on the first violation; silence means every assertion held.

-- Scope: routines this repository authors. Objects owned by an extension
-- (pgcrypto's C functions, which live in util by design) are excluded — their
-- definitions are not ours to pin, and asserting over them would only teach the
-- next person to weaken the check.
CREATE OR REPLACE VIEW pg_temp.authored_routine AS
SELECT p.oid, n.nspname, p.proname, p.proconfig, p.prokind
  FROM pg_proc p
  JOIN pg_namespace n ON n.oid = p.pronamespace
 WHERE n.nspname NOT IN ('pg_catalog', 'information_schema', 'public')
   AND n.nspname NOT LIKE 'pg_%'
   AND NOT EXISTS (
         SELECT 1 FROM pg_depend d
          WHERE d.classid = 'pg_proc'::regclass
            AND d.objid   = p.oid
            AND d.deptype = 'e');

DO $$
DECLARE
    v_bad     text;
    v_count   int;
    v_setting text;
BEGIN
    -- 1. Every routine in a domain schema pins its own search_path.
    --    `public` is excluded from the sweep: it holds no data-layer routine,
    --    only Flyway's history tables and (in the test image) plpgsql_check.
    SELECT string_agg(format('%s.%s', p.nspname, p.proname), ', ')
      INTO v_bad
      FROM pg_temp.authored_routine p
     WHERE NOT EXISTS (
             SELECT 1 FROM unnest(coalesce(p.proconfig, '{}')) AS c
              WHERE c LIKE 'search_path=%');
    IF v_bad IS NOT NULL THEN
        RAISE EXCEPTION 'routines without a pinned search_path: %', v_bad;
    END IF;

    -- 2. No pinned search_path may contain `public`. A writable schema early in
    --    the path is the search-path hijack surface this layer is built to deny.
    SELECT string_agg(format('%s.%s (%s)', p.nspname, p.proname, c), ', ')
      INTO v_bad
      FROM pg_temp.authored_routine p
      CROSS JOIN LATERAL unnest(coalesce(p.proconfig, '{}')) AS c
     WHERE c LIKE 'search_path=%'
       AND c ~ '(^|[=, ])public([, ]|$)';
    IF v_bad IS NOT NULL THEN
        RAISE EXCEPTION 'routines whose search_path contains public: %', v_bad;
    END IF;

    -- 3. Where pg_temp is listed it must be LAST. Listed elsewhere -- or omitted,
    --    which makes Postgres search it FIRST for relation names -- a caller's
    --    temporary object can shadow a real one inside a privileged body.
    SELECT string_agg(format('%s.%s (%s)', p.nspname, p.proname, c), ', ')
      INTO v_bad
      FROM pg_temp.authored_routine p
      CROSS JOIN LATERAL unnest(coalesce(p.proconfig, '{}')) AS c
     WHERE c LIKE 'search_path=%'
       AND c NOT LIKE '%pg_temp';
    IF v_bad IS NOT NULL THEN
        RAISE EXCEPTION 'routines whose search_path does not end in pg_temp: %', v_bad;
    END IF;

    -- 4. pgcrypto lives in util, never in public.
    SELECT n.nspname INTO v_bad
      FROM pg_extension e JOIN pg_namespace n ON n.oid = e.extnamespace
     WHERE e.extname = 'pgcrypto';
    IF v_bad IS DISTINCT FROM 'util' THEN
        RAISE EXCEPTION 'pgcrypto is in schema % (expected util)', coalesce(v_bad, '<absent>');
    END IF;

    -- 5. PUBLIC may not create temporary objects. Postgres grants this by
    --    default; without the revoke, every service role can make a temp table.
    IF has_database_privilege('public', current_database(), 'TEMPORARY') THEN
        RAISE EXCEPTION 'PUBLIC still holds TEMPORARY on database %', current_database();
    END IF;

    -- 6. The database's own default search_path resolves no real schema, so a
    --    routine that forgets to pin one fails on first call instead of quietly
    --    inheriting a usable path.
    SELECT setting INTO v_setting
      FROM pg_db_role_setting s
      JOIN pg_database d ON d.oid = s.setdatabase
      CROSS JOIN LATERAL unnest(s.setconfig) AS setting
     WHERE d.datname = current_database()
       AND s.setrole = 0
       AND setting LIKE 'search_path=%';
    IF v_setting IS DISTINCT FROM 'search_path=pg_temp' THEN
        RAISE EXCEPTION 'database default search_path is % (expected search_path=pg_temp)',
              coalesce(v_setting, '<unset>');
    END IF;

    -- 7. No EXECUTE-only service role holds any table or sequence privilege.
    --    This is the property that makes a leaked service credential worth
    --    little: it can invoke a fixed procedure set and reach nothing else.
    SELECT string_agg(DISTINCT format('%s on %s.%s', g.privilege_type, g.table_schema, g.table_name), ', ')
      INTO v_bad
      FROM information_schema.role_table_grants g
     WHERE g.grantee LIKE '%\_public';
    IF v_bad IS NOT NULL THEN
        RAISE EXCEPTION 'a *_public service role holds table privileges: %', v_bad;
    END IF;

    -- 8. Every data-layer procedure is revoked from PUBLIC.
    SELECT count(*) INTO v_count
      FROM pg_temp.authored_routine p
     WHERE p.prokind = 'p'
       AND has_function_privilege('public', p.oid, 'EXECUTE');
    IF v_count > 0 THEN
        RAISE EXCEPTION '% procedure(s) are still EXECUTE-able by PUBLIC', v_count;
    END IF;

    -- 9. Every table declared append-only carries a trigger that fires on UPDATE
    --    and DELETE. The human break-glass role holds INSERT/UPDATE/DELETE on all
    --    tables by design, so for an audit table the guard trigger is the only
    --    thing between a break-glass session and silently rewritten evidence --
    --    the revoke model does not cover that path.
    --
    --    The list is declared, not inferred: each schema location declares its
    --    append-only tables in testing/append-only/<location>.list (one
    --    schema.table per line), and the caller hands the concatenated list in
    --    through the session setting hardening.append_only (verify.sh does this).
    --    Tables absent from this deployment's locations are skipped, so the same
    --    assertion runs for every deployment shape. An empty list is refused:
    --    every shape has at least one evidence table, so "nothing to check" means
    --    the caller forgot to pass it.
    IF coalesce(trim(current_setting('hardening.append_only', true)), '') = '' THEN
        RAISE EXCEPTION 'hardening.append_only is not set — pass the declared append-only table list (testing/append-only/*.list)';
    END IF;
    FOR v_bad IN
        SELECT format('%s.%s', d.nsp, d.rel)
          FROM (SELECT split_part(x, '.', 1) AS nsp, split_part(x, '.', 2) AS rel
                  FROM unnest(regexp_split_to_array(trim(current_setting('hardening.append_only')), '\s+')) AS x
                 WHERE x <> '') AS d
          JOIN pg_class c     ON c.relname = d.rel
          JOIN pg_namespace n ON n.oid = c.relnamespace AND n.nspname = d.nsp
         WHERE NOT EXISTS (
                 SELECT 1 FROM pg_trigger t
                  WHERE t.tgrelid = c.oid
                    AND NOT t.tgisinternal
                    -- tgtype bits: 8 = UPDATE, 16 = DELETE (both required)
                    AND (t.tgtype & 8) <> 0
                    AND (t.tgtype & 16) <> 0)
    LOOP
        RAISE EXCEPTION 'append-only table % has no UPDATE/DELETE guard trigger', v_bad;
    END LOOP;

    -- 10. A human group role holds privileges in ITS OWN schema and nowhere else.
    --     This is what "least privilege, per schema" actually means at runtime: a
     --    person granted the role that lets them read one schema must not thereby
    --     reach identity PII, the GDPR access records or the signing-evidence
    --     trail. Naming a role `<schema>_read_role` is a claim; this is the check.
    SELECT string_agg(DISTINCT format('%s -> %s.%s', g.grantee, g.table_schema, g.table_name), ', ')
      INTO v_bad
      FROM information_schema.role_table_grants g
     WHERE (g.grantee LIKE '%\_read\_role' OR g.grantee LIKE '%\_write\_role')
       AND g.table_schema <> regexp_replace(g.grantee, '_(read|write)_role$', '');
    IF v_bad IS NOT NULL THEN
        RAISE EXCEPTION 'human group role(s) hold privileges outside their own schema: %', v_bad;
    END IF;

    RAISE NOTICE 'hardening assertions: all held';
END
$$;

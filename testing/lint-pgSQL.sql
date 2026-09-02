-- plpgsql_check static analysis of every PL/pgSQL procedure in the database.
-- Emits one row per finding; check-linter-error-steps.sh fails the build if any
-- finding is level 'error'. The `unused parameter "pi_data"` finding is an
-- expected false positive (the JSONB envelope param is mandatory even when a body
-- ignores it) and is filtered out below.
--
-- plpgsql_check_function_tb is schema-qualified deliberately. This database sets
-- its own default search_path to pg_temp so that no routine can rely on an
-- inherited path, which means an unqualified call here resolves to nothing — and
-- an analysis that cannot run is far worse than one that reports findings, since
-- "no findings" and "never ran" look identical in the output.

      SELECT (pcf).functionid::regprocedure, (pcf).lineno, (pcf).statement, (pcf).sqlstate, (pcf).message, (pcf).detail, (pcf).hint, (pcf).level,  (pcf)."position", (pcf).query, (pcf).context
          FROM ( SELECT public.plpgsql_check_function_tb(pg_proc.oid, COALESCE(pg_trigger.tgrelid, 0)) AS pcf
            FROM pg_proc LEFT JOIN pg_trigger ON (pg_trigger.tgfoid = pg_proc.oid)
              WHERE prolang = (
                SELECT lang.oid
                 FROM pg_language lang
                    WHERE lang.lanname = 'plpgsql') AND pronamespace <> (
                         SELECT nsp.oid FROM pg_namespace nsp
                             WHERE nsp.nspname = 'pg_catalog') AND (pg_proc.prorettype <> (
                                SELECT typ.oid FROM pg_type typ
                                   WHERE typ.typname = 'trigger') OR pg_trigger.tgfoid IS NOT NULL ) OFFSET 0 ) ss
      WHERE (pcf).message not like 'unused parameter "pi_data"'
      ORDER BY (pcf).functionid::regprocedure::text, (pcf).lineno;
-- R (repeatable): human/operator grants — ONE ROLE PER SCHEMA, least privilege.
--
-- It is the LAST location the migrate loop applies (folder `grants`), so every
-- domain schema already exists when the grants are assigned. The `R__x_` prefix
-- also forces it to run after the per-object repeatable files (procedures) within
-- the location.
--
-- `<schema>_read_role`   -> SELECT within that schema only.
-- `<schema>_write_role`  -> CRUD within that schema only (rare, audited,
--    break-glass; a direct human write BYPASSES the procedures' invariants, so it
--    is exceptional — most human access should be read-only).
--
-- Scoped per schema on purpose: a single database-wide read role would let anyone
-- who needs one schema also read identity PII, the GDPR access records and the
-- signing-evidence trail. Least privilege is the requirement, not the aspiration.
--
-- Per schema does NOT mean one schema per person. A person's named login role is
-- granted INTO as many of these group roles as their job needs and the privileges
-- compose (their own role carries the default INHERIT, so no SET ROLE is needed);
-- adding a schema later is one GRANT, removing one is one REVOKE. What the scoping
-- buys is that nobody silently holds a schema they never needed.
--
-- The roles are created (no login, no credentials) by provision-roles.sh from the
-- deployment's HUMAN_READ_SCHEMAS / HUMAN_WRITE_SCHEMAS lists; this migration only
-- assigns privileges. **A schema whose role does not exist simply gets no human
-- grant** — that is the deployment declining to give anyone direct read access to
-- it, which is a legitimate and desirable answer, so it is silent rather than an
-- error. Named per-person login roles are granted INTO these out-of-band; full
-- admins are separate named superusers.
--
-- Database-name free: CONNECT is granted on whatever database the migration runs
-- against (current_database()), so the same file deploys under any name.
DO $$
DECLARE
    s    record;
    v_rd text;
    v_wr text;
BEGIN
    FOR s IN (SELECT schema_name FROM information_schema.schemata
              WHERE schema_name NOT LIKE 'pg_%' AND schema_name <> 'information_schema')
    LOOP
        v_rd := s.schema_name || '_read_role';
        v_wr := s.schema_name || '_write_role';

        IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = v_rd) THEN
            EXECUTE format('GRANT CONNECT ON DATABASE %I TO %I', current_database(), v_rd);
            EXECUTE format('GRANT USAGE ON SCHEMA %I TO %I', s.schema_name, v_rd);
            EXECUTE format('GRANT SELECT ON ALL TABLES IN SCHEMA %I TO %I', s.schema_name, v_rd);
            EXECUTE format('ALTER DEFAULT PRIVILEGES IN SCHEMA %I GRANT SELECT ON TABLES TO %I', s.schema_name, v_rd);
        END IF;

        IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = v_wr) THEN
            EXECUTE format('GRANT CONNECT ON DATABASE %I TO %I', current_database(), v_wr);
            EXECUTE format('GRANT USAGE ON SCHEMA %I TO %I', s.schema_name, v_wr);
            EXECUTE format('GRANT INSERT, UPDATE, DELETE, SELECT ON ALL TABLES IN SCHEMA %I TO %I', s.schema_name, v_wr);
            EXECUTE format('GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA %I TO %I', s.schema_name, v_wr);
            EXECUTE format('ALTER DEFAULT PRIVILEGES IN SCHEMA %I GRANT INSERT, UPDATE, DELETE, SELECT ON TABLES TO %I', s.schema_name, v_wr);
            EXECUTE format('ALTER DEFAULT PRIVILEGES IN SCHEMA %I GRANT USAGE, SELECT ON SEQUENCES TO %I', s.schema_name, v_wr);
            -- EXECUTE on FUNCTIONS only (e.g. util.generate_ulid behind a column
            -- DEFAULT) so a direct write works — deliberately NOT `ALL PROCEDURES`,
            -- so a human write role still cannot invoke the service procedure set.
            -- Default privileges cannot express that distinction (there, FUNCTIONS
            -- covers procedures too), which is why this stays an explicit grant.
            EXECUTE format('GRANT EXECUTE ON ALL FUNCTIONS IN SCHEMA %I TO %I', s.schema_name, v_wr);
        END IF;
    END LOOP;
END
$$ LANGUAGE plpgsql;

-- Default privileges: the same rules, applied to objects that do not exist yet.
--
-- The GRANT statements above are point-in-time, over objects that already exist.
-- They stay correct only because this file is repeatable and the `grants` location
-- runs LAST, so a table created earlier in the same migrate is always caught. That
-- is an ordering guarantee, not a privilege guarantee: it says nothing about an
-- object created by any other route. Default privileges attach the rule to the
-- schema itself, so the next object created by the owner is born with the right
-- privileges instead of waiting to be granted them. The per-schema human grants
-- above therefore carry their own ALTER DEFAULT PRIVILEGES alongside each GRANT.
--
-- FOR ROLE is left implicit (= the migrating owner), which is exactly the role
-- that creates every object here.
--
-- This last one is database-wide: no future routine is EXECUTE-able by PUBLIC.
--
-- PostgreSQL grants EXECUTE on a newly created routine to PUBLIC by default, so
-- every procedure needs an explicit REVOKE, and a forgotten one is invisible in
-- review because it is an *absence*. That is exactly how two verification-evidence
-- procedures ended up callable by every role that could connect. This makes the
-- safe state the DEFAULT state: forgetting the REVOKE then costs nothing, because
-- there is nothing left to revoke.
--
-- Written WITHOUT `IN SCHEMA`, and it must stay that way. The schema-scoped form
-- (`ALTER DEFAULT PRIVILEGES IN SCHEMA x REVOKE EXECUTE ON FUNCTIONS FROM PUBLIC`)
-- is a SILENT NO-OP: it stores no pg_default_acl row and changes nothing, because
-- the built-in PUBLIC EXECUTE grant is role-level, not schema-level, so there is
-- no schema-scoped grant for it to remove. It reports success either way --
-- verified 2026-08-01, which is why the hardening assertion tests the resulting
-- privilege on a real object rather than the presence of this statement.
--
-- Role-level also means it covers schemas that do not exist yet, not only the ones
-- present when this ran.
--
-- Scope note: default privileges only affect objects created AFTER this runs. On a
-- first migrate into an empty database every routine is created before `grants`
-- executes, so the per-file REVOKE lines stay necessary and assertion 8 is what
-- proves them; from the next migrate onward, new routines are covered by
-- construction.
ALTER DEFAULT PRIVILEGES REVOKE EXECUTE ON FUNCTIONS FROM PUBLIC;

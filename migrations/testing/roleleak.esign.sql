-- Role-leak acceptance: every EXECUTE-only service role must reach its data ONLY
-- through the SECURITY DEFINER procedures — never a direct table read/write — and
-- must be siloed from the other schemas' tables (a role-boundary property, not
-- just a per-table one). The audit schemas add an append-only guarantee: even a
-- direct INSERT/UPDATE/DELETE on the audit table must fail at the GRANT boundary,
-- before the guard trigger is ever reached.
--
-- Run as the owner (POSTGRES_USER) — SET ROLE requires membership/superuser, which
-- the dev/CI owner has:
--   psql -v ON_ERROR_STOP=1 -f migrations/testing/roleleak.sql
-- Expected: no ROLE LEAK exception raised (only a final PASS row per role).

-- Reusable assertion: <role> must NOT be able to run <sql>. Raises ROLE LEAK if it
-- succeeds; swallows the expected insufficient_privilege.
CREATE OR REPLACE FUNCTION pg_temp.deny(p_role text, p_sql text) RETURNS void
LANGUAGE plpgsql AS $$
BEGIN
    EXECUTE format('SET ROLE %I', p_role);
    BEGIN
        EXECUTE p_sql;
        EXECUTE 'RESET ROLE';
        RAISE EXCEPTION 'ROLE LEAK: % could run: %', p_role, p_sql;
    EXCEPTION
        WHEN insufficient_privilege THEN NULL;  -- expected: denied
    END;
    EXECUTE 'RESET ROLE';
END $$;

DO $$
BEGIN
    -- identity (authbyte_public) --------------------------------------------
    PERFORM pg_temp.deny('authbyte_public', 'SELECT count(*) FROM identity.person');
    PERFORM pg_temp.deny('authbyte_public', 'SELECT count(*) FROM identity.credential');
    PERFORM pg_temp.deny('authbyte_public',
        'INSERT INTO identity.person(national_id) VALUES (''x'')');
    -- cross-silo: the auth role cannot read another domain's tables.
    PERFORM pg_temp.deny('authbyte_public', 'SELECT count(*) FROM document.document');

    -- document (document_public) --------------------------------------------
    PERFORM pg_temp.deny('document_public', 'SELECT count(*) FROM document.document');
    PERFORM pg_temp.deny('document_public', 'SELECT count(*) FROM document.document_acl');
    PERFORM pg_temp.deny('document_public', 'SELECT count(*) FROM identity.person');

    -- signflow (signing_public owns both signing + validation) --------------
    PERFORM pg_temp.deny('signing_public', 'SELECT count(*) FROM signing.signing_job');
    PERFORM pg_temp.deny('signing_public', 'SELECT count(*) FROM signing.signature_record');
    PERFORM pg_temp.deny('signing_public', 'SELECT count(*) FROM signing.chain_lock');
    PERFORM pg_temp.deny('signing_public', 'SELECT count(*) FROM validation.report');
    PERFORM pg_temp.deny('signing_public', 'SELECT count(*) FROM envelope.envelope');

    -- envelope (envelope_public) --------------------------------------------
    PERFORM pg_temp.deny('envelope_public', 'SELECT count(*) FROM envelope.envelope');
    PERFORM pg_temp.deny('envelope_public', 'SELECT count(*) FROM envelope.signer_slot');
    PERFORM pg_temp.deny('envelope_public', 'SELECT count(*) FROM envelope.envelope_document');
    PERFORM pg_temp.deny('envelope_public', 'SELECT count(*) FROM signing.signing_job');

    -- eidas_audit (eidas_audit_public) — append-only ------------------------
    PERFORM pg_temp.deny('eidas_audit_public', 'SELECT count(*) FROM eidas_audit.audit_event');
    PERFORM pg_temp.deny('eidas_audit_public',
        'INSERT INTO eidas_audit.audit_event(event_id, occurred_at, event_type, outcome, hash, content) '
        || 'VALUES (''x'', now(), ''x'', ''success'', ''x'', ''{}''::jsonb)');
    PERFORM pg_temp.deny('eidas_audit_public', 'UPDATE eidas_audit.audit_event SET outcome = ''x''');
    PERFORM pg_temp.deny('eidas_audit_public', 'DELETE FROM eidas_audit.audit_event');
    PERFORM pg_temp.deny('eidas_audit_public', 'SELECT count(*) FROM access_audit.access_record');

    -- access_audit (access_audit_public) — append-only ---------------------
    PERFORM pg_temp.deny('access_audit_public', 'SELECT count(*) FROM access_audit.access_record');
    PERFORM pg_temp.deny('access_audit_public',
        'INSERT INTO access_audit.access_record(event_id, occurred_at, retention_period, event_type, outcome, seal, content) '
        || 'VALUES (''x'', now(), current_date, ''x'', ''success'', ''x'', ''{}''::jsonb)');
    PERFORM pg_temp.deny('access_audit_public', 'UPDATE access_audit.access_record SET outcome = ''x''');
    PERFORM pg_temp.deny('access_audit_public', 'DELETE FROM access_audit.access_record');
    PERFORM pg_temp.deny('access_audit_public', 'SELECT count(*) FROM eidas_audit.audit_event');

    -- trust_anchor (trust_anchor_public) ------------------------------------
    PERFORM pg_temp.deny('trust_anchor_public', 'SELECT count(*) FROM trust_anchor.snapshot');
    PERFORM pg_temp.deny('trust_anchor_public', 'SELECT count(*) FROM trust_anchor.bootstrap');
    PERFORM pg_temp.deny('trust_anchor_public', 'SELECT count(*) FROM identity.person');
END $$;

SELECT 'ROLELEAK: PASS — every service role is table-isolated, cross-silo denied, and the audit tables are append-only at the grant boundary' AS result;

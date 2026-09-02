-- R: repeatable migration — the identity schema's data API.
--
-- Every read/write the authentication service performs goes through one of these
-- SECURITY DEFINER procedures. They run as the owner of the tables, so the
-- EXECUTE-only `authbyte_public` service role can drive them without any table
-- privileges of its own. Each procedure:
--   * uses the uniform JSONB envelope `(pi_data jsonb, INOUT po_data jsonb)`,
--   * pins `search_path` ending in pg_temp (SECURITY DEFINER hardening),
--   * returns a structured result via util.result_success / util.result_error
--     with `<domain>:<reason>` error codes (`identity:not_found` → HTTP 404),
--   * validates BEFORE any write and, on any unexpected error after a write,
--     re-raises a structured error with SQLSTATE P0001 so the transaction ROLLS
--     BACK rather than committing a partial write.
-- Repeatable: re-applied automatically whenever the checksum changes.

-- identity.upsert — resolve a login to a stable PERSON subject and link the
-- auth-method credential. The natural person is keyed on the
-- eIDAS national id (`serial_number` / `national_id`); the auth-method handle
-- (`idp_sub`, an opaque hash for eParaksts, the national id for Web eID) becomes
-- a credential row pointing at that person. So the SAME human authenticating
-- through different methods resolves to ONE `internal_sub` (the person id),
-- instead of one identity per method.
--
-- Returns {"internal_sub": "<person id>", "created": <bool>}. `created` is true
-- only when THIS call inserted the person (the person's first-ever login, by any
-- method) — detected via the `xmax = 0` upsert idiom — so the service records the
-- correct GDPR-audit event (identity created vs updated). Adding a new method to an
-- existing person is an update, not a create.
CREATE OR REPLACE PROCEDURE identity.upsert(pi_data jsonb, INOUT po_data jsonb)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = identity, util, pg_temp
AS $$
DECLARE
    v_idp_sub      text := pi_data->>'idp_sub';
    -- the national id is the person key; accept either field name (the service
    -- sends `serial_number`), prefer an explicit `national_id`.
    v_national_id  text := COALESCE(NULLIF(pi_data->>'national_id', ''), pi_data->>'serial_number');
    v_login_method text := COALESCE(pi_data->>'login_method', '');
    v_person_sub   text;
    v_created      boolean;
BEGIN
    IF v_idp_sub IS NULL OR v_idp_sub = '' THEN
        po_data := util.result_error('identity:invalid', 'idp_sub is required');
        RETURN;
    END IF;
    -- A natural-person identity REQUIRES the eIDAS unique id; without it we
    -- cannot dedupe across methods, so reject rather than create an orphan.
    IF v_national_id IS NULL OR v_national_id = '' THEN
        po_data := util.result_error('identity:invalid', 'national_id (serial_number) is required');
        RETURN;
    END IF;

    -- 1) Resolve / create the person by national id, refreshing the profile.
    INSERT INTO identity.person (national_id, name, given_name, family_name)
    VALUES (
        v_national_id,
        COALESCE(pi_data->>'name', ''),
        COALESCE(pi_data->>'given_name', ''),
        COALESCE(pi_data->>'family_name', '')
    )
    ON CONFLICT (national_id) DO UPDATE SET
        name        = EXCLUDED.name,
        given_name  = EXCLUDED.given_name,
        family_name = EXCLUDED.family_name,
        updated_at  = now()
    RETURNING person_sub, (xmax = 0) INTO v_person_sub, v_created;

    -- 2) Link the auth-method credential (idp_sub) to that person.
    INSERT INTO identity.credential (idp_sub, person_sub, login_method)
    VALUES (v_idp_sub, v_person_sub, v_login_method)
    ON CONFLICT (idp_sub) DO UPDATE SET
        person_sub   = EXCLUDED.person_sub,
        login_method = EXCLUDED.login_method,
        updated_at   = now();

    po_data := util.result_success(jsonb_build_object('internal_sub', v_person_sub, 'created', v_created));
EXCEPTION
    WHEN SQLSTATE 'P0001' THEN
        RAISE;  -- already a structured error → re-raise unchanged
    WHEN OTHERS THEN
        -- unexpected error after a write → roll back via a structured P0001
        RAISE EXCEPTION '%', util.result_error('identity:upsert_failed', SQLERRM) USING ERRCODE = 'P0001';
END
$$;

-- identity.get — read a person by internal `sub` (person id) or by any of their
-- IdP `sub`s / credential handles. Returns the person profile
-- (and, when looked up by idp_sub, the matched credential's handle + method), or
-- identity:not_found.
CREATE OR REPLACE PROCEDURE identity.get(pi_data jsonb, INOUT po_data jsonb)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = identity, util, pg_temp
AS $$
DECLARE
    v_internal_sub text := pi_data->>'internal_sub';
    v_idp_sub      text := pi_data->>'idp_sub';
    v_person       identity.person%ROWTYPE;
    v_cred         identity.credential%ROWTYPE;
BEGIN
    IF (v_internal_sub IS NULL OR v_internal_sub = '')
       AND (v_idp_sub IS NULL OR v_idp_sub = '') THEN
        po_data := util.result_error('identity:invalid', 'internal_sub or idp_sub is required');
        RETURN;
    END IF;

    IF v_internal_sub IS NOT NULL AND v_internal_sub <> '' THEN
        SELECT * INTO v_person FROM identity.person WHERE person_sub = v_internal_sub;
    ELSE
        SELECT * INTO v_cred FROM identity.credential WHERE idp_sub = v_idp_sub;
        IF FOUND THEN
            SELECT * INTO v_person FROM identity.person WHERE person_sub = v_cred.person_sub;
        END IF;
    END IF;

    IF v_person.person_sub IS NULL THEN
        po_data := util.result_error('identity:not_found', 'identity not found');
        RETURN;
    END IF;

    po_data := util.result_success(jsonb_build_object(
        'internal_sub',  v_person.person_sub,
        'idp_sub',       COALESCE(v_cred.idp_sub, v_idp_sub),
        'login_method',  COALESCE(v_cred.login_method, ''),
        'tenant_id',     v_person.tenant_id,
        'name',          v_person.name,
        'given_name',    v_person.given_name,
        'family_name',   v_person.family_name,
        'serial_number', v_person.national_id
    ));
EXCEPTION
    WHEN SQLSTATE 'P0001' THEN
        RAISE;
    WHEN OTHERS THEN
        RAISE EXCEPTION '%', util.result_error('identity:get_failed', SQLERRM) USING ERRCODE = 'P0001';
END
$$;


-- EXECUTE-only: revoke from PUBLIC, grant only to the service role.
REVOKE ALL ON PROCEDURE identity.upsert(jsonb, jsonb) FROM PUBLIC;
REVOKE ALL ON PROCEDURE identity.get(jsonb, jsonb)    FROM PUBLIC;
GRANT EXECUTE ON PROCEDURE identity.upsert(jsonb, jsonb) TO authbyte_public;
GRANT EXECUTE ON PROCEDURE identity.get(jsonb, jsonb)    TO authbyte_public;

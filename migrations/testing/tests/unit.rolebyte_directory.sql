-- Unit test: a tenant's attached directory, and the admission of its people.
--
-- A tenant names the directory it trusts as its own — the issuer its people sign
-- in through. A person authenticating through that issuer is admitted to the
-- tenant as an ACTIVE member with NO grants until an administrator gives them a
-- role; people from any other issuer are admitted nowhere. One directory belongs
-- to at most one tenant, and the directory travels with the tenant's
-- configuration document.
--
-- Runs as the owner (which owns the SECURITY DEFINER procedures, so it may CALL
-- them regardless of the EXECUTE grants). ON_ERROR_STOP + RAISE EXCEPTION on a
-- failed assertion fails the build.
--   psql -v ON_ERROR_STOP=1 -f migrations/testing/tests/unit.rolebyte_directory.sql

DO $$
DECLARE
    v          jsonb;
    v_actor    text := 'unit-rbdir-admin';
    v_idp      text := 'unit-rbdir-idp';
    v_a        text;                                   -- tenant A
    v_b        text;                                   -- tenant B
    v_iss_1    text := 'https://directory.example/tenants/alpha/v2.0';
    v_iss_2    text := 'https://directory.example/tenants/beta/v2.0';
    v_iss_3    text := 'http://directory-standin:8080';   -- a development stand-in: http is a shape the provider decides
    v_iss_none text := 'https://nobody.example/attached/this';
    v_p1       text := 'sub:' || util.generate_ulid();   -- a person from the directory
    v_p2       text := 'sub:' || util.generate_ulid();   -- a person from an issuer nobody attached
    v_p3       text := 'sub:' || util.generate_ulid();   -- invited by an administrator AND in the directory
    v_p4       text := 'sub:' || util.generate_ulid();   -- arrives after the directory is detached
    v_svc      text := 'svc:' || 'unit-rbdir-machine';
    v_user_1   text;
    v_user_3   text;
    v_bad      text;
    v_n        integer;
BEGIN
    -- ---------------------------------------------------------------- fixture
    CALL rolebyte.tenant_create(jsonb_build_object('actor', v_actor, 'name', 'Directory alpha'), v);
    IF v->>'result' IS DISTINCT FROM 'success' THEN RAISE EXCEPTION 'tenant_create A failed: %', v; END IF;
    v_a := v->'data'->>'id';
    CALL rolebyte.tenant_create(jsonb_build_object('actor', v_actor, 'name', 'Directory beta'), v);
    IF v->>'result' IS DISTINCT FROM 'success' THEN RAISE EXCEPTION 'tenant_create B failed: %', v; END IF;
    v_b := v->'data'->>'id';
    CALL rolebyte.service_register(jsonb_build_object('actor', v_actor, 'service', 'rbdir', 'displayName', 'Directory demo'), v);
    IF v->>'result' IS DISTINCT FROM 'success' THEN RAISE EXCEPTION 'service_register failed: %', v; END IF;
    CALL rolebyte.role_define(jsonb_build_object('actor', v_actor, 'service', 'rbdir', 'group', 'rbdir', 'level', 'worker'), v);
    IF v->>'result' IS DISTINCT FROM 'success' THEN RAISE EXCEPTION 'role_define failed: %', v; END IF;

    -- (1) Attach: the tenant names its directory — the row holds it exactly as
    --     given, one attributed event.
    CALL rolebyte.directory_attach(jsonb_build_object('actor', v_actor, 'tenantId', v_a, 'issuer', '  ' || v_iss_1 || '  '), v);
    IF v->>'result' IS DISTINCT FROM 'success' OR (v->'data'->>'changed')::boolean IS NOT TRUE THEN
        RAISE EXCEPTION 'attach failed: %', v;
    END IF;
    IF (SELECT directory_issuer FROM rolebyte.tenant WHERE id = v_a) IS DISTINCT FROM v_iss_1 THEN
        RAISE EXCEPTION 'the issuer was not stored as given (trimmed): %', (SELECT directory_issuer FROM rolebyte.tenant WHERE id = v_a);
    END IF;
    SELECT count(*) INTO v_n FROM rolebyte.event WHERE tenant_id = v_a AND kind = 'directoryAttached' AND actor = v_actor AND payload->>'issuer' = v_iss_1;
    IF v_n <> 1 THEN RAISE EXCEPTION 'attach should log exactly one directoryAttached event, found %', v_n; END IF;

    -- (2) Attaching the value already held changes nothing and logs nothing.
    CALL rolebyte.directory_attach(jsonb_build_object('actor', v_actor, 'tenantId', v_a, 'issuer', v_iss_1), v);
    IF v->>'result' IS DISTINCT FROM 'success' OR (v->'data'->>'changed')::boolean IS NOT FALSE THEN
        RAISE EXCEPTION 're-attaching the same issuer should change nothing: %', v;
    END IF;
    SELECT count(*) INTO v_n FROM rolebyte.event WHERE tenant_id = v_a AND kind = 'directoryAttached';
    IF v_n <> 1 THEN RAISE EXCEPTION 'a no-op attach logged an event'; END IF;

    -- (3) One directory, one tenant: B cannot attach A's issuer, by the procedure
    --     and by the database itself.
    CALL rolebyte.directory_attach(jsonb_build_object('actor', v_actor, 'tenantId', v_b, 'issuer', v_iss_1), v);
    IF v->>'code' IS DISTINCT FROM 'membership:conflict' THEN
        RAISE EXCEPTION 'a second tenant attaching the same issuer should be membership:conflict: %', v;
    END IF;
    IF (SELECT directory_issuer FROM rolebyte.tenant WHERE id = v_b) IS NOT NULL THEN
        RAISE EXCEPTION 'the refused attach left an issuer on tenant B';
    END IF;
    BEGIN
        UPDATE rolebyte.tenant SET directory_issuer = v_iss_1 WHERE id = v_b;
        RAISE EXCEPTION 'the database let two tenants hold one directory';
    EXCEPTION WHEN unique_violation THEN NULL;
    END;

    -- (4) What an issuer may look like: an absolute http(s) URL, no whitespace,
    --     no query, no fragment. Refused by the procedure with a structured error
    --     and by the column itself; a development stand-in over http is accepted.
    FOREACH v_bad IN ARRAY ARRAY[
        'directory.example/tenants/alpha',          -- no scheme
        'ftp://directory.example',                  -- not http(s)
        'https://directory.example/a b',            -- whitespace
        'https://directory.example/v2.0?tenant=1',  -- a query
        'https://directory.example/v2.0#frag',      -- a fragment
        'https://'                                  -- no host
    ] LOOP
        CALL rolebyte.directory_attach(jsonb_build_object('actor', v_actor, 'tenantId', v_b, 'issuer', v_bad), v);
        IF v->>'code' IS DISTINCT FROM 'membership:invalid' THEN
            RAISE EXCEPTION 'a malformed issuer should be membership:invalid, got % for %', v, v_bad;
        END IF;
        IF position(v_bad IN v->>'message') > 0 THEN
            RAISE EXCEPTION 'the refusal echoed the value: %', v;
        END IF;
        BEGIN
            UPDATE rolebyte.tenant SET directory_issuer = v_bad WHERE id = v_b;
            RAISE EXCEPTION 'the database accepted a malformed issuer: %', v_bad;
        EXCEPTION WHEN check_violation THEN NULL;
        END;
    END LOOP;
    CALL rolebyte.directory_attach(jsonb_build_object('actor', v_actor, 'tenantId', v_b, 'issuer', v_iss_3), v);
    IF v->>'result' IS DISTINCT FROM 'success' THEN
        RAISE EXCEPTION 'a development stand-in issuer over http should be accepted: %', v;
    END IF;
    IF (SELECT directory_issuer FROM rolebyte.tenant WHERE id = v_b) IS DISTINCT FROM v_iss_3 THEN
        RAISE EXCEPTION 'tenant B did not get its own directory';
    END IF;

    -- (5) An unknown tenant, a missing actor, a missing tenant.
    CALL rolebyte.directory_attach(jsonb_build_object('actor', v_actor, 'tenantId', 'no-such-tenant', 'issuer', v_iss_2), v);
    IF v->>'code' IS DISTINCT FROM 'tenant:not_found' THEN RAISE EXCEPTION 'unknown tenant: %', v; END IF;
    CALL rolebyte.directory_attach(jsonb_build_object('tenantId', v_a, 'issuer', v_iss_2), v);
    IF v->>'code' IS DISTINCT FROM 'membership:invalid' THEN RAISE EXCEPTION 'missing actor: %', v; END IF;

    -- (6) THE ADMISSION. A person authenticating through A's directory becomes an
    --     ACTIVE member of A with NO grants: one row, one attributed event, and the
    --     token-issue path answers the tenant with an empty scope set.
    CALL rolebyte.directory_admit(jsonb_build_object(
        'actor', v_idp, 'subjectKey', v_p1, 'issuer', v_iss_1, 'displayName', 'Directory Person'), v);
    IF v->>'result' IS DISTINCT FROM 'success' OR v->'data'->>'outcome' IS DISTINCT FROM 'admitted' THEN
        RAISE EXCEPTION 'first admission should be admitted: %', v;
    END IF;
    IF v->'data'->>'tenantId' IS DISTINCT FROM v_a OR jsonb_array_length(v->'data'->'admitted') <> 1 THEN
        RAISE EXCEPTION 'the admission did not name tenant A once: %', v;
    END IF;
    v_user_1 := v->'data'->'admitted'->0->>'userId';
    IF (SELECT status FROM rolebyte.user_account WHERE id = v_user_1 AND tenant_id = v_a AND subject_key = v_p1) IS DISTINCT FROM 'active' THEN
        RAISE EXCEPTION 'the admitted person is not an active member of A';
    END IF;
    IF (SELECT display_name FROM rolebyte.user_account WHERE id = v_user_1) IS DISTINCT FROM 'Directory Person' THEN
        RAISE EXCEPTION 'the display name from the login was not stored';
    END IF;
    SELECT count(*) INTO v_n FROM rolebyte.assignment WHERE user_id = v_user_1;
    IF v_n <> 0 THEN RAISE EXCEPTION 'an admitted person holds % grant(s) — provisioned is not roled', v_n; END IF;
    SELECT count(*) INTO v_n FROM rolebyte.event
     WHERE tenant_id = v_a AND user_id = v_user_1 AND kind = 'directoryAdmitted'
       AND actor = v_idp AND payload->>'issuer' = v_iss_1 AND payload->>'subjectKey' = v_p1;
    IF v_n <> 1 THEN RAISE EXCEPTION 'the admission should log exactly one directoryAdmitted event, found %', v_n; END IF;
    CALL rolebyte.resolve(jsonb_build_object('subjectKey', v_p1), v);
    IF jsonb_array_length(v->'data'->'memberships') <> 1
       OR v->'data'->'memberships'->0->>'tenantId' IS DISTINCT FROM v_a
       OR v->'data'->'memberships'->0->'scopes' IS DISTINCT FROM '[]'::jsonb THEN
        RAISE EXCEPTION 'an admitted person should resolve to tenant A with no scopes: %', v;
    END IF;

    -- (7) The same person again: already a member — nothing changes, nothing is
    --     logged, and the display name is not rewritten.
    CALL rolebyte.directory_admit(jsonb_build_object(
        'actor', v_idp, 'subjectKey', v_p1, 'issuer', v_iss_1, 'displayName', 'Renamed In Directory'), v);
    IF v->'data'->>'outcome' IS DISTINCT FROM 'member' OR jsonb_array_length(v->'data'->'admitted') <> 0 THEN
        RAISE EXCEPTION 'a second admission should be a member no-op: %', v;
    END IF;
    SELECT count(*) INTO v_n FROM rolebyte.user_account WHERE tenant_id = v_a AND subject_key = v_p1;
    IF v_n <> 1 THEN RAISE EXCEPTION 'a repeat admission made % rows', v_n; END IF;
    SELECT count(*) INTO v_n FROM rolebyte.event WHERE tenant_id = v_a AND kind = 'directoryAdmitted';
    IF v_n <> 1 THEN RAISE EXCEPTION 'a no-op admission logged an event'; END IF;

    -- (8) An issuer nobody attached admits nobody: no row anywhere, the person
    --     resolves to nothing, and refusal is the caller's.
    CALL rolebyte.directory_admit(jsonb_build_object(
        'actor', v_idp, 'subjectKey', v_p2, 'issuer', v_iss_none, 'displayName', 'Stranger'), v);
    IF v->>'result' IS DISTINCT FROM 'success' OR v->'data'->>'outcome' IS DISTINCT FROM 'noDirectory'
       OR v->'data'->>'tenantId' IS NOT NULL OR jsonb_array_length(v->'data'->'admitted') <> 0 THEN
        RAISE EXCEPTION 'an unattached issuer should admit nobody: %', v;
    END IF;
    SELECT count(*) INTO v_n FROM rolebyte.user_account WHERE subject_key = v_p2;
    IF v_n <> 0 THEN RAISE EXCEPTION 'a login from an unattached issuer left % row(s)', v_n; END IF;
    CALL rolebyte.resolve(jsonb_build_object('subjectKey', v_p2), v);
    IF jsonb_array_length(v->'data'->'memberships') <> 0 THEN
        RAISE EXCEPTION 'a person nobody admitted resolves to a membership: %', v;
    END IF;

    -- (9) Only persons, only well-formed requests: a service account, an untyped
    --     key, a missing issuer and a missing display name are refused before any
    --     write.
    CALL rolebyte.directory_admit(jsonb_build_object('actor', v_idp, 'subjectKey', v_svc, 'issuer', v_iss_1, 'displayName', 'A machine'), v);
    IF v->>'code' IS DISTINCT FROM 'membership:invalid' OR position('persons only' IN v->>'message') = 0 THEN
        RAISE EXCEPTION 'a service account should be refused with the persons-only sentence: %', v;
    END IF;
    CALL rolebyte.directory_admit(jsonb_build_object('actor', v_idp, 'subjectKey', 'somebody', 'issuer', v_iss_1, 'displayName', 'Untyped'), v);
    IF v->>'code' IS DISTINCT FROM 'membership:invalid' THEN RAISE EXCEPTION 'an untyped key: %', v; END IF;
    CALL rolebyte.directory_admit(jsonb_build_object('actor', v_idp, 'subjectKey', v_p2, 'displayName', 'No issuer'), v);
    IF v->>'code' IS DISTINCT FROM 'membership:invalid' THEN RAISE EXCEPTION 'a missing issuer: %', v; END IF;
    CALL rolebyte.directory_admit(jsonb_build_object('actor', v_idp, 'subjectKey', v_p2, 'issuer', v_iss_1), v);
    IF v->>'code' IS DISTINCT FROM 'membership:invalid' THEN RAISE EXCEPTION 'a missing display name: %', v; END IF;
    SELECT count(*) INTO v_n FROM rolebyte.user_account WHERE subject_key IN (v_svc, 'somebody', v_p2);
    IF v_n <> 0 THEN RAISE EXCEPTION 'a refused admission left % row(s)', v_n; END IF;

    -- (10) Invited by an administrator AND arriving through the directory: the
    --      admission activates the invitation and the invited roles are kept.
    CALL rolebyte.user_invite(jsonb_build_object(
        'actor', v_actor, 'tenantId', v_a, 'subjectKey', v_p3, 'displayName', 'Invited Worker',
        'roles', '[{"service":"rbdir","group":"rbdir","level":"worker"}]'::jsonb), v);
    IF v->>'result' IS DISTINCT FROM 'success' THEN RAISE EXCEPTION 'user_invite failed: %', v; END IF;
    v_user_3 := v->'data'->>'id';
    CALL rolebyte.directory_admit(jsonb_build_object(
        'actor', v_idp, 'subjectKey', v_p3, 'issuer', v_iss_1, 'displayName', 'Invited Worker'), v);
    IF v->'data'->>'outcome' IS DISTINCT FROM 'admitted' OR v->'data'->'admitted'->0->>'userId' IS DISTINCT FROM v_user_3 THEN
        RAISE EXCEPTION 'an invited person arriving through the directory should be admitted on their invited row: %', v;
    END IF;
    IF (SELECT status FROM rolebyte.user_account WHERE id = v_user_3) IS DISTINCT FROM 'active' THEN
        RAISE EXCEPTION 'the invitation was not activated by the admission';
    END IF;
    SELECT count(*) INTO v_n FROM rolebyte.user_account WHERE tenant_id = v_a AND subject_key = v_p3;
    IF v_n <> 1 THEN RAISE EXCEPTION 'the admission of an invited person made a second row'; END IF;
    IF NOT EXISTS (SELECT 1 FROM rolebyte.event WHERE user_id = v_user_3 AND kind = 'directoryAdmitted'
                     AND (payload->>'claimedInvitation')::boolean IS TRUE) THEN
        RAISE EXCEPTION 'the event should say the admission claimed an invitation';
    END IF;
    CALL rolebyte.resolve(jsonb_build_object('subjectKey', v_p3), v);
    IF v->'data'->'memberships'->0->'scopes' IS DISTINCT FROM '["rbdir:worker"]'::jsonb THEN
        RAISE EXCEPTION 'the invited roles should survive the admission: %', v;
    END IF;

    -- (11) A revoked member is not readmitted by the directory: the
    --      administrator's act stands.
    CALL rolebyte.user_revoke(jsonb_build_object('actor', v_actor, 'tenantId', v_a, 'userId', v_user_1), v);
    IF v->>'result' IS DISTINCT FROM 'success' THEN RAISE EXCEPTION 'user_revoke failed: %', v; END IF;
    CALL rolebyte.directory_admit(jsonb_build_object(
        'actor', v_idp, 'subjectKey', v_p1, 'issuer', v_iss_1, 'displayName', 'Directory Person'), v);
    IF v->'data'->>'outcome' IS DISTINCT FROM 'revoked' OR jsonb_array_length(v->'data'->'admitted') <> 0 THEN
        RAISE EXCEPTION 'a revoked person should not be readmitted: %', v;
    END IF;
    IF (SELECT status FROM rolebyte.user_account WHERE id = v_user_1) IS DISTINCT FROM 'revoked' THEN
        RAISE EXCEPTION 'the directory overruled a revocation';
    END IF;
    CALL rolebyte.resolve(jsonb_build_object('subjectKey', v_p1), v);
    IF jsonb_array_length(v->'data'->'memberships') <> 0 THEN
        RAISE EXCEPTION 'a revoked person resolves after a directory login: %', v;
    END IF;

    -- (12) The configuration document carries the directory: it reads back, a
    --      document changes it through the same act (event included), the read's
    --      own answer re-applies as unchanged, a document without one leaves it,
    --      and a malformed one writes nothing.
    CALL rolebyte.config_get(jsonb_build_object('tenantId', v_a), v);
    IF v->'data'->'tenant'->'directory'->>'issuer' IS DISTINCT FROM v_iss_1 THEN
        RAISE EXCEPTION 'config_get should carry the attached directory: %', v;
    END IF;
    CALL rolebyte.config_apply(jsonb_build_object('tenantId', v_a, 'actor', v_actor,
        'section', jsonb_build_object('tenant', jsonb_build_object('directory', jsonb_build_object('issuer', v_iss_2)))), v);
    IF v->>'result' IS DISTINCT FROM 'success' OR v->'data'->'tenant'->'directory'->>'status' IS DISTINCT FROM 'changed' THEN
        RAISE EXCEPTION 'a document should be able to change the directory: %', v;
    END IF;
    IF (SELECT directory_issuer FROM rolebyte.tenant WHERE id = v_a) IS DISTINCT FROM v_iss_2 THEN
        RAISE EXCEPTION 'the directory did not follow the document';
    END IF;
    IF NOT EXISTS (SELECT 1 FROM rolebyte.event WHERE tenant_id = v_a AND kind = 'directoryAttached'
                     AND payload->>'issuer' = v_iss_2 AND payload->>'from' = v_iss_1) THEN
        RAISE EXCEPTION 'a change through the document should log the attach with the previous issuer';
    END IF;
    CALL rolebyte.config_get(jsonb_build_object('tenantId', v_a), v);
    CALL rolebyte.config_apply(jsonb_build_object('tenantId', v_a, 'actor', v_actor, 'section', v->'data'), v);
    IF v->'data'->'tenant'->'directory'->>'status' IS DISTINCT FROM 'unchanged'
       OR v->'data'->'tenant'->>'status' IS DISTINCT FROM 'unchanged' THEN
        RAISE EXCEPTION 'the round trip should change nothing: %', v;
    END IF;
    CALL rolebyte.config_apply(jsonb_build_object('tenantId', v_a, 'actor', v_actor,
        'section', '{"services":[]}'::jsonb), v);
    IF v->>'result' IS DISTINCT FROM 'success' OR v->'data'->'tenant' IS DISTINCT FROM 'null'::jsonb THEN
        RAISE EXCEPTION 'a document without a tenant section should report no tenant change: %', v;
    END IF;
    IF (SELECT directory_issuer FROM rolebyte.tenant WHERE id = v_a) IS DISTINCT FROM v_iss_2 THEN
        RAISE EXCEPTION 'a document without a directory detached it';
    END IF;
    BEGIN
        CALL rolebyte.config_apply(jsonb_build_object('tenantId', v_a, 'actor', v_actor,
            'section', '{"tenant":{"directory":{"issuer":"not an issuer"}}}'::jsonb), v);
        RAISE EXCEPTION 'a malformed directory in a document should have been refused';
    EXCEPTION WHEN sqlstate 'P0001' THEN
        IF SQLERRM NOT LIKE '%membership:invalid%' THEN
            RAISE EXCEPTION 'a malformed directory raised the wrong code: %', SQLERRM;
        END IF;
    END;
    IF (SELECT directory_issuer FROM rolebyte.tenant WHERE id = v_a) IS DISTINCT FROM v_iss_2 THEN
        RAISE EXCEPTION 'a refused document changed the directory';
    END IF;

    -- (13) Detach: an attributed event, the tenant admits nobody afterwards, and
    --      the people already admitted keep their membership (leaving is an
    --      administration act on the person, not a side effect on the tenant).
    CALL rolebyte.directory_attach(jsonb_build_object('actor', v_actor, 'tenantId', v_a), v);
    IF v->>'result' IS DISTINCT FROM 'success' OR (v->'data'->>'changed')::boolean IS NOT TRUE OR v->'data'->>'issuer' IS NOT NULL THEN
        RAISE EXCEPTION 'detach failed: %', v;
    END IF;
    IF NOT EXISTS (SELECT 1 FROM rolebyte.event WHERE tenant_id = v_a AND kind = 'directoryDetached' AND payload->>'issuer' = v_iss_2) THEN
        RAISE EXCEPTION 'the detach should log the issuer it removed';
    END IF;
    CALL rolebyte.directory_admit(jsonb_build_object(
        'actor', v_idp, 'subjectKey', v_p4, 'issuer', v_iss_2, 'displayName', 'Late Arrival'), v);
    IF v->'data'->>'outcome' IS DISTINCT FROM 'noDirectory' THEN
        RAISE EXCEPTION 'a detached directory should admit nobody: %', v;
    END IF;
    CALL rolebyte.resolve(jsonb_build_object('subjectKey', v_p3), v);
    IF jsonb_array_length(v->'data'->'memberships') <> 1 THEN
        RAISE EXCEPTION 'detaching the directory should not remove an admitted member: %', v;
    END IF;
    CALL rolebyte.directory_attach(jsonb_build_object('actor', v_actor, 'tenantId', v_a, 'issuer', ''), v);
    IF (v->'data'->>'changed')::boolean IS NOT FALSE THEN
        RAISE EXCEPTION 'detaching twice should change nothing: %', v;
    END IF;

    -- (14) The history answers the directory's story.
    CALL rolebyte.history(jsonb_build_object('tenantId', v_a), v);
    IF v->>'result' IS DISTINCT FROM 'success' THEN RAISE EXCEPTION 'history failed: %', v; END IF;
    FOREACH v_bad IN ARRAY ARRAY['directoryAttached', 'directoryAdmitted', 'directoryDetached'] LOOP
        IF NOT EXISTS (SELECT 1 FROM jsonb_array_elements(v->'data'->'events') e WHERE e->>'kind' = v_bad) THEN
            RAISE EXCEPTION 'history misses %', v_bad;
        END IF;
    END LOOP;

    RAISE NOTICE 'unit.rolebyte_directory: all assertions passed';
END $$;

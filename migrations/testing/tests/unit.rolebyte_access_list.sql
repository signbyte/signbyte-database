-- Unit test: who holds what in a tenant. The administration read lists every
-- member of the tenant and nobody from another, in name order, each with the
-- service roles, tenant roles and Administrator checkbox the register holds for
-- them; the checkbox is never also a service role; a revoked member stays listed
-- with their grants on record; a service account is listed and marked; an
-- arrival is exactly an active person holding nothing; a renamed role is read by
-- its new name and a revoked grant is gone; the read writes nothing; a missing
-- or unknown tenant is refused; and the register's own role may run it.
--   psql -v ON_ERROR_STOP=1 -f migrations/testing/tests/unit.rolebyte_access_list.sql

-- Calls one register procedure and returns its answer.
CREATE OR REPLACE FUNCTION pg_temp.rb(p_proc text, p_in jsonb) RETURNS jsonb
LANGUAGE plpgsql AS $$
DECLARE
    v jsonb;
BEGIN
    EXECUTE format('CALL rolebyte.%I($1, NULL::jsonb)', p_proc) INTO v USING p_in;
    RETURN v;
END $$;

-- The call must succeed; returns its data.
CREATE OR REPLACE FUNCTION pg_temp.ok(p_proc text, p_in jsonb, p_why text) RETURNS jsonb
LANGUAGE plpgsql AS $$
DECLARE
    v jsonb := pg_temp.rb(p_proc, p_in);
BEGIN
    IF v->>'result' IS DISTINCT FROM 'success' THEN
        RAISE EXCEPTION '% failed: %', p_why, v;
    END IF;
    RETURN v->'data';
END $$;

-- Everything a read must leave as it was.
CREATE OR REPLACE FUNCTION pg_temp.state() RETURNS text
LANGUAGE sql AS $$
    SELECT concat_ws('/',
        (SELECT count(*) FROM rolebyte.tenant),
        (SELECT string_agg(id || status, ',' ORDER BY id) FROM rolebyte.user_account),
        (SELECT string_agg(id || state, ',' ORDER BY id) FROM rolebyte.assignment),
        (SELECT string_agg(id || state, ',' ORDER BY id) FROM rolebyte.tenant_role_assignment),
        (SELECT count(*) FROM rolebyte.event));
$$;

-- The tenant's access list, read, and proven to have written nothing.
CREATE OR REPLACE FUNCTION pg_temp.access(p_tenant text) RETURNS jsonb
LANGUAGE plpgsql AS $$
DECLARE
    before text := pg_temp.state();
    v      jsonb;
BEGIN
    v := pg_temp.ok('access_list', jsonb_build_object('tenantId', p_tenant), 'access_list of ' || p_tenant);
    IF pg_temp.state() IS DISTINCT FROM before THEN
        RAISE EXCEPTION 'reading the access list of % changed something', p_tenant;
    END IF;
    RETURN v->'members';
END $$;

-- The listed member ids, in the order the list gives them.
CREATE OR REPLACE FUNCTION pg_temp.ids(p_list jsonb) RETURNS text[]
LANGUAGE sql AS $$
    SELECT COALESCE(array_agg(m->>'id' ORDER BY n), '{}') FROM jsonb_array_elements(p_list) WITH ORDINALITY x(m, n);
$$;

-- One member of a list, by id.
CREATE OR REPLACE FUNCTION pg_temp.member(p_list jsonb, p_id text) RETURNS jsonb
LANGUAGE plpgsql AS $$
DECLARE
    v jsonb;
BEGIN
    SELECT m INTO v FROM jsonb_array_elements(p_list) m WHERE m->>'id' = p_id;
    IF v IS NULL THEN
        RAISE EXCEPTION 'member % is not in the list: %', p_id, p_list;
    END IF;
    RETURN v;
END $$;

-- One key of a member's row must hold exactly this.
CREATE OR REPLACE FUNCTION pg_temp.says(p_row jsonb, p_key text, p_want jsonb, p_why text) RETURNS void
LANGUAGE plpgsql AS $$
BEGIN
    IF p_row->p_key IS DISTINCT FROM p_want THEN
        RAISE EXCEPTION '%: % should be %, is % (row %)', p_why, p_key, p_want, p_row->p_key, p_row;
    END IF;
END $$;

DO $$
DECLARE
    v_s        text[] := ARRAY(SELECT 'sub:' || util.generate_ulid() FROM generate_series(1, 9));
    v_svc      text := 'svc:unit-access-list-machine';
    v_iss      text := 'https://directory.example/unit-access-list';
    v_ta       text;
    v_tb       text;
    v_anna     text;
    v_bela     text;
    v_ilze     text;
    v_janis    text;
    v_karlis   text;
    v_laura    text;
    v_martins  text;
    v_martinsb text;
    v_peteris  text;
    v_toms     text;
    v_machine  text;
    v_meistars text;
    v_brig     text;
    v_list     jsonb;
    v_row      jsonb;
    v          jsonb;
    v_before   text;
    v_key      text;
    NONE       CONSTANT jsonb := '[]';
    READS      CONSTANT jsonb := '[{"service":"alsvc","group":"alsvc","level":"read"}]';
    WRITES     CONSTANT jsonb := '[{"service":"alsvc","group":"alsvc","level":"write"}]';
BEGIN
    -- ---------------------------------------------------------------- fixture
    PERFORM pg_temp.ok('service_register', '{"actor":"al-test","service":"alsvc","displayName":"Work"}', 'register alsvc');
    PERFORM pg_temp.ok('role_define', '{"actor":"al-test","service":"alsvc","group":"alsvc","level":"read"}', 'define alsvc:read');
    PERFORM pg_temp.ok('role_define', '{"actor":"al-test","service":"alsvc","group":"alsvc","level":"write"}', 'define alsvc:write');

    -- Two tenants, each opened by the operator with its administrator.
    v := pg_temp.ok('tenant_open', jsonb_build_object('actor', 'op:test', 'name', 'Access A',
        'administrator', jsonb_build_object('subjectKey', v_s[1], 'displayName', 'Anna Ozola')), 'open A');
    v_ta := v->'tenant'->>'id';
    v_anna := v->'administrator'->>'id';
    v := pg_temp.ok('tenant_open', jsonb_build_object('actor', 'op:test', 'name', 'Access B',
        'administrator', jsonb_build_object('subjectKey', v_s[2], 'displayName', 'Bēla Liepa')), 'open B');
    v_tb := v->'tenant'->>'id';
    v_bela := v->'administrator'->>'id';

    -- Mārtiņš reads in A and writes in B: one person, two tenants, two rows.
    v_martins := pg_temp.ok('user_invite', jsonb_build_object('actor', v_s[1], 'tenantId', v_ta, 'subjectKey', v_s[3],
        'displayName', 'Mārtiņš Kalns', 'roles', '[{"service":"alsvc","group":"alsvc","level":"read"}]'::jsonb), 'invite Mārtiņš to A')->>'id';
    v_martinsb := pg_temp.ok('user_invite', jsonb_build_object('actor', v_s[2], 'tenantId', v_tb, 'subjectKey', v_s[3],
        'displayName', 'Mārtiņš Kalns', 'roles', '[{"service":"alsvc","group":"alsvc","level":"write"}]'::jsonb), 'invite Mārtiņš to B')->>'id';
    -- Ilze is invited and has never signed in.
    v_ilze := pg_temp.ok('user_invite', jsonb_build_object('actor', v_s[1], 'tenantId', v_ta, 'subjectKey', v_s[4],
        'displayName', 'Ilze Krūmiņa'), 'invite Ilze')->>'id';
    -- Jānis was invited with nothing and has signed in.
    v_janis := pg_temp.ok('user_invite', jsonb_build_object('actor', v_s[1], 'tenantId', v_ta, 'subjectKey', v_s[5],
        'displayName', 'Jānis Bērziņš'), 'invite Jānis')->>'id';
    -- Laura holds two tenant roles; Pēteris held one and had it taken away.
    v_laura := pg_temp.ok('user_invite', jsonb_build_object('actor', v_s[1], 'tenantId', v_ta, 'subjectKey', v_s[7],
        'displayName', 'Laura Kalniņa'), 'invite Laura')->>'id';
    v_peteris := pg_temp.ok('user_invite', jsonb_build_object('actor', v_s[1], 'tenantId', v_ta, 'subjectKey', v_s[8],
        'displayName', 'Pēteris Ozols'), 'invite Pēteris')->>'id';
    -- Toms wrote in A until his access there ended.
    v_toms := pg_temp.ok('user_invite', jsonb_build_object('actor', v_s[1], 'tenantId', v_ta, 'subjectKey', v_s[9],
        'displayName', 'Toms Egle', 'roles', '[{"service":"alsvc","group":"alsvc","level":"write"}]'::jsonb), 'invite Toms')->>'id';
    -- A machine member of A, holding nothing.
    v_machine := pg_temp.ok('user_invite', jsonb_build_object('actor', 'op:test', 'tenantId', v_ta, 'subjectKey', v_svc,
        'displayName', 'Dokumentu serviss'), 'invite the machine')->>'id';

    FOREACH v_key IN ARRAY ARRAY[v_s[1], v_s[2], v_s[3], v_s[5], v_s[7], v_s[8], v_s[9], v_svc] LOOP
        PERFORM pg_temp.ok('claim_attach', jsonb_build_object('actor', 'idp:test', 'subjectKey', v_key), 'claim ' || v_key);
    END LOOP;

    -- Kārlis arrives through A's directory: active, holding nothing.
    PERFORM pg_temp.ok('directory_attach', jsonb_build_object('actor', v_s[1], 'tenantId', v_ta, 'issuer', v_iss), 'attach A''s directory');
    v := pg_temp.ok('directory_admit', jsonb_build_object('actor', 'idp:test', 'subjectKey', v_s[6], 'issuer', v_iss,
        'displayName', 'Kārlis Liepa'), 'admit Kārlis');
    v_karlis := v->'admitted'->0->>'userId';

    v_meistars := pg_temp.ok('tenant_role_define', jsonb_build_object('actor', v_s[1], 'tenantId', v_ta, 'name', 'Meistars'), 'define Meistars')->>'id';
    v_brig := pg_temp.ok('tenant_role_define', jsonb_build_object('actor', v_s[1], 'tenantId', v_ta, 'name', 'Brigadieris'), 'define Brigadieris')->>'id';
    PERFORM pg_temp.ok('tenant_role_grant', jsonb_build_object('actor', v_s[1], 'tenantId', v_ta, 'userId', v_laura, 'roleId', v_meistars), 'Laura Meistars');
    PERFORM pg_temp.ok('tenant_role_grant', jsonb_build_object('actor', v_s[1], 'tenantId', v_ta, 'userId', v_laura, 'roleId', v_brig), 'Laura Brigadieris');
    PERFORM pg_temp.ok('tenant_role_grant', jsonb_build_object('actor', v_s[1], 'tenantId', v_ta, 'userId', v_peteris, 'roleId', v_meistars), 'Pēteris Meistars');
    PERFORM pg_temp.ok('tenant_role_revoke', jsonb_build_object('actor', v_s[1], 'tenantId', v_ta, 'userId', v_peteris, 'roleId', v_meistars), 'Pēteris loses Meistars');
    PERFORM pg_temp.ok('user_revoke', jsonb_build_object('actor', v_s[1], 'tenantId', v_ta, 'userId', v_toms), 'revoke Toms');

    -- ------------------------------------------ (1) every member of A, in name order
    v_list := pg_temp.access(v_ta);
    IF pg_temp.ids(v_list) IS DISTINCT FROM
       ARRAY[v_anna, v_machine, v_ilze, v_janis, v_karlis, v_laura, v_martins, v_peteris, v_toms] THEN
        RAISE EXCEPTION 'A must list its nine members, and only them, in name order: %', v_list;
    END IF;
    IF v_martinsb = ANY (pg_temp.ids(v_list)) OR v_bela = ANY (pg_temp.ids(v_list)) THEN
        RAISE EXCEPTION 'A''s list must hold nobody of B: %', v_list;
    END IF;

    -- ------------------------------ (2) the administrator: the checkbox, not a row
    v_row := pg_temp.member(v_list, v_anna);
    PERFORM pg_temp.says(v_row, 'subjectKey', to_jsonb(v_s[1]), 'Anna');
    PERFORM pg_temp.says(v_row, 'displayName', '"Anna Ozola"', 'Anna');
    PERFORM pg_temp.says(v_row, 'kind', '"person"', 'Anna');
    PERFORM pg_temp.says(v_row, 'status', '"active"', 'Anna');
    PERFORM pg_temp.says(v_row, 'administrator', 'true', 'the administrator');
    PERFORM pg_temp.says(v_row, 'serviceRoles', NONE, 'the checkbox is not also a service role');
    PERFORM pg_temp.says(v_row, 'tenantRoles', NONE, 'Anna');
    PERFORM pg_temp.says(v_row, 'arrival', 'false', 'an administrator is no arrival');

    -- ------------------------------------- (3) a service role, this tenant's only
    v_row := pg_temp.member(v_list, v_martins);
    PERFORM pg_temp.says(v_row, 'serviceRoles', READS, 'Mārtiņš holds A''s grant, never B''s');
    PERFORM pg_temp.says(v_row, 'administrator', 'false', 'Mārtiņš');
    PERFORM pg_temp.says(v_row, 'arrival', 'false', 'a person with a service role is no arrival');

    -- ------------------------------------------ (4) invited, never signed in
    v_row := pg_temp.member(v_list, v_ilze);
    PERFORM pg_temp.says(v_row, 'status', '"invited"', 'Ilze');
    PERFORM pg_temp.says(v_row, 'arrival', 'false', 'an invitation not yet taken up is no arrival');

    -- ------------------------------ (5) the arrivals: signed in, holding nothing
    PERFORM pg_temp.says(pg_temp.member(v_list, v_janis), 'arrival', 'true', 'Jānis signed in to nothing');
    v_row := pg_temp.member(v_list, v_karlis);
    PERFORM pg_temp.says(v_row, 'status', '"active"', 'Kārlis');
    PERFORM pg_temp.says(v_row, 'arrival', 'true', 'Kārlis came through the directory to nothing');
    PERFORM pg_temp.says(pg_temp.member(v_list, v_peteris), 'arrival', 'true', 'Pēteris holds nothing again');
    PERFORM pg_temp.says(pg_temp.member(v_list, v_peteris), 'tenantRoles', NONE, 'a revoked tenant role is gone');
    IF (SELECT array_agg(m->>'id' ORDER BY m->>'id') FROM jsonb_array_elements(v_list) m WHERE (m->>'arrival')::boolean)
       IS DISTINCT FROM (SELECT array_agg(x ORDER BY x) FROM unnest(ARRAY[v_janis, v_karlis, v_peteris]) x) THEN
        RAISE EXCEPTION 'A''s arrivals must be exactly Jānis, Kārlis and Pēteris: %', v_list;
    END IF;

    -- ----------------------------------------- (6) tenant roles, by name
    v_row := pg_temp.member(v_list, v_laura);
    PERFORM pg_temp.says(v_row, 'tenantRoles', jsonb_build_array(
        jsonb_build_object('id', v_brig, 'name', 'Brigadieris'),
        jsonb_build_object('id', v_meistars, 'name', 'Meistars')), 'Laura''s two roles, by name');
    PERFORM pg_temp.says(v_row, 'serviceRoles', NONE, 'Laura');
    PERFORM pg_temp.says(v_row, 'arrival', 'false', 'a person with a tenant role is no arrival');

    -- ------------------------- (7) a revoked member stays, with their grants on record
    v_row := pg_temp.member(v_list, v_toms);
    PERFORM pg_temp.says(v_row, 'status', '"revoked"', 'Toms');
    PERFORM pg_temp.says(v_row, 'serviceRoles', WRITES, 'Toms''s grant stays on record');
    PERFORM pg_temp.says(v_row, 'arrival', 'false', 'a revoked member is no arrival');

    -- --------------------------------------- (8) a service account, marked
    v_row := pg_temp.member(v_list, v_machine);
    PERFORM pg_temp.says(v_row, 'kind', '"service"', 'the machine');
    PERFORM pg_temp.says(v_row, 'subjectKey', to_jsonb(v_svc), 'the machine');
    PERFORM pg_temp.says(v_row, 'status', '"active"', 'the machine');
    PERFORM pg_temp.says(v_row, 'arrival', 'false', 'a service account is never an arrival');

    -- ------------------------------- (9) B lists its own, and its own grants
    v_list := pg_temp.access(v_tb);
    IF pg_temp.ids(v_list) IS DISTINCT FROM ARRAY[v_bela, v_martinsb] THEN
        RAISE EXCEPTION 'B must list exactly Bēla and its own Mārtiņš: %', v_list;
    END IF;
    PERFORM pg_temp.says(pg_temp.member(v_list, v_bela), 'administrator', 'true', 'B''s administrator');
    PERFORM pg_temp.says(pg_temp.member(v_list, v_martinsb), 'serviceRoles', WRITES, 'Mārtiņš holds B''s grant in B');

    --      Mārtiņš becomes B's second administrator, then his access in B ends: the
    --      tick stays on record like any grant, and his status says it reaches nothing.
    PERFORM pg_temp.ok('role_grant', jsonb_build_object('actor', v_s[2], 'tenantId', v_tb, 'userId', v_martinsb,
        'service', 'rolebyte', 'group', 'membership', 'level', 'admin'), 'tick Mārtiņš in B');
    PERFORM pg_temp.ok('user_revoke', jsonb_build_object('actor', v_s[2], 'tenantId', v_tb, 'userId', v_martinsb), 'revoke Mārtiņš in B');
    v_row := pg_temp.member(pg_temp.access(v_tb), v_martinsb);
    PERFORM pg_temp.says(v_row, 'status', '"revoked"', 'Mārtiņš in B');
    PERFORM pg_temp.says(v_row, 'administrator', 'true', 'a revoked administrator''s tick stays on record');
    PERFORM pg_temp.says(v_row, 'serviceRoles', WRITES, 'Mārtiņš in B');
    PERFORM pg_temp.says(pg_temp.member(pg_temp.access(v_ta), v_martins), 'status', '"active"',
        'ending Mārtiņš''s access in B leaves A untouched');

    -- ------------------------ (10) a renamed role is read by its new name, same id
    PERFORM pg_temp.ok('tenant_role_update', jsonb_build_object('actor', v_s[1], 'tenantId', v_ta, 'roleId', v_meistars,
        'name', 'Vecākais meistars'), 'rename Meistars');
    PERFORM pg_temp.says(pg_temp.member(pg_temp.access(v_ta), v_laura), 'tenantRoles', jsonb_build_array(
        jsonb_build_object('id', v_brig, 'name', 'Brigadieris'),
        jsonb_build_object('id', v_meistars, 'name', 'Vecākais meistars')), 'the renamed role');

    -- --------------- (11) the checkbox moves: ticked on Laura, unticked on Anna
    PERFORM pg_temp.ok('role_grant', jsonb_build_object('actor', v_s[1], 'tenantId', v_ta, 'userId', v_laura,
        'service', 'rolebyte', 'group', 'membership', 'level', 'admin'), 'tick Laura');
    PERFORM pg_temp.ok('role_revoke', jsonb_build_object('actor', v_s[7], 'tenantId', v_ta, 'userId', v_anna,
        'service', 'rolebyte', 'group', 'membership', 'level', 'admin'), 'untick Anna');
    v_list := pg_temp.access(v_ta);
    v_row := pg_temp.member(v_list, v_laura);
    PERFORM pg_temp.says(v_row, 'administrator', 'true', 'Laura ticked');
    PERFORM pg_temp.says(v_row, 'serviceRoles', NONE, 'the ticked checkbox is not also a service role');
    v_row := pg_temp.member(v_list, v_anna);
    PERFORM pg_temp.says(v_row, 'administrator', 'false', 'Anna unticked');
    PERFORM pg_temp.says(v_row, 'arrival', 'true', 'Anna now holds nothing');

    -- ------------------------------------------------------- (12) refusals
    v_before := pg_temp.state();
    v := pg_temp.rb('access_list', '{}');
    IF v->>'result' IS DISTINCT FROM 'error' OR v->>'code' IS DISTINCT FROM 'membership:invalid'
       OR v->>'message' IS DISTINCT FROM 'tenantId is required' THEN
        RAISE EXCEPTION 'a missing tenant must be refused as invalid: %', v;
    END IF;
    v := pg_temp.rb('access_list', '{"tenantId":"   "}');
    IF v->>'code' IS DISTINCT FROM 'membership:invalid' THEN
        RAISE EXCEPTION 'a blank tenant must be refused as invalid: %', v;
    END IF;
    v := pg_temp.rb('access_list', jsonb_build_object('tenantId', util.generate_ulid()));
    IF v->>'result' IS DISTINCT FROM 'error' OR v->>'code' IS DISTINCT FROM 'tenant:not_found' THEN
        RAISE EXCEPTION 'an unknown tenant must be refused as not found: %', v;
    END IF;
    IF pg_temp.state() IS DISTINCT FROM v_before THEN
        RAISE EXCEPTION 'a refused read changed something';
    END IF;

    -- ------------------------------------ (13) the register's own role runs it
    IF NOT has_function_privilege('rolebyte_public', 'rolebyte.access_list(jsonb, jsonb)', 'EXECUTE') THEN
        RAISE EXCEPTION 'the register''s own role must be able to read who holds what';
    END IF;
    IF has_function_privilege('public', 'rolebyte.access_list(jsonb, jsonb)', 'EXECUTE') THEN
        RAISE EXCEPTION 'nobody but the register''s own role may read who holds what';
    END IF;

    RAISE NOTICE 'unit.rolebyte_access_list: all assertions passed';
END $$;

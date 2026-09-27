-- Unit test: the tenant's administrator. No role can be given a permission that
-- changes the tenant's own setup, and one stored before that rule reaches no
-- token and no placement; a tenant never loses its last administrator, by any
-- door, while a second administrator makes each removal possible; an
-- administrator resolves every permission the tenant has, a later one included,
-- and nothing of what it does not have; where nothing is declared an
-- administrator resolves exactly as before; the operator opens a tenant with its
-- administrator, adds and removes one, and sees every tenant; and the seed from
-- the environment acts once per value and never removes anyone.
--   psql -v ON_ERROR_STOP=1 -f migrations/testing/tests/unit.rolebyte_administrator.sql

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

-- Everything a refused call must leave as it was.
CREATE OR REPLACE FUNCTION pg_temp.state() RETURNS text
LANGUAGE sql AS $$
    SELECT concat_ws('/',
        (SELECT count(*) FROM rolebyte.tenant),
        (SELECT string_agg(id || status, ',' ORDER BY id) FROM rolebyte.user_account),
        (SELECT string_agg(id || state, ',' ORDER BY id) FROM rolebyte.assignment),
        (SELECT count(*) FROM rolebyte.tenant_role_permission),
        (SELECT string_agg(tenant_id || subject_key, ',' ORDER BY tenant_id) FROM rolebyte.administrator_seed),
        (SELECT count(*) FROM rolebyte.event));
$$;

-- The call must be refused with this code, say this, and change nothing.
CREATE OR REPLACE FUNCTION pg_temp.refused(p_proc text, p_in jsonb, p_code text, p_says text, p_why text) RETURNS void
LANGUAGE plpgsql AS $$
DECLARE
    v      jsonb;
    before text := pg_temp.state();
BEGIN
    v := pg_temp.rb(p_proc, p_in);
    IF v->>'result' IS DISTINCT FROM 'error' OR v->>'code' IS DISTINCT FROM p_code THEN
        RAISE EXCEPTION '% should be refused %: %', p_why, p_code, v;
    END IF;
    IF p_says IS NOT NULL AND v->>'message' IS DISTINCT FROM p_says THEN
        RAISE EXCEPTION '% must say "%", said "%"', p_why, p_says, v->>'message';
    END IF;
    IF pg_temp.state() IS DISTINCT FROM before THEN
        RAISE EXCEPTION '% was refused but changed something', p_why;
    END IF;
END $$;

CREATE OR REPLACE FUNCTION pg_temp.resolved(p_subject text) RETURNS jsonb
LANGUAGE plpgsql AS $$
DECLARE
    v jsonb;
BEGIN
    CALL rolebyte.resolve(jsonb_build_object('subjectKey', p_subject), v);
    RETURN v;
END $$;

-- What the register answered before a tenant role could reach a token, kept as
-- the reference the byte-identity is measured against. Never edited to follow
-- the procedure.
CREATE OR REPLACE FUNCTION pg_temp.resolved_before_tenant_roles(p_subject text) RETURNS jsonb
LANGUAGE plpgsql AS $$
DECLARE
    v_memberships jsonb;
BEGIN
    SELECT COALESCE(jsonb_agg(m ORDER BY m->>'tenantId'), '[]'::jsonb)
    INTO v_memberships
    FROM (
        SELECT jsonb_build_object(
            'tenantId',    u.tenant_id,
            'userId',      u.id,
            'displayName', u.display_name,
            'scopes',      COALESCE((
                SELECT jsonb_agg(DISTINCT rd.role_group || ':' || rd.role_level)
                FROM rolebyte.assignment a
                JOIN rolebyte.role_definition rd ON rd.id = a.role_definition_id
                WHERE a.user_id = u.id AND a.state = 'granted'
            ), '[]'::jsonb)
        ) AS m
        FROM rolebyte.user_account u
        JOIN rolebyte.tenant t ON t.id = u.tenant_id
        WHERE u.subject_key = NULLIF(trim(p_subject), '')
          AND u.status = 'active'
          AND t.status = 'active'
    ) sub;
    RETURN util.result_success(jsonb_build_object('memberships', v_memberships));
END $$;

-- The scope list of the subject's membership in a tenant, sorted.
CREATE OR REPLACE FUNCTION pg_temp.scopes(p_subject text, p_tenant text) RETURNS text[]
LANGUAGE plpgsql AS $$
DECLARE
    v jsonb;
BEGIN
    SELECT m->'scopes' INTO v
      FROM jsonb_array_elements(pg_temp.resolved(p_subject)->'data'->'memberships') m
     WHERE m->>'tenantId' = p_tenant;
    IF v IS NULL THEN
        RAISE EXCEPTION 'no membership of % answered in %', p_subject, p_tenant;
    END IF;
    RETURN (SELECT COALESCE(array_agg(x ORDER BY x), '{}') FROM jsonb_array_elements_text(v) x);
END $$;

CREATE OR REPLACE FUNCTION pg_temp.holds_exactly(p_got text[], p_expected text[], p_why text) RETURNS void
LANGUAGE plpgsql AS $$
BEGIN
    IF p_got IS DISTINCT FROM (SELECT COALESCE(array_agg(x ORDER BY x), '{}') FROM unnest(p_expected) x) THEN
        RAISE EXCEPTION '%: expected exactly %, got %', p_why, p_expected, p_got;
    END IF;
END $$;

CREATE OR REPLACE FUNCTION pg_temp.events(p_tenant text, p_kind text) RETURNS bigint
LANGUAGE sql AS $$
    SELECT count(*) FROM rolebyte.event WHERE tenant_id = p_tenant AND kind = p_kind;
$$;

DO $$
DECLARE
    v_s       text[] := ARRAY(SELECT 'sub:' || util.generate_ulid() FROM generate_series(1, 9));
    v_ta      text;
    v_tb      text;
    v_anna    text;
    v_bela    text;
    v_martins text;
    v_karlis  text;
    v_ilze    text;
    v_toms    text;
    v_role    text;
    v_full    text[];
    v         jsonb;
    ANNA_LAST CONSTANT text := 'Anna Ozola is this tenant''s last administrator; make someone else an administrator first';
BEGIN
    -- adsvc declares an ordinary box and one of each setup class; adpeople one
    -- ordinary box; adbare registers a role and declares nothing, like a
    -- deployment where no service declares permissions.
    PERFORM pg_temp.ok('service_register', '{"actor":"adm-test","service":"adsvc","displayName":"Work"}', 'register adsvc');
    PERFORM pg_temp.ok('service_register', '{"actor":"adm-test","service":"adpeople","displayName":"People"}', 'register adpeople');
    PERFORM pg_temp.ok('service_register', '{"actor":"adm-test","service":"adbare","displayName":"Bare"}', 'register adbare');
    PERFORM pg_temp.ok('role_define', '{"actor":"adm-test","service":"adsvc","group":"adsvc","level":"read"}', 'define adsvc:read');
    PERFORM pg_temp.ok('permission_declare', '{"actor":"adm-test","service":"adsvc","permission":{"feature":"task","act":"view","class":"ordinary"}}', 'declare task:view');
    PERFORM pg_temp.ok('permission_declare', '{"actor":"adm-test","service":"adsvc","permission":{"feature":"setup","act":"edit","class":"tenantConfiguration"}}', 'declare setup:edit');
    PERFORM pg_temp.ok('permission_declare', '{"actor":"adm-test","service":"adsvc","permission":{"feature":"access","act":"assign","class":"roleManagement"}}', 'declare access:assign');
    PERFORM pg_temp.ok('permission_declare', '{"actor":"adm-test","service":"adpeople","permission":{"feature":"person","act":"view","class":"ordinary"}}', 'declare person:view');

    -- 6. The operator opens two tenants, each with its first administrator.
    v := pg_temp.ok('tenant_open', jsonb_build_object('actor', 'op:test', 'name', 'Administrator A',
        'administrator', jsonb_build_object('subjectKey', v_s[1], 'displayName', 'Anna Ozola')), 'open A');
    v_ta := v->'tenant'->>'id';
    v_anna := v->'administrator'->>'id';
    IF v->'administrator'->>'status' IS DISTINCT FROM 'invited' THEN
        RAISE EXCEPTION 'the first administrator must be invited until they sign in: %', v;
    END IF;
    IF NOT rolebyte.is_administrator(v_anna) THEN
        RAISE EXCEPTION 'an invited first administrator must already count as one';
    END IF;
    v := pg_temp.ok('tenant_open', jsonb_build_object('actor', 'op:test', 'name', 'Administrator B',
        'administrator', jsonb_build_object('subjectKey', v_s[2], 'displayName', 'Bēla Liepa')), 'open B');
    v_tb := v->'tenant'->>'id';
    v_bela := v->'administrator'->>'id';
    FOR i IN 1..2 LOOP
        PERFORM pg_temp.ok('claim_attach', jsonb_build_object('actor', 'idp:test', 'subjectKey', v_s[i]), 'claim ' || i);
    END LOOP;
    IF pg_temp.events(v_ta, 'tenantCreated') <> 1 OR pg_temp.events(v_ta, 'userInvited') <> 1
       OR pg_temp.events(v_ta, 'roleGranted') <> 1 OR pg_temp.events(v_ta, 'administratorSetByOperator') <> 1
       OR (SELECT count(*) FROM rolebyte.event WHERE tenant_id = v_ta AND actor <> 'op:test' AND kind <> 'claimAttached') <> 0 THEN
        RAISE EXCEPTION 'opening a tenant must write its four events, each naming the operator';
    END IF;
    PERFORM pg_temp.refused('tenant_open', jsonb_build_object('actor', 'op:test', 'name', 'No one'),
        'membership:invalid', NULL, 'a tenant without an administrator');
    PERFORM pg_temp.refused('tenant_open', jsonb_build_object('actor', 'op:test', 'name', 'Bad key',
        'administrator', jsonb_build_object('subjectKey', 'pno:x', 'displayName', 'X')), 'membership:invalid', NULL, 'an untyped key');
    PERFORM pg_temp.refused('tenant_open', jsonb_build_object('actor', 'op:test', 'name', 'No name',
        'administrator', jsonb_build_object('subjectKey', v_s[9])), 'membership:invalid', NULL, 'an administrator with no name');
    PERFORM pg_temp.refused('tenant_open', jsonb_build_object('name', 'No actor',
        'administrator', jsonb_build_object('subjectKey', v_s[9], 'displayName', 'X')), 'tenant:invalid', NULL, 'no actor');

    -- A member of A with a service role and a tenant role.
    v_martins := pg_temp.ok('user_invite', jsonb_build_object('actor', v_s[1], 'tenantId', v_ta, 'subjectKey', v_s[3],
        'displayName', 'Mārtiņš Kalns', 'roles', '[{"service":"adsvc","group":"adsvc","level":"read"}]'::jsonb), 'invite Mārtiņš')->>'id';
    PERFORM pg_temp.ok('claim_attach', jsonb_build_object('actor', 'idp:test', 'subjectKey', v_s[3]), 'claim Mārtiņš');
    v_role := pg_temp.ok('tenant_role_define', jsonb_build_object('actor', v_s[1], 'tenantId', v_ta, 'name', 'Meistars'), 'define role')->>'id';
    PERFORM pg_temp.ok('tenant_role_grant', jsonb_build_object('actor', v_s[1], 'tenantId', v_ta, 'userId', v_martins, 'roleId', v_role), 'grant role');

    -- 1. No role may carry a setup box, alone or beside an ordinary one, and the
    --    refusal says why.
    PERFORM pg_temp.refused('tenant_role_permissions_set', jsonb_build_object('actor', v_s[1], 'tenantId', v_ta, 'roleId', v_role,
        'permissions', '["adsvc/setup:edit"]'::jsonb), 'membership:invalid',
        'adsvc/setup:edit changes the tenant''s own setup; only the Administrator checkbox holds it', 'a tenantConfiguration tick');
    PERFORM pg_temp.refused('tenant_role_permissions_set', jsonb_build_object('actor', v_s[1], 'tenantId', v_ta, 'roleId', v_role,
        'permissions', '["adsvc/task:view", "adsvc/access:assign"]'::jsonb), 'membership:invalid',
        'adsvc/access:assign changes the tenant''s own setup; only the Administrator checkbox holds it', 'a roleManagement tick beside an ordinary one');
    PERFORM pg_temp.ok('tenant_role_permissions_set', jsonb_build_object('actor', v_s[1], 'tenantId', v_ta, 'roleId', v_role,
        'permissions', '["adsvc/task:view"]'::jsonb), 'an ordinary tick');

    --    A setup tick stored before the rule reaches neither a token nor a placement.
    INSERT INTO rolebyte.tenant_role_permission (tenant_role_id, permission_id)
    SELECT v_role, id FROM rolebyte.service_permission WHERE service_key = 'adsvc' AND feature_key = 'setup';
    PERFORM pg_temp.ok('entitlement_grant', jsonb_build_object('actor', 'op:test', 'tenantId', v_ta, 'service', 'adsvc'), 'entitle A adsvc');
    PERFORM pg_temp.holds_exactly(pg_temp.scopes(v_s[3], v_ta), ARRAY['adsvc:read', 'adsvc/task:view'],
        'a stored setup tick must not reach a token');
    v := pg_temp.ok('tenant_role_definitions', jsonb_build_object('tenantId', v_ta), 'definitions of A');
    IF (SELECT r->'permissions' FROM jsonb_array_elements(v->'roles') r WHERE r->>'id' = v_role)
       IS DISTINCT FROM '["adsvc/task:view"]'::jsonb THEN
        RAISE EXCEPTION 'a stored setup tick must not reach a placement: %', v;
    END IF;

    -- 2. The last administrator cannot be unticked, revoked or unset, and the
    --    refusal names them. An invited administrator is protected as well.
    PERFORM pg_temp.refused('role_revoke', jsonb_build_object('actor', v_s[1], 'tenantId', v_ta, 'userId', v_anna,
        'service', 'rolebyte', 'group', 'membership', 'level', 'admin'), 'membership:conflict', ANNA_LAST, 'unticking the last administrator');
    PERFORM pg_temp.refused('user_revoke', jsonb_build_object('actor', v_s[1], 'tenantId', v_ta, 'userId', v_anna),
        'membership:conflict', ANNA_LAST, 'revoking the last administrator');
    PERFORM pg_temp.refused('administrator_unset', jsonb_build_object('actor', 'op:test', 'tenantId', v_ta, 'userId', v_anna),
        'membership:conflict', ANNA_LAST, 'the operator unsetting the last administrator');
    v := pg_temp.ok('tenant_open', jsonb_build_object('actor', 'op:test', 'name', 'Administrator C',
        'administrator', jsonb_build_object('subjectKey', v_s[9], 'displayName', 'Jānis Bērziņš')), 'open C');
    PERFORM pg_temp.refused('user_revoke', jsonb_build_object('actor', 'op:test', 'tenantId', v->'tenant'->>'id',
        'userId', v->'administrator'->>'id'), 'membership:conflict', NULL, 'revoking an invited last administrator');
    --    Another tenant's administrator, named under this tenant, is not found here.
    PERFORM pg_temp.refused('user_revoke', jsonb_build_object('actor', v_s[1], 'tenantId', v_ta, 'userId', v_bela),
        'membership:not_found', NULL, 'another tenant''s administrator');
    PERFORM pg_temp.refused('administrator_unset', jsonb_build_object('actor', 'op:test', 'tenantId', v_ta, 'userId', v_bela),
        'membership:not_found', NULL, 'the operator naming another tenant''s administrator');

    -- 6. The operator adds a second administrator while the first is active:
    --    someone not yet a member is added, invited, holding the rung.
    v := pg_temp.ok('administrator_set', jsonb_build_object('actor', 'op:test', 'tenantId', v_ta,
        'subjectKey', v_s[4], 'displayName', 'Kārlis Egle'), 'set Kārlis');
    v_karlis := v->>'userId';
    IF (v->>'invited')::boolean IS NOT TRUE OR (v->>'changed')::boolean IS NOT TRUE THEN
        RAISE EXCEPTION 'a new administrator must be invited and change something: %', v;
    END IF;
    v := pg_temp.ok('administrator_set', jsonb_build_object('actor', 'op:test', 'tenantId', v_ta, 'subjectKey', v_s[4]), 'set Kārlis again');
    IF (v->>'changed')::boolean IS NOT FALSE THEN RAISE EXCEPTION 'setting an administrator twice must not change: %', v; END IF;
    IF pg_temp.events(v_ta, 'administratorSetByOperator') <> 2 THEN
        RAISE EXCEPTION 'expected 2 operator set events in A, found %', pg_temp.events(v_ta, 'administratorSetByOperator');
    END IF;
    PERFORM pg_temp.refused('administrator_set', jsonb_build_object('actor', 'op:test', 'tenantId', v_ta, 'subjectKey', v_s[5]),
        'membership:invalid', 'displayName is required to add someone who is not yet a member of the tenant', 'a non-member with no name');
    PERFORM pg_temp.refused('administrator_set', jsonb_build_object('actor', 'op:test', 'tenantId', 'nosuchtenant',
        'subjectKey', v_s[5], 'displayName', 'X'), 'tenant:not_found', NULL, 'an unknown tenant');
    PERFORM pg_temp.refused('administrator_set', jsonb_build_object('actor', 'op:test', 'tenantId', v_ta,
        'subjectKey', 'sub:not-a-person', 'displayName', 'X'), 'membership:invalid', NULL, 'a malformed key');

    --    With a second administrator each removal succeeds, and the first is back.
    PERFORM pg_temp.ok('role_revoke', jsonb_build_object('actor', v_s[4], 'tenantId', v_ta, 'userId', v_anna,
        'service', 'rolebyte', 'group', 'membership', 'level', 'admin'), 'untick Anna beside Kārlis');
    PERFORM pg_temp.ok('role_grant', jsonb_build_object('actor', v_s[4], 'tenantId', v_ta, 'userId', v_anna,
        'service', 'rolebyte', 'group', 'membership', 'level', 'admin'), 'tick Anna again');
    v := pg_temp.ok('administrator_unset', jsonb_build_object('actor', 'op:test', 'tenantId', v_ta, 'userId', v_karlis), 'unset Kārlis beside Anna');
    IF (v->>'changed')::boolean IS NOT TRUE THEN RAISE EXCEPTION 'unsetting an administrator must change: %', v; END IF;
    v := pg_temp.ok('administrator_unset', jsonb_build_object('actor', 'op:test', 'tenantId', v_ta, 'userId', v_martins), 'unset a non-administrator');
    IF (v->>'changed')::boolean IS NOT FALSE THEN RAISE EXCEPTION 'unsetting a non-administrator must not change: %', v; END IF;
    IF pg_temp.events(v_ta, 'administratorUnsetByOperator') <> 1 THEN
        RAISE EXCEPTION 'expected 1 operator unset event in A, found %', pg_temp.events(v_ta, 'administratorUnsetByOperator');
    END IF;
    PERFORM pg_temp.ok('administrator_set', jsonb_build_object('actor', 'op:test', 'tenantId', v_ta, 'subjectKey', v_s[4]), 'set Kārlis back');
    PERFORM pg_temp.ok('user_revoke', jsonb_build_object('actor', v_s[1], 'tenantId', v_ta, 'userId', v_karlis), 'revoke Kārlis beside Anna');
    PERFORM pg_temp.refused('user_revoke', jsonb_build_object('actor', v_s[1], 'tenantId', v_ta, 'userId', v_anna),
        'membership:conflict', ANNA_LAST, 'Anna is the last one again');
    --    A revoked person cannot be made an administrator: nothing gives access back.
    PERFORM pg_temp.refused('administrator_set', jsonb_build_object('actor', 'op:test', 'tenantId', v_ta, 'subjectKey', v_s[4]),
        'membership:conflict', 'Kārlis Egle no longer has access to this tenant, so cannot be made its administrator', 'a revoked person');

    -- 4. An administrator resolves every box of every entitled service, the setup
    --    ones included, and nothing of a service the tenant does not have.
    PERFORM pg_temp.holds_exactly(pg_temp.scopes(v_s[1], v_ta),
        ARRAY['membership:admin', 'adsvc/task:view', 'adsvc/setup:edit', 'adsvc/access:assign'], 'Anna, adsvc entitled');
    --    A box declared later reaches her with no write.
    PERFORM pg_temp.ok('permission_declare', '{"actor":"adm-test","service":"adsvc","permission":{"feature":"report","act":"export","class":"ordinary"}}', 'declare report:export');
    PERFORM pg_temp.ok('entitlement_grant', jsonb_build_object('actor', 'op:test', 'tenantId', v_ta, 'service', 'adpeople'), 'entitle A adpeople');
    v_full := pg_temp.scopes(v_s[1], v_ta);
    PERFORM pg_temp.holds_exactly(v_full, ARRAY['membership:admin', 'adsvc/task:view', 'adsvc/setup:edit',
        'adsvc/access:assign', 'adsvc/report:export', 'adpeople/person:view'], 'Anna after a later box and a second service');
    --    Revoking and entitling again round-trips; a member keeps only their ticks.
    PERFORM pg_temp.ok('entitlement_revoke', jsonb_build_object('actor', 'op:test', 'tenantId', v_ta, 'service', 'adsvc'), 'revoke A adsvc');
    PERFORM pg_temp.holds_exactly(pg_temp.scopes(v_s[1], v_ta), ARRAY['membership:admin', 'adpeople/person:view'], 'Anna without adsvc');
    PERFORM pg_temp.ok('entitlement_grant', jsonb_build_object('actor', 'op:test', 'tenantId', v_ta, 'service', 'adsvc'), 're-entitle A adsvc');
    PERFORM pg_temp.holds_exactly(pg_temp.scopes(v_s[1], v_ta), v_full, 'revoke and re-entitle round-trips');
    PERFORM pg_temp.holds_exactly(pg_temp.scopes(v_s[3], v_ta), ARRAY['adsvc:read', 'adsvc/task:view'], 'Mārtiņš keeps only his ticks');

    -- 5. Where nothing is declared, an administrator resolves as before: B has
    --    only a service that declares no permission.
    PERFORM pg_temp.ok('entitlement_grant', jsonb_build_object('actor', 'op:test', 'tenantId', v_tb, 'service', 'adbare'), 'entitle B adbare');
    IF pg_temp.resolved(v_s[2])::text IS DISTINCT FROM pg_temp.resolved_before_tenant_roles(v_s[2])::text THEN
        RAISE EXCEPTION 'an administrator where nothing is declared must resolve as the reference: %', pg_temp.resolved(v_s[2]);
    END IF;
    --    And a person with only service roles, in a tenant with every box entitled.
    PERFORM pg_temp.ok('tenant_role_revoke', jsonb_build_object('actor', v_s[1], 'tenantId', v_ta, 'userId', v_martins, 'roleId', v_role), 'revoke the role');
    IF pg_temp.resolved(v_s[3])::text IS DISTINCT FROM pg_temp.resolved_before_tenant_roles(v_s[3])::text THEN
        RAISE EXCEPTION 'a service-only person must resolve as the reference: %', pg_temp.resolved(v_s[3]);
    END IF;

    -- 6. The operator's overview: each tenant with what it has and who holds the
    --    rung, revoked ones included, each with their account's state.
    v := pg_temp.ok('tenant_overview', '{}'::jsonb, 'overview');
    IF NOT (v->'tenants' @> jsonb_build_array(jsonb_build_object('id', v_ta, 'status', 'active',
            'entitlements', '[{"service":"adpeople","feature":""},{"service":"adsvc","feature":""}]'::jsonb))) THEN
        RAISE EXCEPTION 'the overview must show A with what it has: %', v;
    END IF;
    IF (SELECT array_agg((x->>'displayName') || ':' || (x->>'status') ORDER BY ord)
          FROM jsonb_array_elements((SELECT t->'administrators' FROM jsonb_array_elements(v->'tenants') t WHERE t->>'id' = v_ta))
               WITH ORDINALITY AS a(x, ord))
       IS DISTINCT FROM ARRAY['Anna Ozola:active', 'Kārlis Egle:revoked'] THEN
        RAISE EXCEPTION 'the overview must list A''s administrators with their state: %', v;
    END IF;

    -- 7. The seed: the service's own role runs it; the same value twice is one
    --    event; a new value makes a new administrator whatever the old one's
    --    state; nobody is removed; and each bad seed is refused with its reason.
    EXECUTE 'SET ROLE rolebyte_public';
    CALL rolebyte.administrator_seed(jsonb_build_object('actor', 'operator:seed', 'tenantId', v_tb,
        'subjectKey', v_s[6], 'displayName', 'Ilze Zariņa'), v);
    EXECUTE 'RESET ROLE';
    IF v->>'result' IS DISTINCT FROM 'success' OR (v->'data'->>'applied')::boolean IS NOT TRUE THEN
        RAISE EXCEPTION 'the service role must be able to seed: %', v;
    END IF;
    v_ilze := v->'data'->>'userId';
    v := pg_temp.ok('administrator_seed', jsonb_build_object('actor', 'operator:seed', 'tenantId', v_tb, 'subjectKey', v_s[6]), 'the same seed again');
    IF (v->>'applied')::boolean IS NOT FALSE THEN RAISE EXCEPTION 'the same seed must not apply twice: %', v; END IF;
    IF pg_temp.events(v_tb, 'administratorSeeded') <> 1
       OR (SELECT count(*) FROM rolebyte.event WHERE tenant_id = v_tb AND kind = 'administratorSeeded' AND actor = 'operator:seed') <> 1 THEN
        RAISE EXCEPTION 'the same value twice must write one seed event naming the seed';
    END IF;
    PERFORM pg_temp.ok('claim_attach', jsonb_build_object('actor', 'idp:test', 'subjectKey', v_s[6]), 'claim Ilze');
    PERFORM pg_temp.ok('user_revoke', jsonb_build_object('actor', v_s[6], 'tenantId', v_tb, 'userId', v_bela), 'Ilze revokes Bēla');
    v_toms := pg_temp.ok('user_invite', jsonb_build_object('actor', v_s[6], 'tenantId', v_tb, 'subjectKey', v_s[7],
        'displayName', 'Toms Vītols', 'roles', '[]'::jsonb), 'invite Toms')->>'id';
    v := pg_temp.ok('administrator_seed', jsonb_build_object('actor', 'operator:seed', 'tenantId', v_tb, 'subjectKey', v_s[7]), 'a new seed');
    IF (v->>'applied')::boolean IS NOT TRUE OR v->>'userId' IS DISTINCT FROM v_toms THEN
        RAISE EXCEPTION 'a new value must make its person an administrator: %', v;
    END IF;
    IF NOT rolebyte.is_administrator(v_toms) OR NOT rolebyte.is_administrator(v_ilze) THEN
        RAISE EXCEPTION 'a seed makes an administrator and removes nobody';
    END IF;
    IF pg_temp.events(v_tb, 'administratorSeeded') <> 2 THEN
        RAISE EXCEPTION 'expected 2 seed events in B, found %', pg_temp.events(v_tb, 'administratorSeeded');
    END IF;
    --    A seed whose person is already an administrator is remembered, and changes nothing else.
    v := pg_temp.ok('administrator_seed', jsonb_build_object('actor', 'operator:seed', 'tenantId', v_tb, 'subjectKey', v_s[6]), 'seed Ilze again after Toms');
    IF (v->>'applied')::boolean IS NOT TRUE OR (v->>'changed')::boolean IS NOT FALSE THEN
        RAISE EXCEPTION 'a new value naming an administrator is applied and changes nothing: %', v;
    END IF;
    PERFORM pg_temp.refused('administrator_seed', jsonb_build_object('actor', 'operator:seed', 'tenantId', 'nosuchtenant', 'subjectKey', v_s[8]),
        'tenant:not_found', 'tenant does not exist', 'an unknown tenant');
    PERFORM pg_temp.refused('administrator_seed', jsonb_build_object('actor', 'operator:seed', 'subjectKey', v_s[8]),
        'membership:invalid', NULL, 'no tenant named where the deployment has several');
    PERFORM pg_temp.refused('administrator_seed', jsonb_build_object('actor', 'operator:seed', 'tenantId', v_tb, 'subjectKey', 'sub:lower'),
        'membership:invalid', NULL, 'a malformed key');
    PERFORM pg_temp.refused('administrator_seed', jsonb_build_object('actor', 'operator:seed', 'tenantId', v_tb, 'subjectKey', v_s[8]),
        'membership:invalid', 'displayName is required to add someone who is not yet a member of the tenant', 'a non-member with no name');
    PERFORM pg_temp.refused('administrator_seed', jsonb_build_object('actor', 'operator:seed', 'tenantId', v_tb, 'subjectKey', v_s[2]),
        'membership:conflict', 'Bēla Liepa no longer has access to this tenant, so cannot be made its administrator', 'a revoked person');
    PERFORM pg_temp.refused('administrator_seed', jsonb_build_object('tenantId', v_tb, 'subjectKey', v_s[8]),
        'membership:invalid', NULL, 'no actor');

    RAISE NOTICE 'unit.rolebyte_administrator: all assertions passed';
END $$;

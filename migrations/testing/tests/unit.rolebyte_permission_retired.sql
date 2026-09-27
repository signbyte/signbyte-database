-- Unit test: a retired permission. A service retires a permission by declaring
-- it so, in a configuration document whose second apply changes nothing. A role
-- that already ticks it keeps it, the tick still reaches that person's token,
-- and the role may be set again with it; no role can be given it anew, and a role
-- that dropped it cannot take it back. The Administrator checkbox no longer
-- hands it out. Declaring it without the retired mark brings it back for
-- everyone.
--   psql -v ON_ERROR_STOP=1 -f migrations/testing/tests/unit.rolebyte_permission_retired.sql

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

-- The call must be refused with this code and message, and change no tick.
CREATE OR REPLACE FUNCTION pg_temp.refused(p_proc text, p_in jsonb, p_code text, p_says text, p_why text) RETURNS void
LANGUAGE plpgsql AS $$
DECLARE
    v      jsonb;
    before bigint := (SELECT count(*) FROM rolebyte.tenant_role_permission);
BEGIN
    v := pg_temp.rb(p_proc, p_in);
    IF v->>'result' IS DISTINCT FROM 'error' OR v->>'code' IS DISTINCT FROM p_code THEN
        RAISE EXCEPTION '% should be refused %: %', p_why, p_code, v;
    END IF;
    IF v->>'message' IS DISTINCT FROM p_says THEN
        RAISE EXCEPTION '% must say "%", said "%"', p_why, p_says, v->>'message';
    END IF;
    IF (SELECT count(*) FROM rolebyte.tenant_role_permission) <> before THEN
        RAISE EXCEPTION '% was refused but changed a tick', p_why;
    END IF;
END $$;

-- The scope list of the subject's membership in a tenant, sorted.
CREATE OR REPLACE FUNCTION pg_temp.scopes(p_subject text, p_tenant text) RETURNS text[]
LANGUAGE plpgsql AS $$
DECLARE
    v   jsonb;
    out jsonb;
BEGIN
    CALL rolebyte.resolve(jsonb_build_object('subjectKey', p_subject), v);
    SELECT m->'scopes' INTO out
      FROM jsonb_array_elements(v->'data'->'memberships') m
     WHERE m->>'tenantId' = p_tenant;
    IF out IS NULL THEN
        RAISE EXCEPTION 'no membership of % answered in %', p_subject, p_tenant;
    END IF;
    RETURN (SELECT COALESCE(array_agg(x ORDER BY x), '{}') FROM jsonb_array_elements_text(out) x);
END $$;

CREATE OR REPLACE FUNCTION pg_temp.holds_exactly(p_got text[], p_expected text[], p_why text) RETURNS void
LANGUAGE plpgsql AS $$
BEGIN
    IF p_got IS DISTINCT FROM (SELECT COALESCE(array_agg(x ORDER BY x), '{}') FROM unnest(p_expected) x) THEN
        RAISE EXCEPTION '%: expected exactly %, got %', p_why, p_expected, p_got;
    END IF;
END $$;

DO $$
DECLARE
    v_s      text[] := ARRAY(SELECT 'sub:' || util.generate_ulid() FROM generate_series(1, 2));
    v_tenant text;
    v_toms   text;
    v_worker text;
    v_other  text;
    v_doc    jsonb;
    v        jsonb;
    RETIRED  CONSTANT text := 'rtsvc/task:edit is retired: a role that holds it keeps it, and no role can be given it again';
BEGIN
    PERFORM pg_temp.ok('service_register', '{"actor":"retired-test","service":"rtsvc","displayName":"Work"}', 'register rtsvc');
    PERFORM pg_temp.ok('permission_declare', '{"actor":"retired-test","service":"rtsvc","permission":{"feature":"task","act":"view","class":"ordinary","plane":"object"}}', 'declare task:view');
    PERFORM pg_temp.ok('permission_declare', '{"actor":"retired-test","service":"rtsvc","permission":{"feature":"task","act":"edit","class":"ordinary","plane":"object"}}', 'declare task:edit');
    PERFORM pg_temp.ok('permission_declare', '{"actor":"retired-test","service":"rtsvc","permission":{"feature":"project","act":"create","class":"ordinary","plane":"tenant"}}', 'declare project:create');

    -- Anna administers the tenant; Toms works in it through a role ticking two boxes.
    v := pg_temp.ok('tenant_open', jsonb_build_object('actor', 'op:test', 'name', 'Retired demo',
        'administrator', jsonb_build_object('subjectKey', v_s[1], 'displayName', 'Anna Ozola')), 'open the tenant');
    v_tenant := v->'tenant'->>'id';
    PERFORM pg_temp.ok('claim_attach', jsonb_build_object('actor', 'idp:test', 'subjectKey', v_s[1]), 'claim Anna');
    PERFORM pg_temp.ok('entitlement_grant', jsonb_build_object('actor', 'op:test', 'tenantId', v_tenant, 'service', 'rtsvc'), 'entitle rtsvc');
    v_toms := pg_temp.ok('user_invite', jsonb_build_object('actor', v_s[1], 'tenantId', v_tenant, 'subjectKey', v_s[2],
        'displayName', 'Toms Bērziņš'), 'invite Toms')->>'id';
    PERFORM pg_temp.ok('claim_attach', jsonb_build_object('actor', 'idp:test', 'subjectKey', v_s[2]), 'claim Toms');
    v_worker := pg_temp.ok('tenant_role_define', jsonb_build_object('actor', v_s[1], 'tenantId', v_tenant, 'name', 'Darbinieks'), 'define Darbinieks')->>'id';
    v_other := pg_temp.ok('tenant_role_define', jsonb_build_object('actor', v_s[1], 'tenantId', v_tenant, 'name', 'Meistars'), 'define Meistars')->>'id';
    PERFORM pg_temp.ok('tenant_role_permissions_set', jsonb_build_object('actor', v_s[1], 'tenantId', v_tenant, 'roleId', v_worker,
        'permissions', '["rtsvc/task:view", "rtsvc/task:edit"]'::jsonb), 'tick two boxes');
    PERFORM pg_temp.ok('tenant_role_grant', jsonb_build_object('actor', v_s[1], 'tenantId', v_tenant, 'userId', v_toms, 'roleId', v_worker), 'grant Darbinieks');

    -- 1. The service retires task:edit through its configuration document; the
    --    second apply of the same document changes nothing and records nothing.
    v_doc := '{"services":[{"key":"rtsvc","displayName":"Work","roles":[],"permissions":[
        {"feature":"task","act":"view","class":"ordinary","plane":"object"},
        {"feature":"task","act":"edit","class":"ordinary","plane":"object","retired":true},
        {"feature":"project","act":"create","class":"ordinary","plane":"tenant"}]}]}';
    v := pg_temp.ok('config_apply', jsonb_build_object('tenantId', v_tenant, 'actor', 'retired-test', 'section', v_doc), 'retire by document');
    IF (SELECT e->>'status' FROM jsonb_array_elements(v->'permissions') e WHERE e->>'permission' = 'rtsvc/task:edit')
       IS DISTINCT FROM 'changed'
       OR EXISTS (SELECT 1 FROM jsonb_array_elements(v->'permissions') e
                   WHERE e->>'permission' <> 'rtsvc/task:edit' AND e->>'status' <> 'unchanged') THEN
        RAISE EXCEPTION 'retiring one permission should change exactly it: %', v;
    END IF;
    IF (SELECT retired_at FROM rolebyte.service_permission
         WHERE service_key = 'rtsvc' AND feature_key = 'task' AND act = 'edit') IS NULL THEN
        RAISE EXCEPTION 'the retired mark should be stored';
    END IF;
    IF NOT EXISTS (SELECT 1 FROM rolebyte.event WHERE kind = 'permissionRetired'
                    AND payload->>'permission' = 'rtsvc/task:edit' AND actor = 'retired-test') THEN
        RAISE EXCEPTION 'retiring must land in the event stream, attributed';
    END IF;
    v := pg_temp.ok('config_apply', jsonb_build_object('tenantId', v_tenant, 'actor', 'retired-test', 'section', v_doc), 'apply again');
    IF EXISTS (SELECT 1 FROM jsonb_array_elements(v->'permissions') e WHERE e->>'status' <> 'unchanged') THEN
        RAISE EXCEPTION 'the second apply of the same document should change nothing: %', v;
    END IF;
    IF (SELECT count(*) FROM rolebyte.event WHERE kind = 'permissionRetired' AND payload->>'permission' = 'rtsvc/task:edit') <> 1 THEN
        RAISE EXCEPTION 'the second apply must record nothing';
    END IF;

    --    The export says so, and reads back as unchanged.
    v := pg_temp.ok('config_get', jsonb_build_object('tenantId', v_tenant), 'export');
    IF (SELECT p->'retired' FROM jsonb_array_elements(v->'services') s, jsonb_array_elements(s->'permissions') p
         WHERE s->>'key' = 'rtsvc' AND p->>'feature' = 'task' AND p->>'act' = 'edit') IS DISTINCT FROM 'true'::jsonb THEN
        RAISE EXCEPTION 'the export should carry the retired mark: %', v;
    END IF;
    v := pg_temp.ok('config_apply', jsonb_build_object('tenantId', v_tenant, 'actor', 'retired-test', 'section', v), 'round trip');
    IF EXISTS (SELECT 1 FROM jsonb_array_elements(v->'permissions') e WHERE e->>'status' <> 'unchanged') THEN
        RAISE EXCEPTION 'the export applied back should change nothing: %', v;
    END IF;

    -- 2. Toms's role keeps the tick and it still reaches his token.
    PERFORM pg_temp.holds_exactly(pg_temp.scopes(v_s[2], v_tenant), ARRAY['rtsvc/task:view', 'rtsvc/task:edit'],
        'a retired permission a role ticks must still resolve');
    v := pg_temp.ok('tenant_role_definitions', jsonb_build_object('tenantId', v_tenant), 'role definitions');
    IF (SELECT r->'permissions' FROM jsonb_array_elements(v->'roles') r WHERE r->>'id' = v_worker)
       IS DISTINCT FROM '["rtsvc/task:edit", "rtsvc/task:view"]'::jsonb THEN
        RAISE EXCEPTION 'the role''s definition should still carry the retired tick: %', v;
    END IF;

    -- 3. The Administrator checkbox no longer hands it out.
    PERFORM pg_temp.holds_exactly(pg_temp.scopes(v_s[1], v_tenant), ARRAY['membership:admin', 'rtsvc/task:view', 'rtsvc/project:create'],
        'an administrator must not be handed a retired permission');

    -- 4. The role may be set again with the tick it has, which changes nothing.
    v := pg_temp.ok('tenant_role_permissions_set', jsonb_build_object('actor', v_s[1], 'tenantId', v_tenant, 'roleId', v_worker,
        'permissions', '["rtsvc/task:view", "rtsvc/task:edit"]'::jsonb), 'set the same ticks');
    IF (v->>'changed')::boolean THEN
        RAISE EXCEPTION 'setting the same ticks with a retired one should change nothing: %', v;
    END IF;

    -- 5. No other role can be given it, alone or beside a live box, and the
    --    refusal says why.
    PERFORM pg_temp.refused('tenant_role_permissions_set', jsonb_build_object('actor', v_s[1], 'tenantId', v_tenant, 'roleId', v_other,
        'permissions', '["rtsvc/task:edit"]'::jsonb), 'membership:invalid', RETIRED, 'a new tick of a retired permission');
    PERFORM pg_temp.refused('tenant_role_permissions_set', jsonb_build_object('actor', v_s[1], 'tenantId', v_tenant, 'roleId', v_other,
        'permissions', '["rtsvc/task:view", "rtsvc/task:edit"]'::jsonb), 'membership:invalid', RETIRED, 'a retired tick beside a live one');

    -- 6. Once dropped, the role cannot take it back.
    PERFORM pg_temp.ok('tenant_role_permissions_set', jsonb_build_object('actor', v_s[1], 'tenantId', v_tenant, 'roleId', v_worker,
        'permissions', '["rtsvc/task:view"]'::jsonb), 'drop the retired tick');
    PERFORM pg_temp.refused('tenant_role_permissions_set', jsonb_build_object('actor', v_s[1], 'tenantId', v_tenant, 'roleId', v_worker,
        'permissions', '["rtsvc/task:view", "rtsvc/task:edit"]'::jsonb), 'membership:invalid', RETIRED, 'taking a dropped retired tick back');
    PERFORM pg_temp.holds_exactly(pg_temp.scopes(v_s[2], v_tenant), ARRAY['rtsvc/task:view'],
        'a dropped tick must stop resolving');

    -- 7. Declaring it without the mark brings it back for everyone.
    v := pg_temp.ok('permission_declare', '{"actor":"retired-test","service":"rtsvc","permission":{"feature":"task","act":"edit","class":"ordinary","plane":"object"}}', 'reinstate');
    IF v->>'status' IS DISTINCT FROM 'changed' THEN
        RAISE EXCEPTION 'reinstating should be a change: %', v;
    END IF;
    IF NOT EXISTS (SELECT 1 FROM rolebyte.event WHERE kind = 'permissionReinstated' AND payload->>'permission' = 'rtsvc/task:edit') THEN
        RAISE EXCEPTION 'reinstating must land in the event stream';
    END IF;
    PERFORM pg_temp.ok('tenant_role_permissions_set', jsonb_build_object('actor', v_s[1], 'tenantId', v_tenant, 'roleId', v_other,
        'permissions', '["rtsvc/task:edit"]'::jsonb), 'a reinstated permission can be ticked');
    PERFORM pg_temp.holds_exactly(pg_temp.scopes(v_s[1], v_tenant),
        ARRAY['membership:admin', 'rtsvc/task:view', 'rtsvc/task:edit', 'rtsvc/project:create'],
        'a reinstated permission reaches the administrator again');

    RAISE NOTICE 'unit.rolebyte_permission_retired: all assertions passed';
END $$;

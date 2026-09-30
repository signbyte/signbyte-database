-- Unit test: a per-field family — one permission per field of a kind, where the
-- fields are a tenant's own. A family is declared once, on the object plane,
-- seeding no role. A role holds it one field at a time, `<family>@<key>.<generation>`:
-- the bare family is refused on a role, `@` on any other permission is refused,
-- and a part after `@` of any other shape is not a name. The roles a service
-- copies carry each field's permission as it travels, narrowed to what the
-- tenant has; resolve never puts one on a token, and gives the administrators
-- the bare family. Setting which roles hold one field changes that field on
-- those roles and nothing else, records one event per role it changes, and
-- refuses an unknown role or a name that is not one field of a family whole. A
-- retired family keeps the roles that hold a field of it and is given to no
-- other.
--   psql -v ON_ERROR_STOP=1 -f migrations/testing/tests/unit.rolebyte_per_field.sql

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

-- What a refusal must leave untouched: every tick, the declarations and the history.
CREATE OR REPLACE FUNCTION pg_temp.state() RETURNS text
LANGUAGE sql AS $$
    SELECT format('%s/%s/%s',
        (SELECT string_agg(tenant_role_id || permission_id || COALESCE(param, '-'), ','
                           ORDER BY tenant_role_id, permission_id, param)
           FROM rolebyte.tenant_role_permission),
        (SELECT string_agg(id || class || COALESCE(retired_at::text, '-'), ',' ORDER BY id) FROM rolebyte.service_permission),
        (SELECT count(*) FROM rolebyte.event));
$$;

-- The call must be refused with this code, and change nothing. Returns the
-- refusal's message.
CREATE OR REPLACE FUNCTION pg_temp.refused(p_proc text, p_in jsonb, p_code text, p_why text) RETURNS text
LANGUAGE plpgsql AS $$
DECLARE
    v      jsonb;
    before text := pg_temp.state();
BEGIN
    v := pg_temp.rb(p_proc, p_in);
    IF v->>'result' IS DISTINCT FROM 'error' OR v->>'code' IS DISTINCT FROM p_code THEN
        RAISE EXCEPTION '% should be refused %: %', p_why, p_code, v;
    END IF;
    IF pg_temp.state() IS DISTINCT FROM before THEN
        RAISE EXCEPTION '% was refused but changed something', p_why;
    END IF;
    RETURN v->>'message';
END $$;

CREATE OR REPLACE FUNCTION pg_temp.is(p_got anyelement, p_expected anyelement, p_why text) RETURNS void
LANGUAGE plpgsql AS $$
BEGIN
    IF p_got IS DISTINCT FROM p_expected THEN
        RAISE EXCEPTION '%: expected %, got %', p_why, p_expected, p_got;
    END IF;
END $$;

CREATE OR REPLACE FUNCTION pg_temp.texts(p jsonb) RETURNS text[]
LANGUAGE sql AS $$
    SELECT COALESCE(array_agg(x ORDER BY o), '{}') FROM jsonb_array_elements_text(p) WITH ORDINALITY AS t(x, o);
$$;

-- The subject's scopes in a tenant as resolve answers them, sorted bytewise.
CREATE OR REPLACE FUNCTION pg_temp.scopes(p_subject text, p_tenant text) RETURNS text[]
LANGUAGE plpgsql AS $$
DECLARE
    v jsonb;
BEGIN
    CALL rolebyte.resolve(jsonb_build_object('subjectKey', p_subject), v);
    SELECT m->'scopes' INTO v
      FROM jsonb_array_elements(v->'data'->'memberships') m
     WHERE m->>'tenantId' = p_tenant;
    RETURN (SELECT COALESCE(array_agg(x ORDER BY x COLLATE "C"), '{}') FROM jsonb_array_elements_text(v) x);
END $$;

-- One role's permissions in the copy a placing service reads.
CREATE OR REPLACE FUNCTION pg_temp.copied(p_tenant text, p_role text) RETURNS text[]
LANGUAGE plpgsql AS $$
DECLARE
    v jsonb := pg_temp.ok('tenant_role_definitions', jsonb_build_object('tenantId', p_tenant), 'read the copy');
BEGIN
    RETURN pg_temp.texts((SELECT r->'permissions' FROM jsonb_array_elements(v->'roles') r WHERE r->>'id' = p_role));
END $$;

-- The roles of a tenant holding one field's permission, sorted bytewise.
CREATE OR REPLACE FUNCTION pg_temp.holders(p_tenant text, p_name text) RETURNS text[]
LANGUAGE sql AS $$
    SELECT COALESCE(array_agg(r.id ORDER BY r.id COLLATE "C"), '{}')
      FROM rolebyte.tenant_role r
     WHERE r.tenant_id = p_tenant
       AND rolebyte.tenant_role_permission_names(r.id) ? p_name;
$$;

DO $$
DECLARE
    v_fam    constant text := 'pfledger/entry:viewField';
    v_ta     text;
    v_tb     text;
    v_lead   text;
    v_clerk  text;
    v_other  text;
    v_rb     text;
    v_admin  text;
    v_member text;
    v_subs   text[] := ARRAY(SELECT 'sub:' || util.generate_ulid() FROM generate_series(1, 3));
    v_events bigint;
    v_msg    text;
    v        jsonb;
    v_bad    text;
BEGIN
    PERFORM pg_temp.ok('service_register', '{"actor":"pf-test","service":"pfledger","displayName":"Ledger"}', 'register pfledger');
    PERFORM pg_temp.ok('permission_declare', '{"actor":"pf-test","service":"pfledger","permission":{"feature":"entry","act":"view","class":"ordinary","plane":"object"}}', 'declare entry:view');
    PERFORM pg_temp.ok('permission_declare', '{"actor":"pf-test","service":"pfledger","permission":{"feature":"setup","act":"edit","class":"tenantConfiguration","plane":"tenant"}}', 'declare setup:edit');

    -- 1. DECLARING: once, on the object plane, seeding no role.
    v := pg_temp.ok('permission_declare', '{"actor":"pf-test","service":"pfledger","permission":{"feature":"entry","act":"viewField","class":"perField","plane":"object","description":"See the value of a restricted field on an entry"}}', 'declare the family');
    PERFORM pg_temp.is(v->>'status', 'added', 'the family is declared');
    PERFORM pg_temp.is((SELECT class FROM rolebyte.service_permission WHERE service_key = 'pfledger' AND feature_key = 'entry' AND act = 'viewField'),
        'perField', 'the family is stored with its class');
    v_msg := pg_temp.refused('permission_declare', '{"actor":"pf-test","service":"pfledger","permission":{"feature":"line","act":"viewField","class":"perField","plane":"tenant"}}',
        'membership:invalid', 'a family on the tenant plane');
    PERFORM pg_temp.is(v_msg LIKE '%plane is object%', true, 'the refusal says where a family is held');
    PERFORM pg_temp.refused('permission_declare', '{"actor":"pf-test","service":"pfledger","permission":{"feature":"line","act":"viewField","class":"perField","plane":"object","seeds":["manager"]}}',
        'membership:invalid', 'a family that seeds a role');
    PERFORM pg_temp.refused('permission_declare', '{"actor":"pf-test","service":"pfledger","permission":{"feature":"entry","act":"view","class":"perField","plane":"object"}}',
        'membership:conflict', 'an ordinary permission declared again as a family');
    --    The configuration section carries the family with its class.
    v_ta := pg_temp.ok('tenant_open', jsonb_build_object('actor', 'op:test', 'name', 'Per field A',
        'administrator', jsonb_build_object('subjectKey', v_subs[1], 'displayName', 'Admin A')), 'open A')->'tenant'->>'id';
    v := pg_temp.ok('config_get', jsonb_build_object('tenantId', v_ta), 'read the section');
    PERFORM pg_temp.is((SELECT p->>'class' FROM jsonb_array_elements(v->'services') s, jsonb_array_elements(s->'permissions') p
                         WHERE s->>'key' = 'pfledger' AND p->>'feature' = 'entry' AND p->>'act' = 'viewField'),
        'perField', 'the section carries the family''s class');

    v_tb := pg_temp.ok('tenant_create', '{"actor":"pf-test","name":"Per field B"}', 'tenant B')->>'id';
    PERFORM pg_temp.ok('entitlement_grant', jsonb_build_object('actor', 'op:test', 'tenantId', v_ta, 'service', 'pfledger'), 'entitle A');
    PERFORM pg_temp.ok('entitlement_grant', jsonb_build_object('actor', 'op:test', 'tenantId', v_tb, 'service', 'pfledger'), 'entitle B');
    v_lead  := pg_temp.ok('tenant_role_define', jsonb_build_object('actor', 'adm-a', 'tenantId', v_ta, 'name', 'Lead'), 'define Lead')->>'id';
    v_clerk := pg_temp.ok('tenant_role_define', jsonb_build_object('actor', 'adm-a', 'tenantId', v_ta, 'name', 'Clerk'), 'define Clerk')->>'id';
    v_other := pg_temp.ok('tenant_role_define', jsonb_build_object('actor', 'adm-a', 'tenantId', v_ta, 'name', 'Visitor'), 'define Visitor')->>'id';
    v_rb    := pg_temp.ok('tenant_role_define', jsonb_build_object('actor', 'adm-b', 'tenantId', v_tb, 'name', 'Lead'), 'define B''s Lead')->>'id';

    -- 2. A ROLE'S TICKS: the bare family, `@` on anything else, and a part after
    --    `@` of any other shape are refused, and change nothing.
    v_msg := pg_temp.refused('tenant_role_permissions_set', jsonb_build_object('actor', 'adm-a', 'tenantId', v_ta, 'roleId', v_lead,
        'permissions', jsonb_build_array(v_fam)), 'membership:invalid', 'the bare family on a role');
    PERFORM pg_temp.is(v_msg LIKE '%only the Administrator checkbox holds it%', true, 'the refusal says who holds the bare family');
    v_msg := pg_temp.refused('tenant_role_permissions_set', jsonb_build_object('actor', 'adm-a', 'tenantId', v_ta, 'roleId', v_lead,
        'permissions', '["pfledger/entry:view@rate.1"]'::jsonb), 'membership:invalid', 'a field of an ordinary permission');
    PERFORM pg_temp.is(v_msg, 'pfledger/entry:view is not a per-field family, so it names no field', 'the refusal names the permission');
    PERFORM pg_temp.refused('tenant_role_permissions_set', jsonb_build_object('actor', 'adm-a', 'tenantId', v_ta, 'roleId', v_lead,
        'permissions', '["pfledger/setup:edit@rate.1"]'::jsonb), 'membership:invalid', 'a field of a setup permission');
    PERFORM pg_temp.refused('tenant_role_permissions_set', jsonb_build_object('actor', 'adm-a', 'tenantId', v_ta, 'roleId', v_lead,
        'permissions', '["pfledger/entry:missing@rate.1"]'::jsonb), 'membership:unknown_permission', 'a field of an undeclared family');
    FOREACH v_bad IN ARRAY ARRAY['@rate', '@rate.0', '@rate.01', '@Rate.1', '@ra-te.1', '@rate.1.2', '@', '@.1',
                                 '@rate.1@rate.2', '@rate 1', '@rate.1234567890', '@' || repeat('a', 65) || '.1'] LOOP
        v_msg := pg_temp.refused('tenant_role_permissions_set', jsonb_build_object('actor', 'adm-a', 'tenantId', v_ta, 'roleId', v_lead,
            'permissions', jsonb_build_array(v_fam || v_bad)), 'membership:unknown_permission', format('the field part %s', v_bad));
        PERFORM pg_temp.is(v_msg, 'an entry is not a permission name', format('%s is not repeated back', v_bad));
    END LOOP;
    PERFORM pg_temp.refused('tenant_role_permissions_set', jsonb_build_object('actor', 'adm-a', 'tenantId', v_ta, 'roleId', v_lead,
        'permissions', '["pfledger/entry@rate.1:viewField"]'::jsonb), 'membership:unknown_permission', 'a field part before the act');

    --    One field at a time, beside ordinary ticks, a key that starts with a digit
    --    included; the answer spells each as it travels.
    v := pg_temp.ok('tenant_role_permissions_set', jsonb_build_object('actor', 'adm-a', 'tenantId', v_ta, 'roleId', v_lead,
        'permissions', jsonb_build_array('pfledger/entry:view', v_fam || '@rate.2', v_fam || '@grade.1', v_fam || '@2ndShift.4', v_fam || '@rate.2')),
        'tick Lead');
    PERFORM pg_temp.is(pg_temp.texts(v->'permissions'),
        ARRAY['pfledger/entry:view', v_fam || '@2ndShift.4', v_fam || '@grade.1', v_fam || '@rate.2'], 'Lead holds three fields and the view');
    PERFORM pg_temp.is(pg_temp.texts(v->'added'), pg_temp.texts(v->'permissions'), 'all four were added');
    SELECT count(*) INTO v_events FROM rolebyte.event;
    v := pg_temp.ok('tenant_role_permissions_set', jsonb_build_object('actor', 'adm-a', 'tenantId', v_ta, 'roleId', v_lead,
        'permissions', jsonb_build_array('pfledger/entry:view', v_fam || '@rate.2', v_fam || '@grade.1', v_fam || '@2ndShift.4')), 'tick Lead again');
    PERFORM pg_temp.is((v->>'changed')::boolean, false, 'the same set changes nothing');
    PERFORM pg_temp.is((SELECT count(*) FROM rolebyte.event), v_events, 'the same set records nothing');
    v := pg_temp.ok('tenant_role_permissions_set', jsonb_build_object('actor', 'adm-a', 'tenantId', v_ta, 'roleId', v_lead,
        'permissions', jsonb_build_array('pfledger/entry:view', v_fam || '@rate.2', v_fam || '@grade.1')), 'drop one field');
    PERFORM pg_temp.is(pg_temp.texts(v->'removed'), ARRAY[v_fam || '@2ndShift.4'], 'one field removed, by its name');
    PERFORM pg_temp.is(pg_temp.texts(v->'added'), ARRAY[]::text[], 'nothing added');
    --    A later generation of the same field is a different permission.
    v := pg_temp.ok('tenant_role_permissions_set', jsonb_build_object('actor', 'adm-a', 'tenantId', v_ta, 'roleId', v_clerk,
        'permissions', jsonb_build_array('pfledger/entry:view', v_fam || '@rate.3')), 'tick Clerk');
    PERFORM pg_temp.is(pg_temp.texts(v->'permissions'), ARRAY['pfledger/entry:view', v_fam || '@rate.3'], 'Clerk holds the next generation');

    -- 3. THE COPY a placing service reads carries each field as it travels, in
    --    byte order; the role list does too.
    PERFORM pg_temp.is(pg_temp.copied(v_ta, v_lead), ARRAY['pfledger/entry:view', v_fam || '@grade.1', v_fam || '@rate.2'],
        'Lead''s copy carries its fields');
    PERFORM pg_temp.is(pg_temp.copied(v_ta, v_clerk), ARRAY['pfledger/entry:view', v_fam || '@rate.3'], 'Clerk''s copy');
    v := pg_temp.ok('tenant_role_list', jsonb_build_object('tenantId', v_ta), 'list A''s roles');
    PERFORM pg_temp.is(pg_temp.texts((SELECT r->'permissions' FROM jsonb_array_elements(v->'roles') r WHERE r->>'id' = v_lead)),
        ARRAY['pfledger/entry:view', v_fam || '@grade.1', v_fam || '@rate.2'], 'the role list spells the fields');

    -- 4. RESOLVE: a member granted Lead carries the view and no field; the
    --    administrator carries the bare family; no token carries a field.
    v_member := pg_temp.ok('user_invite', jsonb_build_object('actor', 'adm-a', 'tenantId', v_ta, 'subjectKey', v_subs[2],
        'displayName', 'Member', 'roles', '[]'::jsonb), 'invite member')->>'id';
    PERFORM pg_temp.ok('claim_attach', jsonb_build_object('actor', 'pf-test', 'subjectKey', v_subs[2]), 'claim member');
    PERFORM pg_temp.ok('claim_attach', jsonb_build_object('actor', 'pf-test', 'subjectKey', v_subs[1]), 'claim admin');
    PERFORM pg_temp.ok('tenant_role_grant', jsonb_build_object('actor', 'adm-a', 'tenantId', v_ta, 'userId', v_member, 'roleId', v_lead), 'grant Lead');
    PERFORM pg_temp.is(pg_temp.scopes(v_subs[2], v_ta), ARRAY['pfledger/entry:view'], 'the member''s token carries the view, no field');
    PERFORM pg_temp.is(v_fam = ANY (pg_temp.scopes(v_subs[1], v_ta)), true, 'the administrator''s token carries the bare family');
    PERFORM pg_temp.is(EXISTS (SELECT 1 FROM unnest(pg_temp.scopes(v_subs[1], v_ta) || pg_temp.scopes(v_subs[2], v_ta)) s
                                WHERE position('@' IN s) > 0), false, 'no token carries a field');
    --    A field is narrowed to what the tenant has, like any tick.
    PERFORM pg_temp.ok('entitlement_revoke', jsonb_build_object('actor', 'op:test', 'tenantId', v_ta, 'service', 'pfledger'), 'lapse A');
    PERFORM pg_temp.is(pg_temp.copied(v_ta, v_lead), ARRAY[]::text[], 'a lapsed service leaves the copy empty');
    PERFORM pg_temp.ok('entitlement_grant', jsonb_build_object('actor', 'op:test', 'tenantId', v_ta, 'service', 'pfledger'), 'entitle A again');
    PERFORM pg_temp.is(pg_temp.copied(v_ta, v_lead), ARRAY['pfledger/entry:view', v_fam || '@grade.1', v_fam || '@rate.2'],
        'the fields come back with the entitlement');

    -- 5. WHICH ROLES HOLD ONE FIELD: the field form's call. It gives the field to
    --    the roles named, takes it from every other role of the tenant, and
    --    touches no other tick.
    SELECT count(*) INTO v_events FROM rolebyte.event;
    v := pg_temp.ok('field_permission_roles_set', jsonb_build_object('actor', 'adm-a', 'tenantId', v_ta,
        'permission', v_fam || '@rate.2', 'roleIds', jsonb_build_array(v_clerk, v_other, v_clerk)), 'Clerk and Visitor see rate.2');
    PERFORM pg_temp.is(pg_temp.texts(v->'roleIds'),
        (SELECT array_agg(x ORDER BY x COLLATE "C") FROM unnest(ARRAY[v_clerk, v_other]) x), 'the two named roles hold it');
    PERFORM pg_temp.is((v->>'changed')::boolean, true, 'the holders changed');
    PERFORM pg_temp.is(pg_temp.holders(v_ta, v_fam || '@rate.2'),
        (SELECT array_agg(x ORDER BY x COLLATE "C") FROM unnest(ARRAY[v_clerk, v_other]) x), 'Lead lost it');
    PERFORM pg_temp.is(pg_temp.copied(v_ta, v_lead), ARRAY['pfledger/entry:view', v_fam || '@grade.1'], 'Lead''s other ticks stay');
    PERFORM pg_temp.is(pg_temp.copied(v_ta, v_clerk), ARRAY['pfledger/entry:view', v_fam || '@rate.2', v_fam || '@rate.3'],
        'Clerk keeps its other ticks');
    PERFORM pg_temp.is((SELECT count(*) FROM rolebyte.event), v_events + 3, 'one event per role changed: Lead, Clerk, Visitor');
    PERFORM pg_temp.is((SELECT count(*) FROM rolebyte.event e
                         WHERE e.kind = 'tenantRoleReconfigured' AND e.payload->>'roleId' = v_lead
                           AND e.payload->'removed' = jsonb_build_array(v_fam || '@rate.2')), 1::bigint, 'Lead''s event names the field taken');
    PERFORM pg_temp.is(pg_temp.copied(v_tb, v_rb), ARRAY[]::text[], 'another tenant''s role is untouched');
    SELECT count(*) INTO v_events FROM rolebyte.event;
    v := pg_temp.ok('field_permission_roles_set', jsonb_build_object('actor', 'adm-a', 'tenantId', v_ta,
        'permission', v_fam || '@rate.2', 'roleIds', jsonb_build_array(v_other, v_clerk)), 'the same set again');
    PERFORM pg_temp.is((v->>'changed')::boolean, false, 'the same set changes nothing');
    PERFORM pg_temp.is((SELECT count(*) FROM rolebyte.event), v_events, 'and records nothing');
    v := pg_temp.ok('field_permission_roles_set', jsonb_build_object('actor', 'adm-a', 'tenantId', v_ta,
        'permission', v_fam || '@rate.2', 'roleIds', '[]'::jsonb), 'nobody sees rate.2');
    PERFORM pg_temp.is(pg_temp.texts(v->'roleIds'), ARRAY[]::text[], 'no role holds it');
    PERFORM pg_temp.is(pg_temp.copied(v_ta, v_clerk), ARRAY['pfledger/entry:view', v_fam || '@rate.3'], 'Clerk''s next generation stays');

    --    Refusals, each changing nothing.
    PERFORM pg_temp.refused('field_permission_roles_set', jsonb_build_object('actor', 'adm-a', 'tenantId', v_ta,
        'permission', v_fam || '@rate.2', 'roleIds', jsonb_build_array(v_clerk, util.generate_ulid())), 'membership:unknown_role', 'an unknown role');
    PERFORM pg_temp.refused('field_permission_roles_set', jsonb_build_object('actor', 'adm-a', 'tenantId', v_ta,
        'permission', v_fam || '@rate.2', 'roleIds', jsonb_build_array(v_rb)), 'membership:unknown_role', 'another tenant''s role');
    v_msg := pg_temp.refused('field_permission_roles_set', jsonb_build_object('actor', 'adm-a', 'tenantId', v_ta,
        'permission', v_fam, 'roleIds', jsonb_build_array(v_clerk)), 'membership:unknown_permission', 'the bare family');
    PERFORM pg_temp.is(v_msg, 'the permission is not one field of a per-field family', 'the bare family is not one field');
    PERFORM pg_temp.refused('field_permission_roles_set', jsonb_build_object('actor', 'adm-a', 'tenantId', v_ta,
        'permission', 'pfledger/entry:view@rate.2', 'roleIds', jsonb_build_array(v_clerk)), 'membership:invalid', 'a field of an ordinary permission');
    PERFORM pg_temp.refused('field_permission_roles_set', jsonb_build_object('actor', 'adm-a', 'tenantId', v_ta,
        'permission', 'pfledger/entry:missing@rate.2', 'roleIds', jsonb_build_array(v_clerk)), 'membership:unknown_permission', 'an undeclared family');
    v_msg := pg_temp.refused('field_permission_roles_set', jsonb_build_object('actor', 'adm-a', 'tenantId', v_ta,
        'permission', v_fam || '@rate.0', 'roleIds', jsonb_build_array(v_clerk)), 'membership:unknown_permission', 'a malformed field part');
    PERFORM pg_temp.is(v_msg, 'the permission is not one field of a per-field family', 'a malformed name is not repeated back');
    PERFORM pg_temp.refused('field_permission_roles_set', jsonb_build_object('actor', 'adm-a', 'tenantId', v_ta,
        'permission', v_fam || '@rate.2', 'roleIds', '"everyone"'::jsonb), 'membership:invalid', 'role ids that are not a list');
    PERFORM pg_temp.refused('field_permission_roles_set', jsonb_build_object('actor', 'adm-a', 'tenantId', util.generate_ulid(),
        'permission', v_fam || '@rate.2', 'roleIds', '[]'::jsonb), 'tenant:not_found', 'a tenant that does not exist');
    PERFORM pg_temp.refused('field_permission_roles_set', jsonb_build_object('tenantId', v_ta,
        'permission', v_fam || '@rate.2', 'roleIds', '[]'::jsonb), 'membership:invalid', 'no actor');

    -- 6. A RETIRED FAMILY keeps the roles that hold a field of it, and gives one
    --    to no other role, by either call.
    PERFORM pg_temp.ok('permission_declare', '{"actor":"pf-test","service":"pfledger","permission":{"feature":"entry","act":"viewField","class":"perField","plane":"object","description":"See the value of a restricted field on an entry","retired":true}}', 'retire the family');
    PERFORM pg_temp.ok('field_permission_roles_set', jsonb_build_object('actor', 'adm-a', 'tenantId', v_ta,
        'permission', v_fam || '@rate.3', 'roleIds', jsonb_build_array(v_clerk)), 'Clerk keeps rate.3');
    PERFORM pg_temp.refused('field_permission_roles_set', jsonb_build_object('actor', 'adm-a', 'tenantId', v_ta,
        'permission', v_fam || '@rate.3', 'roleIds', jsonb_build_array(v_clerk, v_lead)), 'membership:invalid', 'rate.3 to Lead once retired');
    PERFORM pg_temp.refused('tenant_role_permissions_set', jsonb_build_object('actor', 'adm-a', 'tenantId', v_ta, 'roleId', v_lead,
        'permissions', jsonb_build_array('pfledger/entry:view', v_fam || '@grade.1', v_fam || '@rate.9')), 'membership:invalid', 'a new field once retired');
    PERFORM pg_temp.ok('tenant_role_permissions_set', jsonb_build_object('actor', 'adm-a', 'tenantId', v_ta, 'roleId', v_lead,
        'permissions', jsonb_build_array('pfledger/entry:view', v_fam || '@grade.1')), 'Lead keeps grade.1');
    PERFORM pg_temp.is(v_fam = ANY (pg_temp.scopes(v_subs[1], v_ta)), false, 'a retired family is on no administrator''s token');

    RAISE NOTICE 'unit.rolebyte_per_field: all assertions passed';
END $$;

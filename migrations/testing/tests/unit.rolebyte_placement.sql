-- Unit test: a service that places the tenant's roles on its own objects reads
-- what each role carries, and reports how many times it placed each.
-- The read carries each role's ticks narrowed to what the tenant has, the same
-- set resolve gives a person granted the role, in a fixed order whatever the
-- database's collation, and never another tenant's roles. A report replaces the
-- last one whole, stores no id that is not the tenant's role and answers it
-- back, refuses a count that is not a whole number and a reporter who is not an
-- active member, and records no event. A role placed by an active member service
-- cannot be deleted and the refusal says how many times and by whom; held and
-- placed together, both counts; reported at zero, or reported by a service whose
-- membership was revoked, the delete goes through.
--   psql -v ON_ERROR_STOP=1 -f migrations/testing/tests/unit.rolebyte_placement.sql

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

-- What a refusal must leave untouched: the counts, the roles and the history.
CREATE OR REPLACE FUNCTION pg_temp.state() RETURNS text
LANGUAGE sql AS $$
    SELECT format('%s/%s/%s',
        (SELECT string_agg(tenant_role_id || reporter_id || placements, ',' ORDER BY tenant_role_id, reporter_id)
           FROM rolebyte.tenant_role_placement),
        (SELECT string_agg(id, ',' ORDER BY id) FROM rolebyte.tenant_role),
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

-- One role of the read, by id.
CREATE OR REPLACE FUNCTION pg_temp.role_in(p_defs jsonb, p_id text) RETURNS jsonb
LANGUAGE sql AS $$
    SELECT r FROM jsonb_array_elements(p_defs->'roles') r WHERE r->>'id' = p_id;
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

CREATE OR REPLACE FUNCTION pg_temp.texts(p jsonb) RETURNS text[]
LANGUAGE sql AS $$
    SELECT COALESCE(array_agg(x ORDER BY o), '{}') FROM jsonb_array_elements_text(p) WITH ORDINALITY AS t(x, o);
$$;

DO $$
DECLARE
    v_ta     text;
    v_tb     text;
    v_boss   text;
    v_crew   text;
    v_empty  text;
    v_rb     text;
    v_holder text;
    v_svc    text;
    v_svc2   text;
    v_svcb   text;
    v_subs   text[] := ARRAY(SELECT 'sub:' || util.generate_ulid() FROM generate_series(1, 2));
    v_events bigint;
    v_msg    text;
    v        jsonb;
    v_defs   jsonb;
BEGIN
    -- Two services: one whose features the tenant has in part, one it lacks.
    -- `ab` beside `a/b` is the pair whose order a linguistic collation reverses:
    -- by bytes `a/b` comes first, by words `ab`.
    PERFORM pg_temp.ok('service_register', '{"actor":"pl-test","service":"plorder","displayName":"Orders"}', 'register plorder');
    PERFORM pg_temp.ok('service_register', '{"actor":"pl-test","service":"plpeople","displayName":"People"}', 'register plpeople');
    PERFORM pg_temp.ok('permission_declare', '{"actor":"pl-test","service":"plorder","permission":{"feature":"ab","act":"c","class":"ordinary"}}', 'declare ab:c');
    PERFORM pg_temp.ok('permission_declare', '{"actor":"pl-test","service":"plorder","permission":{"feature":"a/b","act":"d","class":"ordinary"}}', 'declare a/b:d');
    PERFORM pg_temp.ok('permission_declare', '{"actor":"pl-test","service":"plorder","permission":{"feature":"hidden","act":"view","class":"ordinary"}}', 'declare hidden:view');
    PERFORM pg_temp.ok('permission_declare', '{"actor":"pl-test","service":"plpeople","permission":{"feature":"person","act":"view","class":"ordinary"}}', 'declare person:view');

    v_ta := pg_temp.ok('tenant_create', '{"actor":"pl-test","name":"Placement A"}', 'tenant A')->>'id';
    v_tb := pg_temp.ok('tenant_create', '{"actor":"pl-test","name":"Placement B"}', 'tenant B')->>'id';

    -- A has the two ordering features of plorder and nothing of plpeople.
    PERFORM pg_temp.ok('entitlement_grant', jsonb_build_object('actor', 'op:test', 'tenantId', v_ta, 'service', 'plorder', 'feature', 'ab'), 'entitle ab');
    PERFORM pg_temp.ok('entitlement_grant', jsonb_build_object('actor', 'op:test', 'tenantId', v_ta, 'service', 'plorder', 'feature', 'a'), 'entitle a');
    PERFORM pg_temp.ok('entitlement_grant', jsonb_build_object('actor', 'op:test', 'tenantId', v_tb, 'service', 'plorder'), 'entitle B');

    v_boss  := pg_temp.ok('tenant_role_define', jsonb_build_object('actor', 'adm-a', 'tenantId', v_ta, 'name', 'Meistars'), 'define Meistars')->>'id';
    v_crew  := pg_temp.ok('tenant_role_define', jsonb_build_object('actor', 'adm-a', 'tenantId', v_ta, 'name', 'Strādnieks'), 'define Strādnieks')->>'id';
    v_empty := pg_temp.ok('tenant_role_define', jsonb_build_object('actor', 'adm-a', 'tenantId', v_ta, 'name', 'Viesis'), 'define Viesis')->>'id';
    v_rb    := pg_temp.ok('tenant_role_define', jsonb_build_object('actor', 'adm-b', 'tenantId', v_tb, 'name', 'Meistars'), 'define B role')->>'id';
    PERFORM pg_temp.ok('tenant_role_permissions_set', jsonb_build_object('actor', 'adm-a', 'tenantId', v_ta, 'roleId', v_boss,
        'permissions', '["plorder/ab:c", "plorder/a/b:d", "plorder/hidden:view", "plpeople/person:view"]'::jsonb), 'tick Meistars');
    PERFORM pg_temp.ok('tenant_role_permissions_set', jsonb_build_object('actor', 'adm-a', 'tenantId', v_ta, 'roleId', v_crew,
        'permissions', '["plorder/ab:c"]'::jsonb), 'tick Strādnieks');
    PERFORM pg_temp.ok('tenant_role_permissions_set', jsonb_build_object('actor', 'adm-b', 'tenantId', v_tb, 'roleId', v_rb,
        'permissions', '["plorder/hidden:view"]'::jsonb), 'tick B');

    -- A person granted Meistars across the tenant, to compare the read against.
    v_holder := pg_temp.ok('user_invite', jsonb_build_object('actor', 'adm-a', 'tenantId', v_ta, 'subjectKey', v_subs[1],
        'displayName', 'Holder', 'roles', '[]'::jsonb), 'invite holder')->>'id';
    PERFORM pg_temp.ok('claim_attach', jsonb_build_object('actor', 'pl-test', 'subjectKey', v_subs[1]), 'claim holder');
    PERFORM pg_temp.ok('tenant_role_grant', jsonb_build_object('actor', 'adm-a', 'tenantId', v_ta, 'userId', v_holder, 'roleId', v_boss), 'grant Meistars');

    -- Two member services of A and one of B, the way a product's service joins a tenant.
    v_svc  := pg_temp.ok('user_invite', jsonb_build_object('actor', 'adm-a', 'tenantId', v_ta, 'subjectKey', 'svc:pl-orders',
        'displayName', 'Orders service', 'roles', '[]'::jsonb), 'invite service')->>'id';
    v_svc2 := pg_temp.ok('user_invite', jsonb_build_object('actor', 'adm-a', 'tenantId', v_ta, 'subjectKey', 'svc:pl-crew',
        'displayName', 'Crew service', 'roles', '[]'::jsonb), 'invite second service')->>'id';
    v_svcb := pg_temp.ok('user_invite', jsonb_build_object('actor', 'adm-b', 'tenantId', v_tb, 'subjectKey', 'svc:pl-orders',
        'displayName', 'Orders service', 'roles', '[]'::jsonb), 'invite service in B')->>'id';
    PERFORM pg_temp.ok('claim_attach', jsonb_build_object('actor', 'pl-test', 'subjectKey', 'svc:pl-orders'), 'claim service');
    PERFORM pg_temp.ok('claim_attach', jsonb_build_object('actor', 'pl-test', 'subjectKey', 'svc:pl-crew'), 'claim second service');

    -- 1. THE READ: every role of A, in id order, none of B's.
    v_defs := pg_temp.ok('tenant_role_definitions', jsonb_build_object('tenantId', v_ta), 'read A');
    PERFORM pg_temp.is(v_defs->>'tenantId', v_ta, 'the read names its tenant');
    PERFORM pg_temp.is(pg_temp.texts(jsonb_path_query_array(v_defs, '$.roles[*].id')),
        (SELECT array_agg(x ORDER BY x COLLATE "C") FROM unnest(ARRAY[v_boss, v_crew, v_empty]) x), 'A''s roles, in id order');
    PERFORM pg_temp.is(pg_temp.role_in(v_defs, v_rb), NULL::jsonb, 'another tenant''s role');
    PERFORM pg_temp.is(pg_temp.role_in(v_defs, v_boss)->>'name', 'Meistars', 'the role''s name travels');

    -- 2. Only what the tenant has, in byte order whatever the collation.
    PERFORM pg_temp.is(pg_temp.texts(pg_temp.role_in(v_defs, v_boss)->'permissions'),
        ARRAY['plorder/a/b:d', 'plorder/ab:c'], 'Meistars carries its entitled ticks in byte order');
    PERFORM pg_temp.is(pg_temp.texts(pg_temp.role_in(v_defs, v_empty)->'permissions'), ARRAY[]::text[], 'a role ticking nothing');

    -- 3. The same set resolve gives a person granted the role across the tenant.
    PERFORM pg_temp.is(pg_temp.texts(pg_temp.role_in(v_defs, v_boss)->'permissions'), pg_temp.scopes(v_subs[1], v_ta),
        'the read and resolve agree on what Meistars carries');

    -- 4. Entitlement moves the read with no change to a role.
    PERFORM pg_temp.ok('entitlement_grant', jsonb_build_object('actor', 'op:test', 'tenantId', v_ta, 'service', 'plpeople'), 'entitle plpeople');
    v_defs := pg_temp.ok('tenant_role_definitions', jsonb_build_object('tenantId', v_ta), 'read A again');
    PERFORM pg_temp.is(pg_temp.texts(pg_temp.role_in(v_defs, v_boss)->'permissions'),
        ARRAY['plorder/a/b:d', 'plorder/ab:c', 'plpeople/person:view'], 'a new entitlement reaches the read');
    PERFORM pg_temp.is(pg_temp.texts(pg_temp.role_in(v_defs, v_boss)->'permissions'), pg_temp.scopes(v_subs[1], v_ta),
        'still the same set as resolve');

    -- 5. Refusals of the read.
    PERFORM pg_temp.refused('tenant_role_definitions', '{}', 'membership:invalid', 'a read with no tenant');
    PERFORM pg_temp.refused('tenant_role_definitions', jsonb_build_object('tenantId', util.generate_ulid()), 'tenant:not_found', 'a tenant that does not exist');

    -- 6. A REPORT: one role placed twelve times, one zero, an id that is nobody's
    --    role and B's role. Only the placed role is stored; the rest comes back.
    SELECT count(*) INTO v_events FROM rolebyte.event;
    v := pg_temp.ok('tenant_role_placements_set', jsonb_build_object('tenantId', v_ta, 'reporterId', v_svc,
        'placements', jsonb_build_object(v_boss, 12, v_crew, 0, 'no-such-role', 3, v_rb, 1)), 'report');
    PERFORM pg_temp.is(pg_temp.texts(v->'unknown'),
        (SELECT array_agg(x ORDER BY x COLLATE "C") FROM unnest(ARRAY['no-such-role', v_rb]) x), 'unknown ids answered back');
    PERFORM pg_temp.is((SELECT string_agg(tenant_role_id || '=' || placements, ',') FROM rolebyte.tenant_role_placement),
        v_boss || '=12', 'only the placed role is stored');
    PERFORM pg_temp.is((SELECT count(*) FROM rolebyte.event), v_events, 'a report writes no history');

    -- 7. The next report replaces the last one whole.
    PERFORM pg_temp.ok('tenant_role_placements_set', jsonb_build_object('tenantId', v_ta, 'reporterId', v_svc,
        'placements', jsonb_build_object(v_crew, 4)), 'second report');
    PERFORM pg_temp.is((SELECT string_agg(tenant_role_id || '=' || placements, ',') FROM rolebyte.tenant_role_placement),
        v_crew || '=4', 'a role left out of the report counts zero');
    PERFORM pg_temp.ok('tenant_role_placements_set', jsonb_build_object('tenantId', v_ta, 'reporterId', v_svc,
        'placements', jsonb_build_object(v_boss, 12)), 'third report');

    -- 8. Refusals of a report, each changing nothing.
    PERFORM pg_temp.refused('tenant_role_placements_set', jsonb_build_object('tenantId', v_ta, 'reporterId', v_svc,
        'placements', jsonb_build_object(v_boss, -1)), 'membership:invalid', 'a negative count');
    PERFORM pg_temp.refused('tenant_role_placements_set', jsonb_build_object('tenantId', v_ta, 'reporterId', v_svc,
        'placements', jsonb_build_object(v_boss, 1.5)), 'membership:invalid', 'a fraction');
    PERFORM pg_temp.refused('tenant_role_placements_set', jsonb_build_object('tenantId', v_ta, 'reporterId', v_svc,
        'placements', jsonb_build_object(v_boss, '3')), 'membership:invalid', 'a count written as text');
    PERFORM pg_temp.refused('tenant_role_placements_set', jsonb_build_object('tenantId', v_ta, 'reporterId', v_svc,
        'placements', jsonb_build_array(v_boss)), 'membership:invalid', 'a list instead of counts');
    PERFORM pg_temp.refused('tenant_role_placements_set', jsonb_build_object('tenantId', v_ta,
        'placements', '{}'::jsonb), 'membership:invalid', 'no reporter');
    PERFORM pg_temp.refused('tenant_role_placements_set', jsonb_build_object('tenantId', v_ta, 'reporterId', v_svcb,
        'placements', '{}'::jsonb), 'membership:notMember', 'a member of another tenant');

    -- 9. Placed, the role cannot be deleted, and the refusal says by whom.
    v_msg := pg_temp.refused('tenant_role_delete', jsonb_build_object('actor', 'adm-a', 'tenantId', v_ta, 'roleId', v_boss),
        'membership:conflict', 'deleting a held and placed role');
    PERFORM pg_temp.is(v_msg, 'this role is held by 1 person and placed 12 times by Orders service; revoke it and move those placements first',
        'held and placed, both counts');
    PERFORM pg_temp.ok('tenant_role_revoke', jsonb_build_object('actor', 'adm-a', 'tenantId', v_ta, 'userId', v_holder, 'roleId', v_boss), 'revoke Meistars');
    PERFORM pg_temp.ok('tenant_role_placements_set', jsonb_build_object('tenantId', v_ta, 'reporterId', v_svc2,
        'placements', jsonb_build_object(v_boss, 1)), 'the second service places it once');
    v_msg := pg_temp.refused('tenant_role_delete', jsonb_build_object('actor', 'adm-a', 'tenantId', v_ta, 'roleId', v_boss),
        'membership:conflict', 'deleting a placed role');
    PERFORM pg_temp.is(v_msg, 'this role is placed 13 times by Crew service, Orders service; move those placements to another role first',
        'placed by two services, summed and both named');

    -- 10. A retired service's count no longer holds the role.
    PERFORM pg_temp.ok('user_revoke', jsonb_build_object('actor', 'adm-a', 'tenantId', v_ta, 'userId', v_svc2), 'retire the second service');
    v_msg := pg_temp.refused('tenant_role_delete', jsonb_build_object('actor', 'adm-a', 'tenantId', v_ta, 'roleId', v_boss),
        'membership:conflict', 'still placed by the first');
    PERFORM pg_temp.is(v_msg, 'this role is placed 12 times by Orders service; move those placements to another role first',
        'only the active service counts');
    PERFORM pg_temp.refused('tenant_role_placements_set', jsonb_build_object('tenantId', v_ta, 'reporterId', v_svc2,
        'placements', '{}'::jsonb), 'membership:notMember', 'a retired service reporting');

    -- 11. Reported at zero, the delete goes through and takes the retired count with it.
    PERFORM pg_temp.ok('tenant_role_placements_set', jsonb_build_object('tenantId', v_ta, 'reporterId', v_svc,
        'placements', jsonb_build_object(v_boss, 0)), 'moved away');
    PERFORM pg_temp.ok('tenant_role_delete', jsonb_build_object('actor', 'adm-a', 'tenantId', v_ta, 'roleId', v_boss), 'delete Meistars');
    PERFORM pg_temp.is((SELECT count(*) FROM rolebyte.tenant_role_placement WHERE tenant_role_id = v_boss), 0::bigint,
        'no count outlives its role');

    -- 12. A report naming the deleted role gets it back as unknown.
    v := pg_temp.ok('tenant_role_placements_set', jsonb_build_object('tenantId', v_ta, 'reporterId', v_svc,
        'placements', jsonb_build_object(v_boss, 2)), 'a late report');
    PERFORM pg_temp.is(pg_temp.texts(v->'unknown'), ARRAY[v_boss], 'a deleted role comes back as unknown');

    RAISE NOTICE 'unit.rolebyte_placement: ALL PASSED';
END $$;

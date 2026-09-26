-- Unit test: what a tenant has decides which of its roles' ticks reach a token.
-- A tick whose feature the tenant does not have resolves to nothing; entitling
-- it makes it appear with no change to any role; a feature covers the features
-- nested under it, and only in its own service; revoking deletes no tick, and
-- entitling again gives back exactly the same set; another tenant is untouched;
-- every write is an event naming the operator; a name that does not exist is
-- refused; and a person who holds only service roles resolves byte for byte as
-- the register did before tenant roles reached a token.
--   psql -v ON_ERROR_STOP=1 -f migrations/testing/tests/unit.rolebyte_entitlement.sql

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

-- The call must be refused with this code, and change nothing.
CREATE OR REPLACE FUNCTION pg_temp.refused(p_proc text, p_in jsonb, p_code text, p_why text) RETURNS void
LANGUAGE plpgsql AS $$
DECLARE
    v      jsonb;
    before text;
    after  text;
BEGIN
    SELECT format('%s/%s', (SELECT string_agg(id || state, ',' ORDER BY id) FROM rolebyte.tenant_entitlement),
                           (SELECT count(*) FROM rolebyte.event)) INTO before;
    v := pg_temp.rb(p_proc, p_in);
    IF v->>'result' IS DISTINCT FROM 'error' OR v->>'code' IS DISTINCT FROM p_code THEN
        RAISE EXCEPTION '% should be refused %: %', p_why, p_code, v;
    END IF;
    SELECT format('%s/%s', (SELECT string_agg(id || state, ',' ORDER BY id) FROM rolebyte.tenant_entitlement),
                           (SELECT count(*) FROM rolebyte.event)) INTO after;
    IF after IS DISTINCT FROM before THEN
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

DO $$
DECLARE
    v_ta    text;
    v_tb    text;
    v_role  text;
    v_rb    text;
    v_s     text[] := ARRAY(SELECT 'sub:' || util.generate_ulid() FROM generate_series(1, 3));
    v_u     text;
    v_ub    text;
    v_first text;
    v_ticks bigint;
    v_full  text[];
    v       jsonb;
    ALL_FOUR CONSTANT text[] := ARRAY['esdemo/task:view', 'esdemo/task/attachment:delete',
                                      'esdemo/spentTime:view', 'esaddon/workforce/person:view'];
BEGIN
    -- Three services: two whose boxes a role ticks, and a third that declares a
    -- feature of the same name as one of the first's.
    PERFORM pg_temp.ok('service_register', '{"actor":"ent-test","service":"esdemo","displayName":"Work"}', 'register esdemo');
    PERFORM pg_temp.ok('service_register', '{"actor":"ent-test","service":"esaddon","displayName":"People"}', 'register esaddon');
    PERFORM pg_temp.ok('service_register', '{"actor":"ent-test","service":"esother","displayName":"Other"}', 'register esother');
    PERFORM pg_temp.ok('role_define', '{"actor":"ent-test","service":"esdemo","group":"esdemo","level":"read"}', 'define esdemo:read');
    PERFORM pg_temp.ok('permission_declare', '{"actor":"ent-test","service":"esdemo","permission":{"feature":"task","act":"view","class":"ordinary"}}', 'declare task:view');
    PERFORM pg_temp.ok('permission_declare', '{"actor":"ent-test","service":"esdemo","permission":{"feature":"task/attachment","act":"delete","class":"ordinary"}}', 'declare attachment:delete');
    PERFORM pg_temp.ok('permission_declare', '{"actor":"ent-test","service":"esdemo","permission":{"feature":"spentTime","act":"view","class":"ordinary"}}', 'declare spentTime:view');
    PERFORM pg_temp.ok('permission_declare', '{"actor":"ent-test","service":"esaddon","permission":{"feature":"workforce/person","act":"view","class":"ordinary"}}', 'declare person:view');
    PERFORM pg_temp.ok('permission_declare', '{"actor":"ent-test","service":"esother","permission":{"feature":"spentTime","act":"view","class":"ordinary"}}', 'declare other spentTime:view');

    v_ta := pg_temp.ok('tenant_create', '{"actor":"ent-test","name":"Entitlement A"}', 'tenant A')->>'id';
    v_tb := pg_temp.ok('tenant_create', '{"actor":"ent-test","name":"Entitlement B"}', 'tenant B')->>'id';

    -- Person 1 holds a service role only; person 2 a tenant role ticking four
    -- boxes across two services; person 3, in B, B's own role.
    PERFORM pg_temp.ok('user_invite', jsonb_build_object('actor', 'adm-a', 'tenantId', v_ta, 'subjectKey', v_s[1],
        'displayName', 'Service roles only', 'roles', '[{"service":"esdemo","group":"esdemo","level":"read"}]'::jsonb), 'invite 1');
    v_u := pg_temp.ok('user_invite', jsonb_build_object('actor', 'adm-a', 'tenantId', v_ta, 'subjectKey', v_s[2],
        'displayName', 'Tenant role', 'roles', '[]'::jsonb), 'invite 2')->>'id';
    v_ub := pg_temp.ok('user_invite', jsonb_build_object('actor', 'adm-b', 'tenantId', v_tb, 'subjectKey', v_s[3],
        'displayName', 'In B', 'roles', '[]'::jsonb), 'invite 3')->>'id';
    FOR i IN 1..3 LOOP
        PERFORM pg_temp.ok('claim_attach', jsonb_build_object('actor', 'ent-test', 'subjectKey', v_s[i]), 'claim ' || i);
    END LOOP;
    v_first := pg_temp.resolved(v_s[1])::text;

    -- Ticking a box the tenant does not have is allowed: that is what lets an
    -- entitlement make it appear later with no change to the role.
    v_role := pg_temp.ok('tenant_role_define', jsonb_build_object('actor', 'adm-a', 'tenantId', v_ta, 'name', 'Meistars'), 'define A role')->>'id';
    PERFORM pg_temp.ok('tenant_role_permissions_set', jsonb_build_object('actor', 'adm-a', 'tenantId', v_ta, 'roleId', v_role,
        'permissions', to_jsonb(ALL_FOUR)), 'tick four unentitled boxes');
    PERFORM pg_temp.ok('tenant_role_grant', jsonb_build_object('actor', 'adm-a', 'tenantId', v_ta, 'userId', v_u, 'roleId', v_role), 'grant 2');
    v_rb := pg_temp.ok('tenant_role_define', jsonb_build_object('actor', 'adm-b', 'tenantId', v_tb, 'name', 'Meistars'), 'define B role')->>'id';
    PERFORM pg_temp.ok('tenant_role_permissions_set', jsonb_build_object('actor', 'adm-b', 'tenantId', v_tb, 'roleId', v_rb,
        'permissions', '["esdemo/task:view"]'::jsonb), 'tick B');
    PERFORM pg_temp.ok('tenant_role_grant', jsonb_build_object('actor', 'adm-b', 'tenantId', v_tb, 'userId', v_ub, 'roleId', v_rb), 'grant 3');
    PERFORM pg_temp.ok('entitlement_grant', jsonb_build_object('actor', 'op:test', 'tenantId', v_tb, 'service', 'esdemo'), 'entitle B');
    SELECT count(*) INTO v_ticks FROM rolebyte.tenant_role_permission;

    -- 1. Nothing entitled: the ticks are held and none of them resolves.
    PERFORM pg_temp.holds_exactly(pg_temp.scopes(v_s[2], v_ta), ARRAY[]::text[], 'an unentitled tenant');

    -- 2. A feature covers the features nested under it, and nothing beside it.
    v := pg_temp.ok('entitlement_grant', jsonb_build_object('actor', 'op:test', 'tenantId', v_ta, 'service', 'esdemo', 'feature', 'task'), 'entitle task');
    IF (v->>'changed')::boolean IS NOT TRUE THEN RAISE EXCEPTION 'a first entitlement must change: %', v; END IF;
    PERFORM pg_temp.holds_exactly(pg_temp.scopes(v_s[2], v_ta), ARRAY['esdemo/task:view', 'esdemo/task/attachment:delete'],
        'task covers task/attachment and not spentTime');

    -- 3. A feature of the same name in another service covers nothing here.
    PERFORM pg_temp.ok('entitlement_grant', jsonb_build_object('actor', 'op:test', 'tenantId', v_ta, 'service', 'esother', 'feature', 'spentTime'), 'entitle other spentTime');
    PERFORM pg_temp.holds_exactly(pg_temp.scopes(v_s[2], v_ta), ARRAY['esdemo/task:view', 'esdemo/task/attachment:delete'],
        'another service''s spentTime');

    -- 4. A whole service, with no role changed.
    PERFORM pg_temp.ok('entitlement_grant', jsonb_build_object('actor', 'op:test', 'tenantId', v_ta, 'service', 'esaddon'), 'entitle esaddon');
    PERFORM pg_temp.ok('entitlement_grant', jsonb_build_object('actor', 'op:test', 'tenantId', v_ta, 'service', 'esdemo', 'feature', 'task/attachment'), 'entitle attachment too');
    PERFORM pg_temp.ok('entitlement_grant', jsonb_build_object('actor', 'op:test', 'tenantId', v_ta, 'service', 'esdemo', 'feature', 'spentTime'), 'entitle spentTime');
    v_full := pg_temp.scopes(v_s[2], v_ta);
    PERFORM pg_temp.holds_exactly(v_full, ALL_FOUR, 'every tick, each once, overlapping entitlements');
    IF (SELECT count(*) FROM rolebyte.tenant_role_permission) <> v_ticks THEN
        RAISE EXCEPTION 'entitling changed a role';
    END IF;

    -- 5. Entitling what the tenant has changes nothing.
    v := pg_temp.ok('entitlement_grant', jsonb_build_object('actor', 'op:test', 'tenantId', v_ta, 'service', 'esaddon'), 'entitle esaddon again');
    IF (v->>'changed')::boolean IS NOT FALSE THEN RAISE EXCEPTION 'entitling twice must not change: %', v; END IF;

    -- 6. Revoking one entitlement leaves what another still covers.
    PERFORM pg_temp.ok('entitlement_revoke', jsonb_build_object('actor', 'op:test', 'tenantId', v_ta, 'service', 'esdemo', 'feature', 'task'), 'revoke task');
    PERFORM pg_temp.holds_exactly(pg_temp.scopes(v_s[2], v_ta),
        ARRAY['esdemo/task/attachment:delete', 'esdemo/spentTime:view', 'esaddon/workforce/person:view'], 'after revoking task');

    -- 7. Revoking deletes no tick; entitling again gives back exactly the set.
    PERFORM pg_temp.ok('entitlement_revoke', jsonb_build_object('actor', 'op:test', 'tenantId', v_ta, 'service', 'esdemo', 'feature', 'task/attachment'), 'revoke attachment');
    PERFORM pg_temp.ok('entitlement_revoke', jsonb_build_object('actor', 'op:test', 'tenantId', v_ta, 'service', 'esdemo', 'feature', 'spentTime'), 'revoke spentTime');
    PERFORM pg_temp.ok('entitlement_revoke', jsonb_build_object('actor', 'op:test', 'tenantId', v_ta, 'service', 'esaddon'), 'revoke esaddon');
    PERFORM pg_temp.holds_exactly(pg_temp.scopes(v_s[2], v_ta), ARRAY[]::text[], 'every entitlement revoked');
    IF (SELECT count(*) FROM rolebyte.tenant_role_permission) <> v_ticks THEN
        RAISE EXCEPTION 'revoking an entitlement deleted a tick';
    END IF;
    v := pg_temp.ok('entitlement_revoke', jsonb_build_object('actor', 'op:test', 'tenantId', v_ta, 'service', 'esaddon'), 'revoke esaddon again');
    IF (v->>'changed')::boolean IS NOT FALSE THEN RAISE EXCEPTION 'revoking twice must not change: %', v; END IF;
    PERFORM pg_temp.ok('entitlement_grant', jsonb_build_object('actor', 'op:test', 'tenantId', v_ta, 'service', 'esdemo'), 're-entitle esdemo whole');
    PERFORM pg_temp.ok('entitlement_grant', jsonb_build_object('actor', 'op:test', 'tenantId', v_ta, 'service', 'esaddon'), 're-entitle esaddon');
    PERFORM pg_temp.holds_exactly(pg_temp.scopes(v_s[2], v_ta), v_full, 'revoke and re-entitle round-trips to the same set');

    -- 8. The other tenant saw none of it.
    PERFORM pg_temp.holds_exactly(pg_temp.scopes(v_s[3], v_tb), ARRAY['esdemo/task:view'], 'tenant B');

    -- 9. What exists, and only that, can be named.
    PERFORM pg_temp.refused('entitlement_grant', jsonb_build_object('tenantId', v_ta, 'service', 'esdemo'), 'membership:invalid', 'no actor');
    PERFORM pg_temp.refused('entitlement_grant', jsonb_build_object('actor', 'op:test', 'tenantId', 'nosuchtenant', 'service', 'esdemo'), 'membership:not_found', 'an unknown tenant');
    PERFORM pg_temp.refused('entitlement_grant', jsonb_build_object('actor', 'op:test', 'tenantId', v_ta, 'service', 'esnobody'), 'membership:not_found', 'an unregistered service');
    PERFORM pg_temp.refused('entitlement_grant', jsonb_build_object('actor', 'op:test', 'tenantId', v_ta, 'service', 'esdemo', 'feature', 'Task View'), 'membership:invalid', 'a malformed feature');
    PERFORM pg_temp.refused('entitlement_grant', jsonb_build_object('actor', 'op:test', 'tenantId', v_ta, 'service', 'esdemo', 'feature', 'invoice'), 'membership:not_found', 'an undeclared feature');
    PERFORM pg_temp.refused('entitlement_grant', jsonb_build_object('actor', 'op:test', 'tenantId', v_ta, 'service', 'esdemo', 'feature', 'tas'), 'membership:not_found', 'a prefix that is not a whole segment');
    PERFORM pg_temp.refused('entitlement_revoke', jsonb_build_object('actor', 'op:test', 'tenantId', v_ta, 'service', 'esaddon', 'feature', 'workforce'), 'membership:not_found', 'revoking what was never given');

    -- 10. The list answers what is in force.
    v := pg_temp.ok('entitlement_list', jsonb_build_object('tenantId', v_ta), 'list A');
    IF (SELECT array_agg(x->>'service' || '|' || (x->>'feature') ORDER BY ord)
          FROM jsonb_array_elements(v->'entitlements') WITH ORDINALITY AS t(x, ord))
       IS DISTINCT FROM ARRAY['esaddon|', 'esdemo|', 'esother|spentTime'] THEN
        RAISE EXCEPTION 'the list must answer exactly what is in force, in order: %', v;
    END IF;

    -- 11. Every change is one event naming the operator, in the tenant's history.
    IF (SELECT count(*) FROM rolebyte.event WHERE tenant_id = v_ta AND kind = 'tenantEntitled' AND actor = 'op:test') <> 7
       OR (SELECT count(*) FROM rolebyte.event WHERE tenant_id = v_ta AND kind = 'tenantEntitlementRevoked' AND actor = 'op:test') <> 4 THEN
        RAISE EXCEPTION 'expected 7 entitle and 4 revoke events for A, found % and %',
            (SELECT count(*) FROM rolebyte.event WHERE tenant_id = v_ta AND kind = 'tenantEntitled'),
            (SELECT count(*) FROM rolebyte.event WHERE tenant_id = v_ta AND kind = 'tenantEntitlementRevoked');
    END IF;
    v := pg_temp.ok('history', jsonb_build_object('tenantId', v_ta, 'service', 'esother'), 'A history, one service');
    IF NOT (v->'events' @> '[{"kind":"tenantEntitled","payload":{"service":"esother","feature":"spentTime"}}]'::jsonb) THEN
        RAISE EXCEPTION 'the tenant''s history must show what it was given: %', v;
    END IF;

    -- 12. A person with only service roles resolves byte for byte as before.
    IF pg_temp.resolved(v_s[1])::text IS DISTINCT FROM v_first THEN
        RAISE EXCEPTION 'a service-only person moved: % -> %', v_first, pg_temp.resolved(v_s[1]);
    END IF;
    IF pg_temp.resolved(v_s[1])::text IS DISTINCT FROM pg_temp.resolved_before_tenant_roles(v_s[1])::text THEN
        RAISE EXCEPTION 'a service-only person must resolve as the reference: %', pg_temp.resolved(v_s[1]);
    END IF;

    RAISE NOTICE 'unit.rolebyte_entitlement: all assertions passed';
END $$;

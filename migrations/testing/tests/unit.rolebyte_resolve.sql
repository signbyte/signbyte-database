-- Unit test: resolve answers a tenant role's ticks beside the service roles' levels.
-- A person who holds only service roles resolves byte for byte as the register
-- did before tenant roles reached a token — compared as text against that
-- aggregation, kept below as the reference; a granted tenant role adds each box
-- it ticks as `service/feature:act`; both kinds together give both; a box ticked
-- twice appears once; an empty role, a revoked grant and another membership's
-- role add nothing.
--   psql -v ON_ERROR_STOP=1 -f migrations/testing/tests/unit.rolebyte_resolve.sql

-- Calls one register procedure; the call must succeed; returns its data.
CREATE OR REPLACE FUNCTION pg_temp.ok(p_proc text, p_in jsonb, p_why text) RETURNS jsonb
LANGUAGE plpgsql AS $$
DECLARE
    v jsonb;
BEGIN
    EXECUTE format('CALL rolebyte.%I($1, NULL::jsonb)', p_proc) INTO v USING p_in;
    IF v->>'result' IS DISTINCT FROM 'success' THEN
        RAISE EXCEPTION '% failed: %', p_why, v;
    END IF;
    RETURN v->'data';
END $$;

-- What the register answers now, whole.
CREATE OR REPLACE FUNCTION pg_temp.resolved(p_subject text) RETURNS jsonb
LANGUAGE plpgsql AS $$
DECLARE
    v jsonb;
BEGIN
    CALL rolebyte.resolve(jsonb_build_object('subjectKey', p_subject), v);
    RETURN v;
END $$;

-- What the register answered before a tenant role could reach a token: the
-- resolve body of that time, unchanged apart from being a function. This is the
-- reference the byte-identity is measured against, so it is never edited to
-- follow the procedure.
CREATE OR REPLACE FUNCTION pg_temp.resolved_before_tenant_roles(p_subject text) RETURNS jsonb
LANGUAGE plpgsql AS $$
DECLARE
    v_subject     text;
    v_memberships jsonb;
BEGIN
    v_subject := NULLIF(trim(p_subject), '');
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
        WHERE u.subject_key = v_subject
          AND u.status = 'active'
          AND t.status = 'active'
    ) sub;

    RETURN util.result_success(jsonb_build_object('memberships', v_memberships));
END $$;

-- The subject's answer must be byte-identical to the reference.
CREATE OR REPLACE FUNCTION pg_temp.same_as_before(p_subject text, p_why text) RETURNS void
LANGUAGE plpgsql AS $$
DECLARE
    v_now    text := pg_temp.resolved(p_subject)::text;
    v_before text := pg_temp.resolved_before_tenant_roles(p_subject)::text;
BEGIN
    IF v_now IS DISTINCT FROM v_before THEN
        RAISE EXCEPTION '% must resolve exactly as before tenant roles: now %, before %', p_why, v_now, v_before;
    END IF;
END $$;

-- The scope list of the subject's one membership in a tenant.
CREATE OR REPLACE FUNCTION pg_temp.scopes_in(p_subject text, p_tenant text) RETURNS jsonb
LANGUAGE sql AS $$
    SELECT m->'scopes'
      FROM jsonb_array_elements(pg_temp.resolved(p_subject)->'data'->'memberships') m
     WHERE m->>'tenantId' = p_tenant;
$$;

-- The list must hold exactly these strings, each once, in any order.
CREATE OR REPLACE FUNCTION pg_temp.holds_exactly(p_scopes jsonb, p_expected text[], p_why text) RETURNS void
LANGUAGE plpgsql AS $$
DECLARE
    v_got text[];
BEGIN
    IF p_scopes IS NULL THEN
        RAISE EXCEPTION '%: no membership answered', p_why;
    END IF;
    SELECT COALESCE(array_agg(x ORDER BY x), '{}') INTO v_got FROM jsonb_array_elements_text(p_scopes) x;
    IF v_got IS DISTINCT FROM (SELECT COALESCE(array_agg(x ORDER BY x), '{}') FROM unnest(p_expected) x) THEN
        RAISE EXCEPTION '%: expected exactly %, got %', p_why, p_expected, p_scopes;
    END IF;
END $$;

DO $$
DECLARE
    v_ta   text;   -- the tenant whose roles are exercised
    v_tb   text;   -- a second tenant one person also belongs to
    v_tc   text;   -- a tenant that is suspended
    v_role_ticks text;  -- ticks two boxes of the work service
    v_role_more  text;  -- ticks one of the same boxes and one of the addon's
    v_role_empty text;  -- ticks nothing
    v_s    text[];     -- subject keys, by person
    v_u    text[];     -- user ids in tenant A, by person
    v_ub   text;       -- the two-tenant person's user id in tenant B
    v_first text;      -- the service-only person's answer before any tenant role exists
    v_n    int;
    k      text;
BEGIN
    -- Two services: one declares roles and permissions, the other permissions only.
    PERFORM pg_temp.ok('service_register', '{"actor":"resolve-test","service":"rsdemo","displayName":"Work"}', 'register rsdemo');
    PERFORM pg_temp.ok('service_register', '{"actor":"resolve-test","service":"rsaddon","displayName":"People"}', 'register rsaddon');
    PERFORM pg_temp.ok('role_define', '{"actor":"resolve-test","service":"rsdemo","group":"rsdemo","level":"read"}', 'define rsdemo:read');
    PERFORM pg_temp.ok('role_define', '{"actor":"resolve-test","service":"rsdemo","group":"rsdemo","level":"write"}', 'define rsdemo:write');
    PERFORM pg_temp.ok('role_define', '{"actor":"resolve-test","service":"rsdemo","group":"rsreport","level":"view"}', 'define rsreport:view');
    PERFORM pg_temp.ok('permission_declare', '{"actor":"resolve-test","service":"rsdemo","permission":{"feature":"task","act":"view","class":"ordinary"}}', 'declare task:view');
    PERFORM pg_temp.ok('permission_declare', '{"actor":"resolve-test","service":"rsdemo","permission":{"feature":"spentTime","act":"view","class":"ordinary"}}', 'declare spentTime:view');
    PERFORM pg_temp.ok('permission_declare', '{"actor":"resolve-test","service":"rsaddon","permission":{"feature":"workforce/person","act":"view","class":"ordinary"}}', 'declare person:view');

    v_ta := pg_temp.ok('tenant_create', '{"actor":"resolve-test","name":"Resolve A"}', 'tenant A')->>'id';
    v_tb := pg_temp.ok('tenant_create', '{"actor":"resolve-test","name":"Resolve B"}', 'tenant B')->>'id';
    v_tc := pg_temp.ok('tenant_create', '{"actor":"resolve-test","name":"Resolve C"}', 'tenant C')->>'id';

    -- Eleven people in tenant A, each claimed (active) unless stated.
    --  1 service roles only (two of one group, one of another)
    --  2 a service role granted, then revoked, beside one kept
    --  3 in A and in B, service roles in each
    --  4 invited, never claimed
    --  5 membership revoked
    --  6 tenant role with two ticks
    --  7 a service role and that tenant role
    --  8 two tenant roles sharing a box
    --  9 only the empty tenant role
    -- 10 that tenant role, granted and then revoked
    -- 11 service roles, and later that tenant role granted and revoked again
    v_s := ARRAY(SELECT 'sub:' || util.generate_ulid() FROM generate_series(1, 11));
    FOR i IN 1..11 LOOP
        v_u[i] := pg_temp.ok('user_invite', jsonb_build_object('actor', 'adm-a', 'tenantId', v_ta,
            'subjectKey', v_s[i], 'displayName', 'Person ' || i,
            'roles', CASE
                WHEN i IN (1, 11) THEN '[{"service":"rsdemo","group":"rsdemo","level":"read"},{"service":"rsdemo","group":"rsdemo","level":"write"},{"service":"rsdemo","group":"rsreport","level":"view"}]'::jsonb
                WHEN i IN (2, 3, 5, 7) THEN '[{"service":"rsdemo","group":"rsdemo","level":"read"}]'::jsonb
                ELSE '[]'::jsonb END), 'invite person ' || i)->>'id';
    END LOOP;
    v_ub := pg_temp.ok('user_invite', jsonb_build_object('actor', 'adm-b', 'tenantId', v_tb,
        'subjectKey', v_s[3], 'displayName', 'Person 3 in B',
        'roles', '[{"service":"rsdemo","group":"rsreport","level":"view"}]'::jsonb), 'invite person 3 in B')->>'id';
    -- Person 1 is also in the suspended tenant, with a role there.
    PERFORM pg_temp.ok('user_invite', jsonb_build_object('actor', 'adm-c', 'tenantId', v_tc,
        'subjectKey', v_s[1], 'displayName', 'Person 1 in C',
        'roles', '[{"service":"rsdemo","group":"rsdemo","level":"write"}]'::jsonb), 'invite person 1 in C');
    FOR i IN 1..11 LOOP
        IF i <> 4 THEN
            PERFORM pg_temp.ok('claim_attach', jsonb_build_object('actor', 'resolve-test', 'subjectKey', v_s[i]), 'claim ' || i);
        END IF;
    END LOOP;
    PERFORM pg_temp.ok('role_grant', jsonb_build_object('actor', 'adm-a', 'tenantId', v_ta, 'userId', v_u[2],
        'service', 'rsdemo', 'group', 'rsdemo', 'level', 'write'), 'grant person 2 write');
    PERFORM pg_temp.ok('role_revoke', jsonb_build_object('actor', 'adm-a', 'tenantId', v_ta, 'userId', v_u[2],
        'service', 'rsdemo', 'group', 'rsdemo', 'level', 'write'), 'revoke person 2 write');
    PERFORM pg_temp.ok('user_revoke', jsonb_build_object('actor', 'adm-a', 'tenantId', v_ta, 'userId', v_u[5]), 'revoke person 5');
    UPDATE rolebyte.tenant SET status = 'suspended' WHERE id = v_tc;

    -- 1. Before any tenant role exists, every service-only person resolves as before.
    v_first := pg_temp.resolved(v_s[1])::text;
    FOREACH k IN ARRAY v_s[1:5] LOOP
        PERFORM pg_temp.same_as_before(k, 'a service-only person, before tenant roles exist');
    END LOOP;
    PERFORM pg_temp.same_as_before('sub:' || util.generate_ulid(), 'a stranger');
    -- The fixture says what it claims: person 1 has one active membership with three
    -- levels (the suspended tenant's is absent), person 3 two memberships.
    PERFORM pg_temp.holds_exactly(pg_temp.scopes_in(v_s[1], v_ta), ARRAY['rsdemo:read', 'rsdemo:write', 'rsreport:view'], 'person 1');
    IF jsonb_array_length(pg_temp.resolved(v_s[1])->'data'->'memberships') <> 1 THEN
        RAISE EXCEPTION 'the suspended tenant must not resolve: %', pg_temp.resolved(v_s[1]);
    END IF;
    IF jsonb_array_length(pg_temp.resolved(v_s[3])->'data'->'memberships') <> 2 THEN
        RAISE EXCEPTION 'person 3 must resolve in two tenants: %', pg_temp.resolved(v_s[3]);
    END IF;

    -- The tenant's roles.
    v_role_ticks := pg_temp.ok('tenant_role_define', jsonb_build_object('actor', 'adm-a', 'tenantId', v_ta, 'name', 'Meistars'), 'define ticks')->>'id';
    v_role_more  := pg_temp.ok('tenant_role_define', jsonb_build_object('actor', 'adm-a', 'tenantId', v_ta, 'name', 'Personāls'), 'define more')->>'id';
    v_role_empty := pg_temp.ok('tenant_role_define', jsonb_build_object('actor', 'adm-a', 'tenantId', v_ta, 'name', 'Viesis'), 'define empty')->>'id';
    PERFORM pg_temp.ok('tenant_role_permissions_set', jsonb_build_object('actor', 'adm-a', 'tenantId', v_ta, 'roleId', v_role_ticks,
        'permissions', '["rsdemo/task:view","rsdemo/spentTime:view"]'::jsonb), 'tick two');
    PERFORM pg_temp.ok('tenant_role_permissions_set', jsonb_build_object('actor', 'adm-a', 'tenantId', v_ta, 'roleId', v_role_more,
        'permissions', '["rsdemo/task:view","rsaddon/workforce/person:view"]'::jsonb), 'tick shared + addon');

    PERFORM pg_temp.ok('tenant_role_grant', jsonb_build_object('actor', 'adm-a', 'tenantId', v_ta, 'userId', v_u[6], 'roleId', v_role_ticks), 'grant 6');
    PERFORM pg_temp.ok('tenant_role_grant', jsonb_build_object('actor', 'adm-a', 'tenantId', v_ta, 'userId', v_u[7], 'roleId', v_role_ticks), 'grant 7');
    PERFORM pg_temp.ok('tenant_role_grant', jsonb_build_object('actor', 'adm-a', 'tenantId', v_ta, 'userId', v_u[8], 'roleId', v_role_ticks), 'grant 8a');
    PERFORM pg_temp.ok('tenant_role_grant', jsonb_build_object('actor', 'adm-a', 'tenantId', v_ta, 'userId', v_u[8], 'roleId', v_role_more), 'grant 8b');
    PERFORM pg_temp.ok('tenant_role_grant', jsonb_build_object('actor', 'adm-a', 'tenantId', v_ta, 'userId', v_u[9], 'roleId', v_role_empty), 'grant 9');
    PERFORM pg_temp.ok('tenant_role_grant', jsonb_build_object('actor', 'adm-a', 'tenantId', v_ta, 'userId', v_u[10], 'roleId', v_role_ticks), 'grant 10');
    PERFORM pg_temp.ok('tenant_role_revoke', jsonb_build_object('actor', 'adm-a', 'tenantId', v_ta, 'userId', v_u[10], 'roleId', v_role_ticks), 'revoke 10');
    PERFORM pg_temp.ok('tenant_role_grant', jsonb_build_object('actor', 'adm-a', 'tenantId', v_ta, 'userId', v_u[11], 'roleId', v_role_more), 'grant 11');
    PERFORM pg_temp.ok('tenant_role_revoke', jsonb_build_object('actor', 'adm-a', 'tenantId', v_ta, 'userId', v_u[11], 'roleId', v_role_more), 'revoke 11');
    -- Person 3's membership in A gets the role; their membership in B must not.
    PERFORM pg_temp.ok('tenant_role_grant', jsonb_build_object('actor', 'adm-a', 'tenantId', v_ta, 'userId', v_u[3], 'roleId', v_role_more), 'grant 3 in A');

    -- 2. A tenant role reaches the answer as its ticks, spelled as they travel.
    PERFORM pg_temp.holds_exactly(pg_temp.scopes_in(v_s[6], v_ta), ARRAY['rsdemo/task:view', 'rsdemo/spentTime:view'],
        'a tenant role resolves to its ticks');

    -- 3. Both kinds together give both.
    PERFORM pg_temp.holds_exactly(pg_temp.scopes_in(v_s[7], v_ta), ARRAY['rsdemo:read', 'rsdemo/task:view', 'rsdemo/spentTime:view'],
        'a service role and a tenant role resolve to both');

    -- 4. A box two roles tick appears once, and a role spans services.
    PERFORM pg_temp.holds_exactly(pg_temp.scopes_in(v_s[8], v_ta),
        ARRAY['rsdemo/task:view', 'rsdemo/spentTime:view', 'rsaddon/workforce/person:view'],
        'two roles sharing a box');

    -- 5. An empty role and a revoked grant add nothing; the membership still resolves.
    PERFORM pg_temp.holds_exactly(pg_temp.scopes_in(v_s[9], v_ta), ARRAY[]::text[], 'only an empty role');
    PERFORM pg_temp.holds_exactly(pg_temp.scopes_in(v_s[10], v_ta), ARRAY[]::text[], 'a revoked tenant-role grant');

    -- 6. A role granted in one membership reaches that membership only.
    PERFORM pg_temp.holds_exactly(pg_temp.scopes_in(v_s[3], v_ta),
        ARRAY['rsdemo:read', 'rsdemo/task:view', 'rsaddon/workforce/person:view'], 'person 3 in A');
    PERFORM pg_temp.holds_exactly(pg_temp.scopes_in(v_s[3], v_tb), ARRAY['rsreport:view'],
        'person 3 in B holds nothing of A''s role');

    -- 7. Reconfiguring the role changes what its holders resolve to, at once.
    PERFORM pg_temp.ok('tenant_role_permissions_set', jsonb_build_object('actor', 'adm-a', 'tenantId', v_ta, 'roleId', v_role_ticks,
        'permissions', '["rsdemo/spentTime:view"]'::jsonb), 'untick task:view');
    PERFORM pg_temp.holds_exactly(pg_temp.scopes_in(v_s[6], v_ta), ARRAY['rsdemo/spentTime:view'], 'after reconfigure');

    -- 8. After all of it, every person in the register who holds no tenant role
    --    resolves exactly as before — this test's people and every fixture any
    --    earlier test left — and person 1's answer is the one taken at the start.
    v_n := 0;
    FOR k IN
        SELECT DISTINCT u.subject_key FROM rolebyte.user_account u
         WHERE NOT EXISTS (SELECT 1 FROM rolebyte.tenant_role_assignment ta
                            WHERE ta.user_id = u.id AND ta.state = 'granted')
    LOOP
        -- A subject with a granted tenant role in ANOTHER membership is covered by 6.
        CONTINUE WHEN EXISTS (SELECT 1 FROM rolebyte.user_account u2
                               JOIN rolebyte.tenant_role_assignment ta ON ta.user_id = u2.id AND ta.state = 'granted'
                              WHERE u2.subject_key = k);
        PERFORM pg_temp.same_as_before(k, 'subject ' || k);
        v_n := v_n + 1;
    END LOOP;
    IF v_n < 6 THEN
        RAISE EXCEPTION 'the sweep compared only % subjects; this test alone leaves 6 without a tenant role', v_n;
    END IF;
    IF pg_temp.resolved(v_s[1])::text IS DISTINCT FROM v_first THEN
        RAISE EXCEPTION 'person 1 resolved differently after tenant-role writes in the same tenant: %', pg_temp.resolved(v_s[1]);
    END IF;

    RAISE NOTICE 'unit.rolebyte_resolve: all assertions passed (% subjects byte-identical to the reference)', v_n;
END $$;

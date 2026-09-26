-- Unit test: a tenant defines its own roles.
-- A tenant makes, renames, reconfigures and deletes a role made of ticks over
-- declared permissions from more than one service; another tenant of the same
-- deployment is untouched by all four and can reach none of it; every change is
-- an event naming who made it; a role people hold cannot be deleted; a tick can
-- only name a declared permission; and the database itself refuses a grant that
-- joins a person and a role from two tenants.
--   psql -v ON_ERROR_STOP=1 -f migrations/testing/tests/unit.rolebyte_tenant_role.sql

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
    v jsonb;
BEGIN
    v := pg_temp.rb(p_proc, p_in);
    IF v->>'result' IS DISTINCT FROM 'success' THEN
        RAISE EXCEPTION '% failed: %', p_why, v;
    END IF;
    RETURN v->'data';
END $$;

-- The call must be refused with exactly this code, and write nothing: no role,
-- tick, grant or event may change.
CREATE OR REPLACE FUNCTION pg_temp.refused(p_proc text, p_in jsonb, p_code text, p_why text) RETURNS text
LANGUAGE plpgsql AS $$
DECLARE
    v      jsonb;
    before text;
    after  text;
BEGIN
    SELECT format('%s/%s/%s/%s',
                  (SELECT count(*) FROM rolebyte.tenant_role),
                  (SELECT count(*) FROM rolebyte.tenant_role_permission),
                  (SELECT string_agg(id || state, ',' ORDER BY id) FROM rolebyte.tenant_role_assignment),
                  (SELECT count(*) FROM rolebyte.event))
      INTO before;
    v := pg_temp.rb(p_proc, p_in);
    IF v->>'result' IS DISTINCT FROM 'error' OR v->>'code' IS DISTINCT FROM p_code THEN
        RAISE EXCEPTION '% should be refused %: %', p_why, p_code, v;
    END IF;
    SELECT format('%s/%s/%s/%s',
                  (SELECT count(*) FROM rolebyte.tenant_role),
                  (SELECT count(*) FROM rolebyte.tenant_role_permission),
                  (SELECT string_agg(id || state, ',' ORDER BY id) FROM rolebyte.tenant_role_assignment),
                  (SELECT count(*) FROM rolebyte.event))
      INTO after;
    IF after IS DISTINCT FROM before THEN
        RAISE EXCEPTION '% was refused but wrote something (% -> %)', p_why, before, after;
    END IF;
    RETURN v->>'message';
END $$;

-- The one event of this kind about this role, which must name this actor.
CREATE OR REPLACE FUNCTION pg_temp.event_of(p_kind text, p_role text, p_actor text, p_tenant text) RETURNS jsonb
LANGUAGE plpgsql AS $$
DECLARE
    v_payload jsonb;
    v_n       int;
BEGIN
    SELECT count(*), max(payload::text)::jsonb INTO v_n, v_payload
      FROM rolebyte.event
     WHERE kind = p_kind AND payload->>'roleId' = p_role;
    IF v_n <> 1 THEN
        RAISE EXCEPTION 'expected one % event for role %, found %', p_kind, p_role, v_n;
    END IF;
    IF NOT EXISTS (SELECT 1 FROM rolebyte.event
                   WHERE kind = p_kind AND payload->>'roleId' = p_role
                     AND actor = p_actor AND tenant_id = p_tenant) THEN
        RAISE EXCEPTION 'the % event for role % must name actor % and tenant %', p_kind, p_role, p_actor, p_tenant;
    END IF;
    RETURN v_payload;
END $$;

DO $$
DECLARE
    v        jsonb;
    v_msg    text;
    v_ta     text;   -- tenant A, whose roles are exercised
    v_tb     text;   -- tenant B, which must be untouched by all of it
    v_pa1    text;   -- a member of A
    v_pa2    text;   -- a member of A whose access is later revoked
    v_pb1    text;   -- a member of B
    v_role   text;   -- A's role
    v_other  text;   -- A's second role
    v_long   text;
    v_rb     text;   -- B's role
    v_events int;
    v_b_before text;
BEGIN
    -- Two services declare what a role may tick: a role spans both.
    PERFORM pg_temp.ok('service_register', '{"actor":"tenant-role-test","service":"trdemo","displayName":"Work"}', 'register trdemo');
    PERFORM pg_temp.ok('service_register', '{"actor":"tenant-role-test","service":"traddon","displayName":"People"}', 'register traddon');
    PERFORM pg_temp.ok('permission_declare', '{"actor":"tenant-role-test","service":"trdemo","permission":{"feature":"task","act":"view","class":"ordinary"}}', 'declare task:view');
    PERFORM pg_temp.ok('permission_declare', '{"actor":"tenant-role-test","service":"trdemo","permission":{"feature":"task","act":"edit","class":"ordinary"}}', 'declare task:edit');
    PERFORM pg_temp.ok('permission_declare', '{"actor":"tenant-role-test","service":"trdemo","permission":{"feature":"task/attachment","act":"deleteAny","class":"ordinary"}}', 'declare attachment:deleteAny');
    PERFORM pg_temp.ok('permission_declare', '{"actor":"tenant-role-test","service":"traddon","permission":{"feature":"workforce/person","act":"view","class":"ordinary"}}', 'declare person:view');

    v_ta := pg_temp.ok('tenant_create', '{"actor":"tenant-role-test","name":"Tenant roles A"}', 'tenant A')->>'id';
    v_tb := pg_temp.ok('tenant_create', '{"actor":"tenant-role-test","name":"Tenant roles B"}', 'tenant B')->>'id';
    -- Tenant A has both services, so a granted role's ticks reach what its holder
    -- resolves to. What an entitlement withholds is unit.rolebyte_entitlement's.
    PERFORM pg_temp.ok('entitlement_grant', jsonb_build_object('actor', 'op:tenant-role-test', 'tenantId', v_ta, 'service', 'trdemo'), 'entitle A trdemo');
    PERFORM pg_temp.ok('entitlement_grant', jsonb_build_object('actor', 'op:tenant-role-test', 'tenantId', v_ta, 'service', 'traddon'), 'entitle A traddon');
    v_pa1 := pg_temp.ok('user_invite', jsonb_build_object('actor', 'adm-a', 'tenantId', v_ta,
        'subjectKey', 'sub:' || util.generate_ulid(), 'displayName', 'A member', 'roles', '[]'::jsonb), 'invite pa1')->>'id';
    v_pa2 := pg_temp.ok('user_invite', jsonb_build_object('actor', 'adm-a', 'tenantId', v_ta,
        'subjectKey', 'sub:' || util.generate_ulid(), 'displayName', 'A leaver', 'roles', '[]'::jsonb), 'invite pa2')->>'id';
    v_pb1 := pg_temp.ok('user_invite', jsonb_build_object('actor', 'adm-b', 'tenantId', v_tb,
        'subjectKey', 'sub:' || util.generate_ulid(), 'displayName', 'B member', 'roles', '[]'::jsonb), 'invite pb1')->>'id';

    -- 1. DEFINE. A role is made with a name, a description and nothing ticked, and
    --    the history names who made it.
    v := pg_temp.ok('tenant_role_define', jsonb_build_object('actor', 'adm-a', 'tenantId', v_ta,
        'name', '  Manager  ', 'description', 'Runs a project'), 'define in A');
    v_role := v->>'id';
    IF length(v_role) <> 26 THEN RAISE EXCEPTION 'a role is identified by a generated id: %', v; END IF;
    IF v->>'name' IS DISTINCT FROM 'Manager' THEN RAISE EXCEPTION 'the name is stored trimmed: %', v; END IF;
    IF v->'permissions' IS DISTINCT FROM '[]'::jsonb THEN RAISE EXCEPTION 'a new role holds nothing: %', v; END IF;
    v := pg_temp.event_of('tenantRoleDefined', v_role, 'adm-a', v_ta);
    IF v->>'name' IS DISTINCT FROM 'Manager' OR v->>'description' IS DISTINCT FROM 'Runs a project' THEN
        RAISE EXCEPTION 'the definition event carries the label: %', v;
    END IF;

    -- A name is unique in its tenant, ignoring case — and only in its tenant.
    PERFORM pg_temp.refused('tenant_role_define', jsonb_build_object('actor', 'adm-a', 'tenantId', v_ta, 'name', 'MANAGER'),
        'membership:conflict', 'the same name in another case');
    v_rb := pg_temp.ok('tenant_role_define', jsonb_build_object('actor', 'adm-b', 'tenantId', v_tb,
        'name', 'Manager', 'description', 'B''s own'), 'the same name in tenant B')->>'id';
    IF v_rb = v_role THEN RAISE EXCEPTION 'two tenants must get two roles'; END IF;

    -- Every malformed definition is refused and stores nothing.
    PERFORM pg_temp.refused('tenant_role_define', jsonb_build_object('tenantId', v_ta, 'name', 'X'),
        'membership:invalid', 'no actor');
    PERFORM pg_temp.refused('tenant_role_define', jsonb_build_object('actor', 'adm-a', 'name', 'X'),
        'membership:invalid', 'no tenant');
    PERFORM pg_temp.refused('tenant_role_define', jsonb_build_object('actor', 'adm-a', 'tenantId', v_ta),
        'membership:invalid', 'no name');
    PERFORM pg_temp.refused('tenant_role_define', jsonb_build_object('actor', 'adm-a', 'tenantId', v_ta, 'name', 5),
        'membership:invalid', 'a name that is not a string');
    PERFORM pg_temp.refused('tenant_role_define', jsonb_build_object('actor', 'adm-a', 'tenantId', v_ta, 'name', '   '),
        'membership:invalid', 'a blank name');
    PERFORM pg_temp.refused('tenant_role_define', jsonb_build_object('actor', 'adm-a', 'tenantId', v_ta,
        'name', 'Two' || chr(10) || 'lines'), 'membership:invalid', 'a name with a line break');
    PERFORM pg_temp.refused('tenant_role_define', jsonb_build_object('actor', 'adm-a', 'tenantId', v_ta,
        'name', repeat('n', 101)), 'membership:invalid', 'a 101-character name');
    PERFORM pg_temp.refused('tenant_role_define', jsonb_build_object('actor', 'adm-a', 'tenantId', v_ta,
        'name', 'Long description', 'description', repeat('d', 1001)), 'membership:invalid', 'a 1001-character description');
    PERFORM pg_temp.refused('tenant_role_define', jsonb_build_object('actor', 'adm-a', 'tenantId', v_ta,
        'name', 'Numeric description', 'description', 7), 'membership:invalid', 'a description that is not a string');
    PERFORM pg_temp.refused('tenant_role_define', jsonb_build_object('actor', 'adm-a', 'tenantId', util.generate_ulid(),
        'name', 'Nowhere'), 'tenant:not_found', 'an unknown tenant');

    -- The boundaries themselves are allowed.
    v_long := pg_temp.ok('tenant_role_define', jsonb_build_object('actor', 'adm-a', 'tenantId', v_ta,
        'name', repeat('n', 100), 'description', repeat('d', 1000)), 'a 100-character name')->>'id';

    -- 2. RENAME. The label changes, the id does not, and the event says from what to what.
    v := pg_temp.ok('tenant_role_update', jsonb_build_object('actor', 'adm-a', 'tenantId', v_ta,
        'roleId', v_role, 'name', 'Meistars'), 'rename');
    IF (v->>'changed')::boolean IS NOT TRUE OR v->>'id' IS DISTINCT FROM v_role THEN
        RAISE EXCEPTION 'a rename changes the label and keeps the id: %', v;
    END IF;
    IF v->>'description' IS DISTINCT FROM 'Runs a project' THEN
        RAISE EXCEPTION 'an absent description keeps the one there: %', v;
    END IF;
    v := pg_temp.event_of('tenantRoleRenamed', v_role, 'adm-a', v_ta);
    IF v->>'from' IS DISTINCT FROM 'Manager' OR v->>'to' IS DISTINCT FROM 'Meistars' THEN
        RAISE EXCEPTION 'the rename event says from what to what: %', v;
    END IF;

    -- The same label again changes nothing and records nothing.
    SELECT count(*) INTO v_events FROM rolebyte.event;
    v := pg_temp.ok('tenant_role_update', jsonb_build_object('actor', 'adm-a', 'tenantId', v_ta,
        'roleId', v_role, 'name', 'Meistars', 'description', 'Runs a project'), 'the same label');
    IF (v->>'changed')::boolean IS NOT FALSE OR (SELECT count(*) FROM rolebyte.event) <> v_events THEN
        RAISE EXCEPTION 'an unchanged label must record nothing: %', v;
    END IF;

    -- A new description alone is its own event; an empty one clears it.
    v := pg_temp.ok('tenant_role_update', jsonb_build_object('actor', 'adm-a', 'tenantId', v_ta,
        'roleId', v_role, 'name', 'Meistars', 'description', ''), 'clear the description');
    IF v->>'description' IS DISTINCT FROM '' OR (v->>'changed')::boolean IS NOT TRUE THEN
        RAISE EXCEPTION 'an empty description clears it: %', v;
    END IF;
    v := pg_temp.event_of('tenantRoleDescribed', v_role, 'adm-a', v_ta);
    IF v->>'from' IS DISTINCT FROM 'Runs a project' OR v->>'to' IS DISTINCT FROM '' THEN
        RAISE EXCEPTION 'the description event says from what to what: %', v;
    END IF;
    IF EXISTS (SELECT 1 FROM rolebyte.event WHERE kind = 'tenantRoleRenamed' AND payload->>'roleId' = v_role
                  AND payload->>'to' <> 'Meistars') THEN
        RAISE EXCEPTION 'a description change must not record a rename';
    END IF;

    -- A change of letter case is a rename of this role, not a clash with itself;
    -- taking another role's name is a clash.
    v := pg_temp.ok('tenant_role_update', jsonb_build_object('actor', 'adm-a', 'tenantId', v_ta,
        'roleId', v_role, 'name', 'MEISTARS'), 'a case-only rename');
    IF (v->>'changed')::boolean IS NOT TRUE THEN RAISE EXCEPTION 'a case-only rename is a change: %', v; END IF;
    v := pg_temp.ok('tenant_role_update', jsonb_build_object('actor', 'adm-a', 'tenantId', v_ta,
        'roleId', v_role, 'name', 'Meistars'), 'back to the name');
    v_other := pg_temp.ok('tenant_role_define', jsonb_build_object('actor', 'adm-a', 'tenantId', v_ta,
        'name', 'Worker'), 'a second role in A')->>'id';
    PERFORM pg_temp.refused('tenant_role_update', jsonb_build_object('actor', 'adm-a', 'tenantId', v_ta,
        'roleId', v_other, 'name', 'meistars'), 'membership:conflict', 'renaming onto another role''s name');
    PERFORM pg_temp.refused('tenant_role_update', jsonb_build_object('actor', 'adm-a', 'tenantId', v_ta,
        'roleId', v_role, 'name', ''), 'membership:invalid', 'a rename to nothing');
    PERFORM pg_temp.refused('tenant_role_update', jsonb_build_object('actor', 'adm-a', 'tenantId', v_ta,
        'roleId', v_role, 'name', 'Meistars', 'description', repeat('d', 1001)), 'membership:invalid', 'a long description');
    PERFORM pg_temp.refused('tenant_role_update', jsonb_build_object('actor', 'adm-a', 'tenantId', v_ta,
        'name', 'Meistars'), 'membership:invalid', 'no role id');
    PERFORM pg_temp.refused('tenant_role_update', jsonb_build_object('actor', 'adm-a', 'tenantId', v_ta,
        'roleId', util.generate_ulid(), 'name', 'Ghost'), 'membership:not_found', 'an unknown role');

    -- ANOTHER TENANT cannot rename it: A's role through B's tenant is not found.
    PERFORM pg_temp.refused('tenant_role_update', jsonb_build_object('actor', 'adm-b', 'tenantId', v_tb,
        'roleId', v_role, 'name', 'Taken over'), 'membership:not_found', 'renaming another tenant''s role');

    -- 3. RECONFIGURE. The whole set is sent; the answer is the new set and the
    --    difference. Ticks come from two services; a name given twice counts once.
    v := pg_temp.ok('tenant_role_permissions_set', jsonb_build_object('actor', 'adm-a', 'tenantId', v_ta,
        'roleId', v_role, 'permissions', '["trdemo/task:edit","traddon/workforce/person:view","trdemo/task:edit"]'::jsonb),
        'the first ticks');
    IF v->'permissions' IS DISTINCT FROM '["traddon/workforce/person:view","trdemo/task:edit"]'::jsonb THEN
        RAISE EXCEPTION 'the role holds both services'' ticks, each once, in order: %', v;
    END IF;
    IF v->'added' IS DISTINCT FROM v->'permissions' OR v->'removed' IS DISTINCT FROM '[]'::jsonb
       OR (v->>'changed')::boolean IS NOT TRUE THEN
        RAISE EXCEPTION 'the first ticks are all added: %', v;
    END IF;
    v := pg_temp.event_of('tenantRoleReconfigured', v_role, 'adm-a', v_ta);
    IF v->'added' IS DISTINCT FROM '["traddon/workforce/person:view","trdemo/task:edit"]'::jsonb
       OR v->>'name' IS DISTINCT FROM 'Meistars' THEN
        RAISE EXCEPTION 'the reconfiguration event carries what changed: %', v;
    END IF;

    -- The same set again, in another order, changes nothing and records nothing.
    SELECT count(*) INTO v_events FROM rolebyte.event;
    v := pg_temp.ok('tenant_role_permissions_set', jsonb_build_object('actor', 'adm-a', 'tenantId', v_ta,
        'roleId', v_role, 'permissions', '["traddon/workforce/person:view","trdemo/task:edit"]'::jsonb), 'the same ticks');
    IF (v->>'changed')::boolean IS NOT FALSE OR (SELECT count(*) FROM rolebyte.event) <> v_events THEN
        RAISE EXCEPTION 'the same set must record nothing: %', v;
    END IF;

    -- Swapping one tick answers exactly that.
    v := pg_temp.ok('tenant_role_permissions_set', jsonb_build_object('actor', 'adm-a', 'tenantId', v_ta,
        'roleId', v_role, 'permissions', '["trdemo/task:view","traddon/workforce/person:view","trdemo/task/attachment:deleteAny"]'::jsonb),
        'swap a tick');
    IF v->'added' IS DISTINCT FROM '["trdemo/task:view","trdemo/task/attachment:deleteAny"]'::jsonb
       OR v->'removed' IS DISTINCT FROM '["trdemo/task:edit"]'::jsonb THEN
        RAISE EXCEPTION 'the answer is the difference, feature before sub-feature: %', v;
    END IF;

    -- One unknown name refuses the whole call, and the set stays as it was.
    v_msg := pg_temp.refused('tenant_role_permissions_set', jsonb_build_object('actor', 'adm-a', 'tenantId', v_ta,
        'roleId', v_role, 'permissions', '["trdemo/task:edit","trdemo/task:nuke"]'::jsonb),
        'membership:unknown_permission', 'a tick nobody declared');
    IF v_msg NOT LIKE '%trdemo/task:nuke%' THEN
        RAISE EXCEPTION 'a permission-shaped unknown tick is named: %', v_msg;
    END IF;
    v_msg := pg_temp.refused('tenant_role_permissions_set', jsonb_build_object('actor', 'adm-a', 'tenantId', v_ta,
        'roleId', v_role, 'permissions', '["hello there"]'::jsonb),
        'membership:unknown_permission', 'a tick that is not a permission name');
    IF v_msg LIKE '%hello%' THEN
        RAISE EXCEPTION 'a tick that is not permission-shaped must not be echoed: %', v_msg;
    END IF;
    PERFORM pg_temp.refused('tenant_role_permissions_set', jsonb_build_object('actor', 'adm-a', 'tenantId', v_ta,
        'roleId', v_role, 'permissions', '["/task:view"]'::jsonb), 'membership:unknown_permission', 'no service');
    PERFORM pg_temp.refused('tenant_role_permissions_set', jsonb_build_object('actor', 'adm-a', 'tenantId', v_ta,
        'roleId', v_role, 'permissions', '["trdemo/task"]'::jsonb), 'membership:unknown_permission', 'no act');
    PERFORM pg_temp.refused('tenant_role_permissions_set', jsonb_build_object('actor', 'adm-a', 'tenantId', v_ta,
        'roleId', v_role, 'permissions', '"trdemo/task:view"'::jsonb), 'membership:invalid', 'a set that is not a list');
    PERFORM pg_temp.refused('tenant_role_permissions_set', jsonb_build_object('actor', 'adm-a', 'tenantId', v_ta,
        'roleId', v_role, 'permissions', '["trdemo/task:view", 3]'::jsonb), 'membership:invalid', 'a non-string entry');
    PERFORM pg_temp.refused('tenant_role_permissions_set', jsonb_build_object('actor', 'adm-a', 'tenantId', v_ta,
        'roleId', v_role), 'membership:invalid', 'no set at all');
    PERFORM pg_temp.refused('tenant_role_permissions_set', jsonb_build_object('actor', 'adm-a', 'tenantId', v_ta,
        'roleId', util.generate_ulid(), 'permissions', '[]'::jsonb), 'membership:not_found', 'an unknown role');

    -- ANOTHER TENANT cannot reconfigure it.
    PERFORM pg_temp.refused('tenant_role_permissions_set', jsonb_build_object('actor', 'adm-b', 'tenantId', v_tb,
        'roleId', v_role, 'permissions', '[]'::jsonb), 'membership:not_found', 'reconfiguring another tenant''s role');

    -- An empty list clears the role; the removal is the difference.
    v := pg_temp.ok('tenant_role_permissions_set', jsonb_build_object('actor', 'adm-a', 'tenantId', v_ta,
        'roleId', v_other, 'permissions', '["trdemo/task:view"]'::jsonb), 'tick the second role');
    v := pg_temp.ok('tenant_role_permissions_set', jsonb_build_object('actor', 'adm-a', 'tenantId', v_ta,
        'roleId', v_other, 'permissions', '[]'::jsonb), 'clear the second role');
    IF v->'permissions' IS DISTINCT FROM '[]'::jsonb OR v->'removed' IS DISTINCT FROM '["trdemo/task:view"]'::jsonb THEN
        RAISE EXCEPTION 'an empty list clears the role: %', v;
    END IF;

    -- 4. GRANT, by the role's id.
    v := pg_temp.ok('tenant_role_grant', jsonb_build_object('actor', 'adm-a', 'tenantId', v_ta,
        'userId', v_pa1, 'roleId', v_role), 'grant');
    IF (v->>'changed')::boolean IS NOT TRUE THEN RAISE EXCEPTION 'a first grant changes state: %', v; END IF;
    v := pg_temp.ok('tenant_role_grant', jsonb_build_object('actor', 'adm-a', 'tenantId', v_ta,
        'userId', v_pa1, 'roleId', v_role), 'grant again');
    IF (v->>'changed')::boolean IS NOT FALSE THEN RAISE EXCEPTION 're-granting a held role is a no-op: %', v; END IF;
    IF (SELECT count(*) FROM rolebyte.event WHERE kind = 'tenantRoleGranted' AND user_id = v_pa1
          AND actor = 'adm-a' AND tenant_id = v_ta AND payload->>'roleId' = v_role
          AND payload->>'name' = 'Meistars') <> 1 THEN
        RAISE EXCEPTION 'one attributed grant event names the person and the role';
    END IF;

    -- No tenant is crossed by a grant, whichever side is foreign.
    PERFORM pg_temp.refused('tenant_role_grant', jsonb_build_object('actor', 'adm-a', 'tenantId', v_ta,
        'userId', v_pb1, 'roleId', v_role), 'membership:not_found', 'A''s role to B''s person');
    PERFORM pg_temp.refused('tenant_role_grant', jsonb_build_object('actor', 'adm-a', 'tenantId', v_ta,
        'userId', v_pa1, 'roleId', v_rb), 'membership:unknown_role', 'B''s role to A''s person');
    PERFORM pg_temp.refused('tenant_role_grant', jsonb_build_object('actor', 'adm-b', 'tenantId', v_tb,
        'userId', v_pb1, 'roleId', v_role), 'membership:unknown_role', 'A''s role through B''s tenant');
    PERFORM pg_temp.refused('tenant_role_grant', jsonb_build_object('actor', 'adm-a', 'tenantId', v_ta,
        'userId', v_pa1), 'membership:invalid', 'no role id');

    -- Even the owner, writing the table directly, cannot join two tenants.
    BEGIN
        INSERT INTO rolebyte.tenant_role_assignment (id, tenant_id, user_id, tenant_role_id)
        VALUES (util.generate_ulid(), v_ta, v_pb1, v_role);
        RAISE EXCEPTION 'a grant joining B''s person to A''s role was stored';
    EXCEPTION WHEN foreign_key_violation THEN NULL;
    END;
    BEGIN
        INSERT INTO rolebyte.tenant_role_assignment (id, tenant_id, user_id, tenant_role_id)
        VALUES (util.generate_ulid(), v_tb, v_pb1, v_role);
        RAISE EXCEPTION 'a grant of A''s role inside tenant B was stored';
    EXCEPTION WHEN foreign_key_violation THEN NULL;
    END;

    -- The grant reaches what the person resolves to, as the role's ticks. (What
    -- resolve answers in every other case is unit.rolebyte_resolve's.)
    v := pg_temp.ok('claim_attach', jsonb_build_object('actor', 'tenant-role-test',
        'subjectKey', (SELECT subject_key FROM rolebyte.user_account WHERE id = v_pa1)), 'claim pa1');
    v := pg_temp.ok('resolve', jsonb_build_object(
        'subjectKey', (SELECT subject_key FROM rolebyte.user_account WHERE id = v_pa1)), 'resolve pa1');
    IF NOT (v->'memberships'->0->'scopes' @> '["trdemo/task:view","trdemo/task/attachment:deleteAny","traddon/workforce/person:view"]'::jsonb
            AND jsonb_array_length(v->'memberships'->0->'scopes') = 3) THEN
        RAISE EXCEPTION 'a granted tenant role must resolve to exactly its three ticks: %', v;
    END IF;

    -- 5. DELETE. A role somebody holds is refused, with the count, and survives.
    v_msg := pg_temp.refused('tenant_role_delete', jsonb_build_object('actor', 'adm-a', 'tenantId', v_ta,
        'roleId', v_role), 'membership:conflict', 'deleting a held role');
    IF v_msg NOT LIKE '%held by 1 person%' THEN
        RAISE EXCEPTION 'the refusal counts the holders: %', v_msg;
    END IF;

    -- ANOTHER TENANT cannot delete it either, held or not.
    PERFORM pg_temp.refused('tenant_role_delete', jsonb_build_object('actor', 'adm-b', 'tenantId', v_tb,
        'roleId', v_role), 'membership:not_found', 'deleting another tenant''s role');

    -- Revoke by id: the first changes state, a second changes nothing.
    v := pg_temp.ok('tenant_role_revoke', jsonb_build_object('actor', 'adm-a', 'tenantId', v_ta,
        'userId', v_pa1, 'roleId', v_role), 'revoke');
    IF (v->>'changed')::boolean IS NOT TRUE THEN RAISE EXCEPTION 'a revoke changes state: %', v; END IF;
    v := pg_temp.ok('tenant_role_revoke', jsonb_build_object('actor', 'adm-a', 'tenantId', v_ta,
        'userId', v_pa1, 'roleId', v_role), 'revoke again');
    IF (v->>'changed')::boolean IS NOT FALSE THEN RAISE EXCEPTION 'revoking an ungranted role is a no-op: %', v; END IF;
    IF (SELECT count(*) FROM rolebyte.event WHERE kind = 'tenantRoleRevoked' AND user_id = v_pa1
          AND actor = 'adm-a' AND payload->>'roleId' = v_role) <> 1 THEN
        RAISE EXCEPTION 'one attributed revoke event';
    END IF;
    PERFORM pg_temp.refused('tenant_role_revoke', jsonb_build_object('actor', 'adm-a', 'tenantId', v_ta,
        'userId', v_pa1, 'roleId', v_rb), 'membership:unknown_role', 'revoking B''s role in A');
    PERFORM pg_temp.refused('tenant_role_revoke', jsonb_build_object('actor', 'adm-b', 'tenantId', v_tb,
        'userId', v_pa1, 'roleId', v_role), 'membership:not_found', 'revoking from A''s person through B');

    -- A person whose access was revoked does not count as holding it; a re-grant
    -- of a revoked role flips the same row back.
    PERFORM pg_temp.ok('tenant_role_grant', jsonb_build_object('actor', 'adm-a', 'tenantId', v_ta,
        'userId', v_pa2, 'roleId', v_role), 'grant pa2');
    PERFORM pg_temp.ok('user_revoke', jsonb_build_object('actor', 'adm-a', 'tenantId', v_ta, 'userId', v_pa2), 'revoke pa2');
    PERFORM pg_temp.refused('tenant_role_grant', jsonb_build_object('actor', 'adm-a', 'tenantId', v_ta,
        'userId', v_pa2, 'roleId', v_other), 'membership:not_found', 'a grant to a revoked person');

    v := pg_temp.ok('tenant_role_delete', jsonb_build_object('actor', 'adm-a', 'tenantId', v_ta, 'roleId', v_role), 'delete');
    IF (v->>'deleted')::boolean IS NOT TRUE THEN RAISE EXCEPTION 'delete answers deleted: %', v; END IF;
    IF EXISTS (SELECT 1 FROM rolebyte.tenant_role WHERE id = v_role)
       OR EXISTS (SELECT 1 FROM rolebyte.tenant_role_permission WHERE tenant_role_id = v_role)
       OR EXISTS (SELECT 1 FROM rolebyte.tenant_role_assignment WHERE tenant_role_id = v_role) THEN
        RAISE EXCEPTION 'a deleted role leaves no role, tick or grant behind';
    END IF;
    v := pg_temp.event_of('tenantRoleDeleted', v_role, 'adm-a', v_ta);
    IF v->>'name' IS DISTINCT FROM 'Meistars'
       OR v->'permissions' IS DISTINCT FROM '["traddon/workforce/person:view","trdemo/task:view","trdemo/task/attachment:deleteAny"]'::jsonb THEN
        RAISE EXCEPTION 'the delete event carries what the role held: %', v;
    END IF;
    PERFORM pg_temp.refused('tenant_role_delete', jsonb_build_object('actor', 'adm-a', 'tenantId', v_ta, 'roleId', v_role),
        'membership:not_found', 'deleting it twice');
    PERFORM pg_temp.refused('tenant_role_grant', jsonb_build_object('actor', 'adm-a', 'tenantId', v_ta,
        'userId', v_pa1, 'roleId', v_role), 'membership:unknown_role', 'granting a deleted role');
    PERFORM pg_temp.refused('tenant_role_delete', jsonb_build_object('actor', 'adm-a', 'tenantId', v_ta),
        'membership:invalid', 'no role id');

    -- 6. THE OTHER TENANT, after all four: its role is exactly as it made it, and
    --    its history holds nothing but its own act.
    v := pg_temp.ok('tenant_role_list', jsonb_build_object('tenantId', v_tb), 'list B');
    IF jsonb_array_length(v->'roles') <> 1
       OR v->'roles'->0->>'id' IS DISTINCT FROM v_rb
       OR v->'roles'->0->>'name' IS DISTINCT FROM 'Manager'
       OR v->'roles'->0->>'description' IS DISTINCT FROM 'B''s own'
       OR v->'roles'->0->'permissions' IS DISTINCT FROM '[]'::jsonb THEN
        RAISE EXCEPTION 'tenant B''s role must be untouched: %', v;
    END IF;
    v := pg_temp.ok('history', jsonb_build_object('tenantId', v_tb), 'history B');
    IF (SELECT count(*) FROM jsonb_array_elements(v->'events') e WHERE e->>'kind' LIKE 'tenantRole%') <> 1
       OR NOT EXISTS (SELECT 1 FROM jsonb_array_elements(v->'events') e
                      WHERE e->>'kind' = 'tenantRoleDefined' AND e->>'actor' = 'adm-b') THEN
        RAISE EXCEPTION 'tenant B''s history holds only its own definition: %', v;
    END IF;

    -- A's list holds what is left, ordered by name, each with what it holds.
    v := pg_temp.ok('tenant_role_list', jsonb_build_object('tenantId', v_ta), 'list A');
    IF jsonb_array_length(v->'roles') <> 2
       OR v->'roles'->0->>'id' IS DISTINCT FROM v_long
       OR v->'roles'->1->>'id' IS DISTINCT FROM v_other
       OR v->'roles'->1->'permissions' IS DISTINCT FROM '[]'::jsonb THEN
        RAISE EXCEPTION 'tenant A lists its two remaining roles by name: %', v;
    END IF;
    PERFORM pg_temp.refused('tenant_role_list', '{}'::jsonb, 'membership:invalid', 'a list with no tenant');
    PERFORM pg_temp.refused('tenant_role_list', jsonb_build_object('tenantId', util.generate_ulid()),
        'tenant:not_found', 'a list of an unknown tenant');

    -- A's history tells all of it, each act by its actor; the per-service seat
    -- count leaves tenant-role events out, because a tenant role has no service.
    v := pg_temp.ok('history', jsonb_build_object('tenantId', v_ta), 'history A');
    IF (SELECT count(DISTINCT e->>'kind') FROM jsonb_array_elements(v->'events') e
         WHERE e->>'kind' IN ('tenantRoleDefined','tenantRoleRenamed','tenantRoleDescribed','tenantRoleReconfigured',
                              'tenantRoleGranted','tenantRoleRevoked','tenantRoleDeleted')
           AND e->>'actor' = 'adm-a') <> 7 THEN
        RAISE EXCEPTION 'tenant A''s history carries all seven acts by its actor: %', v;
    END IF;
    v := pg_temp.ok('history', jsonb_build_object('tenantId', v_ta, 'service', 'trdemo'), 'history A for one service');
    IF EXISTS (SELECT 1 FROM jsonb_array_elements(v->'events') e WHERE e->>'kind' LIKE 'tenantRole%') THEN
        RAISE EXCEPTION 'a tenant-role event carries no service: %', v;
    END IF;

    RAISE NOTICE 'unit.rolebyte_tenant_role: all assertions passed';
END $$;

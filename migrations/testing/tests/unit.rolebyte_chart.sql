-- SQL unit tests for the chart of authority and the user type every member holds.
--
--   * every tenant has a default user type; every arrival receives it, on every
--     lane; a member's type is never set to nothing; the default, a type held
--     and a type a position names are not deleted;
--   * a tenant has the chart only while it is entitled to the chart's key; the
--     editor refuses a write otherwise and the document answers empty;
--   * one tree with one top; no loop; a position moves with what is under it;
--     a person sits in one position; machine members and strangers never do;
--   * the document answers, for each person, everyone below them and never the
--     people beside them;
--   * a position's boxes reach a token while the tenant holds the chart, and
--     never a role's, a user type's or the administrator's;
--   * the user type a position names applies while the person sits there and
--     the tenant holds the chart, and the person's own returns after.
--
-- Self-contained, seed-then-assert, one RAISE EXCEPTION per failed assertion.
--
-- Run as the owner:
--   psql "$DSN" -f migrations/testing/tests/unit.rolebyte_chart.sql

CREATE OR REPLACE FUNCTION pg_temp.rb(p_proc text, p_in jsonb) RETURNS jsonb
LANGUAGE plpgsql AS $$
DECLARE
    v jsonb;
BEGIN
    EXECUTE format('CALL rolebyte.%I($1, NULL::jsonb)', p_proc) INTO v USING p_in;
    RETURN v;
END $$;

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

CREATE OR REPLACE FUNCTION pg_temp.refused(p_proc text, p_in jsonb, p_code text, p_why text) RETURNS void
LANGUAGE plpgsql AS $$
DECLARE
    v jsonb := pg_temp.rb(p_proc, p_in);
BEGIN
    IF v->>'result' IS DISTINCT FROM 'error' OR v->>'code' IS DISTINCT FROM p_code THEN
        RAISE EXCEPTION '% should be refused %: %', p_why, p_code, v;
    END IF;
END $$;

-- The scopes a person's token would carry in a tenant.
CREATE OR REPLACE FUNCTION pg_temp.scopes(p_subject text, p_tenant text) RETURNS jsonb
LANGUAGE plpgsql AS $$
DECLARE
    v jsonb := pg_temp.ok('resolve', jsonb_build_object('subjectKey', p_subject), 'resolve');
BEGIN
    RETURN COALESCE((SELECT m->'scopes' FROM jsonb_array_elements(v->'memberships') m WHERE m->>'tenantId' = p_tenant),
                    '[]'::jsonb);
END $$;

-- A member of the tenant, invited and then made active, as the lanes do.
CREATE OR REPLACE FUNCTION pg_temp.member(p_tenant text, p_subject text, p_name text) RETURNS text
LANGUAGE plpgsql AS $$
DECLARE
    v jsonb := pg_temp.ok('user_invite', jsonb_build_object('actor', 'op:test', 'tenantId', p_tenant,
                          'subjectKey', p_subject, 'displayName', p_name), 'invite ' || p_name);
BEGIN
    UPDATE rolebyte.user_account SET status = 'active' WHERE id = v->>'id';
    RETURN v->>'id';
END $$;

DO $$
DECLARE
    v         jsonb;
    v_svc     text := 'chsv' || lower(substr(util.generate_ulid(), 20, 6));
    v_ta      text;
    v_tb      text;
    v_tl      text;
    v_def     text;
    v_admin   text := 'sub:' || util.generate_ulid();
    v_sanna   text := 'sub:' || util.generate_ulid();
    v_speteris text := 'sub:' || util.generate_ulid();
    v_silze   text := 'sub:' || util.generate_ulid();
    v_skarlis text := 'sub:' || util.generate_ulid();
    v_sjanis  text := 'sub:' || util.generate_ulid();
    v_stoms   text := 'sub:' || util.generate_ulid();
    v_anna    text;
    v_peteris text;
    v_ilze    text;
    v_karlis  text;
    v_janis   text;
    v_toms    text;
    v_svcacct text;
    v_other   text;
    v_director text;
    v_construction text;
    v_office  text;
    v_site    text;
    v_crew    text;
    v_spare   text;
    v_pm      text;
    v_role    text;
    v_foreign text;
    v_n       int;
BEGIN
    PERFORM pg_temp.ok('service_register', jsonb_build_object('actor', 'op:test', 'service', v_svc, 'displayName', 'Chart demo'), 'register');
    -- The chart's own key is registered once for the whole deployment.
    IF NOT EXISTS (SELECT 1 FROM rolebyte.service WHERE key = 'authority') THEN
        PERFORM pg_temp.ok('service_register', jsonb_build_object('actor', 'op:test', 'service', 'authority',
                           'displayName', 'Chart of authority'), 'register authority');
    END IF;

    PERFORM pg_temp.ok('permission_declare', jsonb_build_object('actor', 'op:test', 'service', v_svc, 'permission',
        jsonb_build_object('feature', 'project', 'act', 'create', 'description', 'Register a project',
                           'class', 'ordinary', 'plane', 'tenant')), 'project:create');
    PERFORM pg_temp.ok('permission_declare', jsonb_build_object('actor', 'op:test', 'service', v_svc, 'permission',
        jsonb_build_object('feature', 'project', 'act', 'view', 'description', 'See a project',
                           'class', 'ordinary', 'plane', 'object')), 'project:view');
    PERFORM pg_temp.ok('permission_declare', jsonb_build_object('actor', 'op:test', 'service', 'authority', 'permission',
        jsonb_build_object('feature', 'project', 'act', 'view', 'description', 'See the projects of the people below you',
                           'class', 'ordinary', 'plane', 'chart')), 'chart project:view');
    PERFORM pg_temp.ok('permission_declare', jsonb_build_object('actor', 'op:test', 'service', 'authority', 'permission',
        jsonb_build_object('feature', 'task', 'act', 'view', 'description', 'See the tasks of the people below you',
                           'class', 'ordinary', 'plane', 'chart')), 'chart task:view');
    PERFORM pg_temp.refused('permission_declare', jsonb_build_object('actor', 'op:test', 'service', 'authority', 'permission',
        jsonb_build_object('feature', 'setup', 'act', 'manage', 'description', 'Not a chart box',
                           'class', 'tenantConfiguration', 'plane', 'chart')), 'membership:invalid',
        'a setup permission on the chart plane');
    PERFORM pg_temp.refused('permission_declare', jsonb_build_object('actor', 'op:test', 'service', 'authority', 'permission',
        jsonb_build_object('feature', 'project', 'act', 'seeded', 'description', 'Seeded', 'class', 'ordinary',
                           'plane', 'chart', 'seeds', jsonb_build_array('manager'))), 'membership:invalid',
        'a seed on a chart box');
    PERFORM pg_temp.refused('permission_declare', jsonb_build_object('actor', 'op:test', 'service', 'authority', 'permission',
        jsonb_build_object('feature', 'project', 'act', 'other', 'description', 'Other', 'class', 'ordinary',
                           'plane', 'galaxy')), 'membership:invalid', 'an unknown plane');

    ----------------------------------------------------------------
    -- 1. Every tenant has a default user type; every arrival receives it.
    ----------------------------------------------------------------
    v := pg_temp.ok('tenant_open', jsonb_build_object('actor', 'op:test', 'name', 'Chart A',
        'administrator', jsonb_build_object('subjectKey', v_admin, 'displayName', 'Laura Zariņa')), 'open A');
    v_ta := v->'tenant'->>'id';
    SELECT default_user_type_id INTO v_def FROM rolebyte.tenant WHERE id = v_ta;
    IF v_def IS NULL OR (SELECT name FROM rolebyte.user_type WHERE id = v_def) IS DISTINCT FROM 'Member' THEN
        RAISE EXCEPTION 'a new workspace holds its default user type, Member';
    END IF;
    IF EXISTS (SELECT 1 FROM rolebyte.user_type_permission WHERE user_type_id = v_def) THEN
        RAISE EXCEPTION 'Member holds nothing';
    END IF;
    IF (SELECT user_type_id || '/' || user_type_source FROM rolebyte.user_account WHERE tenant_id = v_ta AND subject_key = v_admin)
       IS DISTINCT FROM v_def || '/workspaceDefault' THEN
        RAISE EXCEPTION 'the administrator arrives with the default';
    END IF;
    IF NOT EXISTS (SELECT 1 FROM rolebyte.event WHERE tenant_id = v_ta AND kind = 'defaultUserTypeSet') THEN
        RAISE EXCEPTION 'the default is an event';
    END IF;

    v := pg_temp.ok('tenant_open', jsonb_build_object('actor', 'op:test', 'name', 'Chart L', 'language', 'lv',
        'administrator', jsonb_build_object('subjectKey', 'sub:' || util.generate_ulid(), 'displayName', 'Inga Kalēja')), 'open lv');
    v_tl := v->'tenant'->>'id';
    IF (SELECT t.name FROM rolebyte.tenant n JOIN rolebyte.user_type t ON t.id = n.default_user_type_id WHERE n.id = v_tl)
       IS DISTINCT FROM 'Dalībnieks' THEN
        RAISE EXCEPTION 'a Latvian workspace names its default in Latvian';
    END IF;

    v_anna := pg_temp.member(v_ta, v_sanna, 'Anna Liepa');
    IF (SELECT user_type_id || '/' || user_type_source FROM rolebyte.user_account WHERE id = v_anna)
       IS DISTINCT FROM v_def || '/workspaceDefault' THEN
        RAISE EXCEPTION 'an invited member receives the default';
    END IF;
    IF NOT EXISTS (SELECT 1 FROM rolebyte.event WHERE user_id = v_anna AND kind = 'userTypeAssigned'
                    AND payload->>'source' = 'workspaceDefault') THEN
        RAISE EXCEPTION 'the arrival of a type is an event';
    END IF;

    PERFORM pg_temp.refused('user_type_assign', jsonb_build_object('actor', 'op:test', 'tenantId', v_ta, 'userId', v_anna),
        'membership:invalid', 'a member''s user type set to nothing');
    PERFORM pg_temp.refused('user_type_assign', jsonb_build_object('actor', 'op:test', 'tenantId', v_ta, 'userId', v_anna,
        'userTypeId', ''), 'membership:invalid', 'a member''s user type set to an empty one');
    PERFORM pg_temp.refused('user_type_delete', jsonb_build_object('actor', 'op:test', 'tenantId', v_ta, 'userTypeId', v_def),
        'membership:conflict', 'the default cannot be deleted');
    v := pg_temp.ok('user_type_list', jsonb_build_object('tenantId', v_ta), 'list');
    IF NOT (SELECT bool_or((t->>'workspaceDefault')::boolean) FROM jsonb_array_elements(v->'userTypes') t) THEN
        RAISE EXCEPTION 'the list says which is the default';
    END IF;

    v_peteris := pg_temp.member(v_ta, v_speteris, 'Pēteris Ozols');
    v_ilze    := pg_temp.member(v_ta, v_silze, 'Ilze Bērziņa');
    v_karlis  := pg_temp.member(v_ta, v_skarlis, 'Kārlis Ozoliņš');
    v_janis   := pg_temp.member(v_ta, v_sjanis, 'Jānis Kalniņš');
    v_toms    := pg_temp.member(v_ta, v_stoms, 'Toms Vītols');
    v := pg_temp.ok('user_invite', jsonb_build_object('actor', 'op:test', 'tenantId', v_ta,
        'subjectKey', 'svc:' || util.generate_ulid(), 'displayName', 'A service'), 'a service account');
    v_svcacct := v->>'id';
    IF (SELECT user_type_id FROM rolebyte.user_account WHERE id = v_svcacct) IS DISTINCT FROM v_def THEN
        RAISE EXCEPTION 'every member holds a user type, a service account included';
    END IF;

    ----------------------------------------------------------------
    -- 2. Without the chart: the editor refuses, the document is empty.
    ----------------------------------------------------------------
    PERFORM pg_temp.refused('chart_position_add', jsonb_build_object('actor', 'op:test', 'tenantId', v_ta, 'name', 'Director'),
        'membership:conflict', 'a position in a workspace without the chart');
    v := pg_temp.ok('chart_get', jsonb_build_object('tenantId', v_ta), 'get without');
    IF (v->>'included')::boolean OR jsonb_array_length(v->'positions') <> 0 THEN
        RAISE EXCEPTION 'the chart is not included and holds nothing: %', v;
    END IF;
    v := pg_temp.ok('chart_document', jsonb_build_object('tenantId', v_ta), 'document without');
    IF v->'below' IS DISTINCT FROM '{}'::jsonb THEN RAISE EXCEPTION 'an empty chart: %', v; END IF;
    PERFORM pg_temp.refused('chart_get', jsonb_build_object('tenantId', 'no-such-tenant'), 'tenant:not_found', 'a tenant that does not exist');

    PERFORM pg_temp.ok('entitlement_grant', jsonb_build_object('actor', 'op:test', 'tenantId', v_ta, 'service', v_svc), 'entitle the demo service');
    PERFORM pg_temp.ok('entitlement_grant', jsonb_build_object('actor', 'op:test', 'tenantId', v_ta, 'service', 'authority'), 'entitle');

    ----------------------------------------------------------------
    -- 3. The tree.
    ----------------------------------------------------------------
    PERFORM pg_temp.refused('chart_position_add', jsonb_build_object('actor', 'op:test', 'tenantId', v_ta, 'name', ' '),
        'membership:invalid', 'a nameless position');
    PERFORM pg_temp.refused('chart_position_add', jsonb_build_object('actor', 'op:test', 'tenantId', v_ta, 'name', 'X',
        'parentId', 'no-such-position'), 'membership:not_found', 'a parent that does not exist');
    v_director := pg_temp.ok('chart_position_add', jsonb_build_object('actor', 'op:test', 'tenantId', v_ta, 'name', 'Director'), 'top')->>'id';
    PERFORM pg_temp.refused('chart_position_add', jsonb_build_object('actor', 'op:test', 'tenantId', v_ta, 'name', 'Co-director'),
        'membership:conflict', 'a second top');
    v_construction := pg_temp.ok('chart_position_add', jsonb_build_object('actor', 'op:test', 'tenantId', v_ta,
        'name', 'Head of construction', 'parentId', v_director), 'construction')->>'id';
    v_office := pg_temp.ok('chart_position_add', jsonb_build_object('actor', 'op:test', 'tenantId', v_ta,
        'name', 'Head of office', 'parentId', v_director), 'office')->>'id';
    v_site := pg_temp.ok('chart_position_add', jsonb_build_object('actor', 'op:test', 'tenantId', v_ta,
        'name', 'Site manager', 'parentId', v_construction), 'site')->>'id';
    v_crew := pg_temp.ok('chart_position_add', jsonb_build_object('actor', 'op:test', 'tenantId', v_ta,
        'name', 'Site crew', 'parentId', v_site), 'crew')->>'id';
    IF (SELECT count(*) FROM rolebyte.event WHERE tenant_id = v_ta AND kind = 'chartPositionAdded') <> 5 THEN
        RAISE EXCEPTION 'each position is an event naming who made it';
    END IF;

    PERFORM pg_temp.refused('chart_position_move', jsonb_build_object('actor', 'op:test', 'tenantId', v_ta,
        'positionId', v_construction, 'parentId', v_crew), 'membership:conflict', 'a position under what is below it');
    PERFORM pg_temp.refused('chart_position_move', jsonb_build_object('actor', 'op:test', 'tenantId', v_ta,
        'positionId', v_construction, 'parentId', v_construction), 'membership:conflict', 'a position under itself');
    PERFORM pg_temp.refused('chart_position_move', jsonb_build_object('actor', 'op:test', 'tenantId', v_ta,
        'positionId', v_director, 'parentId', v_crew), 'membership:conflict', 'the top moved');
    PERFORM pg_temp.refused('chart_position_move', jsonb_build_object('actor', 'op:test', 'tenantId', v_ta,
        'positionId', v_crew, 'parentId', 'no-such-position'), 'membership:not_found', 'a move to nowhere');
    PERFORM pg_temp.ok('chart_position_rename', jsonb_build_object('actor', 'op:test', 'tenantId', v_ta,
        'positionId', v_crew, 'name', 'Site team'), 'rename');
    IF (SELECT name FROM rolebyte.chart_position WHERE id = v_crew) IS DISTINCT FROM 'Site team'
       OR NOT EXISTS (SELECT 1 FROM rolebyte.event WHERE kind = 'chartPositionRenamed' AND payload->>'positionId' = v_crew
                       AND payload->>'from' = 'Site crew') THEN
        RAISE EXCEPTION 'a rename is an event carrying the old name';
    END IF;

    ----------------------------------------------------------------
    -- 4. People in positions.
    ----------------------------------------------------------------
    PERFORM pg_temp.ok('chart_person_place', jsonb_build_object('actor', 'op:test', 'tenantId', v_ta, 'userId', v_anna, 'positionId', v_director), 'Anna');
    PERFORM pg_temp.ok('chart_person_place', jsonb_build_object('actor', 'op:test', 'tenantId', v_ta, 'userId', v_peteris, 'positionId', v_construction), 'Pēteris');
    PERFORM pg_temp.ok('chart_person_place', jsonb_build_object('actor', 'op:test', 'tenantId', v_ta, 'userId', v_ilze, 'positionId', v_office), 'Ilze');
    PERFORM pg_temp.ok('chart_person_place', jsonb_build_object('actor', 'op:test', 'tenantId', v_ta, 'userId', v_karlis, 'positionId', v_site), 'Kārlis');
    PERFORM pg_temp.ok('chart_person_place', jsonb_build_object('actor', 'op:test', 'tenantId', v_ta, 'userId', v_janis, 'positionId', v_crew), 'Jānis');
    PERFORM pg_temp.refused('chart_person_place', jsonb_build_object('actor', 'op:test', 'tenantId', v_ta, 'userId', v_svcacct,
        'positionId', v_crew), 'membership:invalid', 'a service account in the chart');
    PERFORM pg_temp.refused('chart_person_place', jsonb_build_object('actor', 'op:test', 'tenantId', v_ta, 'userId', 'no-such-member',
        'positionId', v_crew), 'membership:not_found', 'a stranger in the chart');
    v := pg_temp.ok('tenant_open', jsonb_build_object('actor', 'op:test', 'name', 'Chart B',
        'administrator', jsonb_build_object('subjectKey', 'sub:' || util.generate_ulid(), 'displayName', 'Mārtiņš Eglītis')), 'open B');
    v_tb := v->'tenant'->>'id';
    v_foreign := (SELECT id FROM rolebyte.user_account WHERE tenant_id = v_tb LIMIT 1);
    PERFORM pg_temp.refused('chart_person_place', jsonb_build_object('actor', 'op:test', 'tenantId', v_ta, 'userId', v_foreign,
        'positionId', v_crew), 'membership:not_found', 'another tenant''s member');
    -- Without the chart, B is refused before anything is looked up; with it, A's
    -- position is not found from B.
    PERFORM pg_temp.refused('chart_person_place', jsonb_build_object('actor', 'op:test', 'tenantId', v_tb, 'userId', v_foreign,
        'positionId', v_crew), 'membership:conflict', 'a placement in a workspace without the chart');
    PERFORM pg_temp.ok('entitlement_grant', jsonb_build_object('actor', 'op:test', 'tenantId', v_tb, 'service', 'authority'), 'entitle B');
    PERFORM pg_temp.refused('chart_person_place', jsonb_build_object('actor', 'op:test', 'tenantId', v_tb, 'userId', v_foreign,
        'positionId', v_crew), 'membership:not_found', 'another tenant''s position');

    v := pg_temp.ok('chart_get', jsonb_build_object('tenantId', v_ta), 'get');
    IF NOT (v->>'included')::boolean OR jsonb_array_length(v->'positions') <> 5 THEN RAISE EXCEPTION 'five positions: %', v; END IF;
    -- Unplaced: Toms and the administrator, never the service account.
    IF jsonb_array_length(v->'unplaced') <> 2 THEN RAISE EXCEPTION 'two unplaced people, not the service account: %', v->'unplaced'; END IF;

    -- Below means every position under mine, never the people beside me.
    v := pg_temp.ok('chart_document', jsonb_build_object('tenantId', v_ta), 'document');
    IF (SELECT jsonb_agg(x ORDER BY x) FROM jsonb_array_elements_text(v->'below'->v_sanna) x)
       IS DISTINCT FROM (SELECT jsonb_agg(x ORDER BY x) FROM unnest(ARRAY[v_speteris, v_silze, v_skarlis, v_sjanis]) x) THEN
        RAISE EXCEPTION 'Anna has all four below her: %', v;
    END IF;
    IF (SELECT jsonb_agg(x ORDER BY x) FROM jsonb_array_elements_text(v->'below'->v_speteris) x)
       IS DISTINCT FROM (SELECT jsonb_agg(x ORDER BY x) FROM unnest(ARRAY[v_skarlis, v_sjanis]) x) THEN
        RAISE EXCEPTION 'Pēteris has Kārlis and Jānis below him: %', v;
    END IF;
    IF v->'below' ? v_silze OR v->'below' ? v_sjanis OR v->'below' ? v_stoms THEN
        RAISE EXCEPTION 'nobody below anybody has no entry, and Toms is in no position: %', v;
    END IF;
    IF jsonb_array_length(v->'below'->v_skarlis) <> 1 THEN RAISE EXCEPTION 'Kārlis has Jānis below him'; END IF;

    -- Two people in one position are not below each other.
    PERFORM pg_temp.ok('chart_person_place', jsonb_build_object('actor', 'op:test', 'tenantId', v_ta, 'userId', v_toms, 'positionId', v_crew), 'Toms joins the crew');
    v := pg_temp.ok('chart_document', jsonb_build_object('tenantId', v_ta), 'document');
    IF v->'below' ? v_sjanis OR v->'below' ? v_stoms THEN RAISE EXCEPTION 'the crew are not below each other'; END IF;
    IF jsonb_array_length(v->'below'->v_skarlis) <> 2 THEN RAISE EXCEPTION 'Kārlis has both crew below him'; END IF;

    -- A person in at most one position: placing again moves them.
    PERFORM pg_temp.ok('chart_person_place', jsonb_build_object('actor', 'op:test', 'tenantId', v_ta, 'userId', v_toms, 'positionId', v_office), 'Toms to the office');
    IF (SELECT count(*) FROM rolebyte.chart_holder WHERE user_id = v_toms) <> 1 THEN RAISE EXCEPTION 'one position per person'; END IF;
    IF NOT EXISTS (SELECT 1 FROM rolebyte.event WHERE kind = 'chartPersonPlaced' AND user_id = v_toms AND payload->>'from' = v_crew) THEN
        RAISE EXCEPTION 'a move carries where the person came from';
    END IF;
    v := pg_temp.ok('chart_document', jsonb_build_object('tenantId', v_ta), 'document');
    IF NOT (v->'below'->v_silze) @> to_jsonb(v_stoms) THEN RAISE EXCEPTION 'Toms is below Ilze now: %', v; END IF;

    -- A move of a position takes everything under it.
    PERFORM pg_temp.ok('chart_position_move', jsonb_build_object('actor', 'op:test', 'tenantId', v_ta,
        'positionId', v_site, 'parentId', v_office), 'Site manager under the office');
    v := pg_temp.ok('chart_document', jsonb_build_object('tenantId', v_ta), 'document');
    IF v->'below' ? v_speteris OR NOT (v->'below'->v_silze) @> to_jsonb(v_sjanis) THEN
        RAISE EXCEPTION 'the site and its crew moved under Ilze: %', v;
    END IF;
    PERFORM pg_temp.ok('chart_position_move', jsonb_build_object('actor', 'op:test', 'tenantId', v_ta,
        'positionId', v_site, 'parentId', v_construction), 'back');

    -- A removed member leaves no one below anyone.
    UPDATE rolebyte.user_account SET status = 'revoked' WHERE id = v_toms;
    v := pg_temp.ok('chart_document', jsonb_build_object('tenantId', v_ta), 'document');
    IF (v->'below'->v_silze) IS NOT NULL THEN RAISE EXCEPTION 'a member who left is below nobody: %', v; END IF;
    PERFORM pg_temp.refused('chart_person_place', jsonb_build_object('actor', 'op:test', 'tenantId', v_ta, 'userId', v_toms,
        'positionId', v_crew), 'membership:conflict', 'a member who left');
    PERFORM pg_temp.ok('chart_person_remove', jsonb_build_object('actor', 'op:test', 'tenantId', v_ta, 'userId', v_toms), 'Toms out');
    PERFORM pg_temp.refused('chart_person_remove', jsonb_build_object('actor', 'op:test', 'tenantId', v_ta, 'userId', v_toms),
        'membership:not_found', 'removing a person who is in no position');

    -- A position with people or positions in it is not removed.
    PERFORM pg_temp.refused('chart_position_remove', jsonb_build_object('actor', 'op:test', 'tenantId', v_ta, 'positionId', v_site),
        'membership:conflict', 'a position with a crew under it');
    PERFORM pg_temp.refused('chart_position_remove', jsonb_build_object('actor', 'op:test', 'tenantId', v_ta, 'positionId', v_director),
        'membership:conflict', 'the top with positions under it');
    v := pg_temp.ok('chart_position_add', jsonb_build_object('actor', 'op:test', 'tenantId', v_ta, 'name', 'Temporary', 'parentId', v_office), 'temp');
    PERFORM pg_temp.ok('chart_position_remove', jsonb_build_object('actor', 'op:test', 'tenantId', v_ta, 'positionId', v->>'id'), 'remove empty');
    PERFORM pg_temp.refused('chart_position_remove', jsonb_build_object('actor', 'op:test', 'tenantId', v_ta, 'positionId', v->>'id'),
        'membership:not_found', 'a removed position');

    ----------------------------------------------------------------
    -- 5. A position's boxes: on a token while the tenant holds the chart.
    ----------------------------------------------------------------
    IF pg_temp.scopes(v_sanna, v_ta) ? 'authority/project:view' THEN RAISE EXCEPTION 'no box before a position carries it'; END IF;
    PERFORM pg_temp.refused('chart_position_permissions_set', jsonb_build_object('actor', 'op:test', 'tenantId', v_ta,
        'positionId', v_director, 'permissions', jsonb_build_array(v_svc || '/project:create')),
        'membership:invalid', 'a tenant-wide permission on a position');
    PERFORM pg_temp.refused('chart_position_permissions_set', jsonb_build_object('actor', 'op:test', 'tenantId', v_ta,
        'positionId', v_director, 'permissions', jsonb_build_array(v_svc || '/project:view')),
        'membership:invalid', 'an object permission on a position');
    PERFORM pg_temp.refused('chart_position_permissions_set', jsonb_build_object('actor', 'op:test', 'tenantId', v_ta,
        'positionId', v_director, 'permissions', jsonb_build_array('authority/project:nothing')),
        'membership:invalid', 'a permission that is not declared');
    PERFORM pg_temp.refused('chart_position_permissions_set', jsonb_build_object('actor', 'op:test', 'tenantId', v_ta,
        'positionId', v_director, 'permissions', 'authority/project:view'),
        'membership:invalid', 'permissions not a list');
    PERFORM pg_temp.ok('chart_position_permissions_set', jsonb_build_object('actor', 'op:test', 'tenantId', v_ta,
        'positionId', v_director, 'permissions', jsonb_build_array('authority/project:view', 'authority/task:view')), 'Anna sees');
    PERFORM pg_temp.ok('chart_position_permissions_set', jsonb_build_object('actor', 'op:test', 'tenantId', v_ta,
        'positionId', v_construction, 'permissions', jsonb_build_array('authority/project:view')), 'Pēteris sees projects');
    IF NOT (pg_temp.scopes(v_sanna, v_ta) ? 'authority/project:view') OR NOT (pg_temp.scopes(v_sanna, v_ta) ? 'authority/task:view') THEN
        RAISE EXCEPTION 'the position''s boxes reach its holder''s token';
    END IF;
    IF NOT (pg_temp.scopes(v_speteris, v_ta) ? 'authority/project:view') OR (pg_temp.scopes(v_speteris, v_ta) ? 'authority/task:view') THEN
        RAISE EXCEPTION 'each position carries its own';
    END IF;
    IF pg_temp.scopes(v_silze, v_ta) ? 'authority/project:view' OR pg_temp.scopes(v_sjanis, v_ta) ? 'authority/project:view' THEN
        RAISE EXCEPTION 'a box reaches only those who sit in its position';
    END IF;
    IF EXISTS (SELECT 1 FROM jsonb_array_elements_text(pg_temp.scopes(v_admin, v_ta)) s WHERE s LIKE 'authority/%') THEN
        RAISE EXCEPTION 'the administrator checkbox holds no chart box';
    END IF;
    IF NOT EXISTS (SELECT 1 FROM rolebyte.event WHERE kind = 'chartPositionPermissionsSet' AND payload->>'positionId' = v_director) THEN
        RAISE EXCEPTION 'ticking boxes is an event';
    END IF;

    -- No box on two lists.
    v_role := pg_temp.ok('tenant_role_define', jsonb_build_object('actor', 'op:test', 'tenantId', v_ta, 'name', 'Observers',
        'description', ''), 'role')->>'id';
    PERFORM pg_temp.refused('tenant_role_permissions_set', jsonb_build_object('actor', 'op:test', 'tenantId', v_ta,
        'roleId', v_role, 'permissions', jsonb_build_array('authority/project:view')),
        'membership:invalid', 'a chart box ticked on a role');
    PERFORM pg_temp.refused('user_type_define', jsonb_build_object('actor', 'op:test', 'tenantId', v_ta, 'name', 'Observer',
        'permissions', jsonb_build_array('authority/project:view')), 'membership:invalid', 'a chart box on a user type');

    ----------------------------------------------------------------
    -- 6. The chart lapses and returns: nothing is deleted.
    ----------------------------------------------------------------
    -- An empty position, so that removing it is refused by the lapse alone.
    v_spare := pg_temp.ok('chart_position_add', jsonb_build_object('actor', 'op:test', 'tenantId', v_ta,
        'name', 'Spare', 'parentId', v_office), 'spare')->>'id';
    PERFORM pg_temp.ok('entitlement_revoke', jsonb_build_object('actor', 'op:test', 'tenantId', v_ta, 'service', 'authority'), 'lapse');
    IF pg_temp.scopes(v_sanna, v_ta) ? 'authority/project:view' THEN RAISE EXCEPTION 'a lapsed chart gives no box'; END IF;
    v := pg_temp.ok('chart_document', jsonb_build_object('tenantId', v_ta), 'document after lapse');
    IF v->'below' IS DISTINCT FROM '{}'::jsonb THEN RAISE EXCEPTION 'a lapsed chart answers empty: %', v; END IF;
    v := pg_temp.ok('chart_get', jsonb_build_object('tenantId', v_ta), 'get after lapse');
    IF (v->>'included')::boolean OR jsonb_array_length(v->'positions') <> 6 THEN
        RAISE EXCEPTION 'the positions stay, and the editor says the chart is not included: %', v;
    END IF;
    PERFORM pg_temp.refused('chart_position_add', jsonb_build_object('actor', 'op:test', 'tenantId', v_ta, 'name', 'More',
        'parentId', v_office), 'membership:conflict', 'a write after the lapse');
    -- Every other write is refused as well, and none of them writes anything.
    SELECT count(*) INTO v_n FROM rolebyte.event WHERE tenant_id = v_ta AND kind LIKE 'chart%';
    PERFORM pg_temp.refused('chart_position_rename', jsonb_build_object('actor', 'op:test', 'tenantId', v_ta,
        'positionId', v_crew, 'name', 'Renamed'), 'membership:conflict', 'a rename after the lapse');
    PERFORM pg_temp.refused('chart_position_move', jsonb_build_object('actor', 'op:test', 'tenantId', v_ta,
        'positionId', v_crew, 'parentId', v_office), 'membership:conflict', 'a move after the lapse');
    PERFORM pg_temp.refused('chart_position_remove', jsonb_build_object('actor', 'op:test', 'tenantId', v_ta,
        'positionId', v_spare), 'membership:conflict', 'a removal after the lapse');
    PERFORM pg_temp.refused('chart_position_permissions_set', jsonb_build_object('actor', 'op:test', 'tenantId', v_ta,
        'positionId', v_director, 'permissions', '[]'::jsonb), 'membership:conflict', 'a position''s boxes after the lapse');
    PERFORM pg_temp.refused('chart_position_user_type_set', jsonb_build_object('actor', 'op:test', 'tenantId', v_ta,
        'positionId', v_site, 'userTypeId', v_def), 'membership:conflict', 'a position''s user type after the lapse');
    PERFORM pg_temp.refused('chart_person_place', jsonb_build_object('actor', 'op:test', 'tenantId', v_ta,
        'userId', v_ilze, 'positionId', v_crew), 'membership:conflict', 'a person placed after the lapse');
    PERFORM pg_temp.refused('chart_person_remove', jsonb_build_object('actor', 'op:test', 'tenantId', v_ta,
        'userId', v_janis), 'membership:conflict', 'a person taken out after the lapse');
    IF (SELECT count(*) FROM rolebyte.event WHERE tenant_id = v_ta AND kind LIKE 'chart%') IS DISTINCT FROM v_n::bigint THEN
        RAISE EXCEPTION 'a refused chart write leaves no event';
    END IF;
    IF (SELECT name FROM rolebyte.chart_position WHERE id = v_crew) IS DISTINCT FROM 'Site team'
       OR (SELECT parent_id FROM rolebyte.chart_position WHERE id = v_crew) IS DISTINCT FROM v_site
       OR (SELECT position_id FROM rolebyte.chart_holder WHERE user_id = v_janis) IS DISTINCT FROM v_crew
       OR (SELECT position_id FROM rolebyte.chart_holder WHERE user_id = v_ilze) IS DISTINCT FROM v_office
       OR NOT EXISTS (SELECT 1 FROM rolebyte.chart_position WHERE id = v_spare) THEN
        RAISE EXCEPTION 'a refused chart write changes nothing';
    END IF;
    PERFORM pg_temp.ok('entitlement_grant', jsonb_build_object('actor', 'op:test', 'tenantId', v_ta, 'service', 'authority'), 'again');
    PERFORM pg_temp.ok('chart_position_remove', jsonb_build_object('actor', 'op:test', 'tenantId', v_ta,
        'positionId', v_spare), 'entitled again, the empty position is removed');
    IF NOT (pg_temp.scopes(v_sanna, v_ta) ? 'authority/project:view') THEN RAISE EXCEPTION 'entitled again, the box returns as left'; END IF;
    v := pg_temp.ok('chart_document', jsonb_build_object('tenantId', v_ta), 'document again');
    IF jsonb_array_length(v->'below'->v_sanna) <> 4 THEN RAISE EXCEPTION 'entitled again, the chart returns as left: %', v; END IF;

    -- Another tenant is untouched by all of it.
    IF (SELECT count(*) FROM rolebyte.chart_position WHERE tenant_id = v_tb) <> 0 THEN RAISE EXCEPTION 'another tenant has no chart'; END IF;

    ----------------------------------------------------------------
    -- 7. The user type a position names, beside the member's own.
    ----------------------------------------------------------------
    v_pm := pg_temp.ok('user_type_define', jsonb_build_object('actor', 'op:test', 'tenantId', v_ta, 'name', 'Project manager',
        'permissions', jsonb_build_array(v_svc || '/project:create')), 'define')->>'id';
    IF pg_temp.scopes(v_skarlis, v_ta) ? (v_svc || '/project:create') THEN RAISE EXCEPTION 'Kārlis holds Member: nothing'; END IF;
    PERFORM pg_temp.refused('chart_position_user_type_set', jsonb_build_object('actor', 'op:test', 'tenantId', v_ta,
        'positionId', v_site, 'userTypeId', 'no-such-type'), 'membership:invalid', 'a user type that is not the tenant''s');
    PERFORM pg_temp.ok('chart_position_user_type_set', jsonb_build_object('actor', 'op:test', 'tenantId', v_ta,
        'positionId', v_site, 'userTypeId', v_pm), 'Site manager sets Project manager');
    IF NOT (pg_temp.scopes(v_skarlis, v_ta) ? (v_svc || '/project:create')) THEN
        RAISE EXCEPTION 'sitting in the position, Kārlis receives its user type';
    END IF;
    IF (SELECT user_type_id FROM rolebyte.user_account WHERE id = v_karlis) IS DISTINCT FROM v_def THEN
        RAISE EXCEPTION 'his own user type is untouched underneath';
    END IF;
    IF pg_temp.scopes(v_sjanis, v_ta) ? (v_svc || '/project:create') THEN RAISE EXCEPTION 'only the position''s holders'; END IF;
    PERFORM pg_temp.refused('user_type_delete', jsonb_build_object('actor', 'op:test', 'tenantId', v_ta, 'userTypeId', v_pm),
        'membership:conflict', 'a user type a position names');

    PERFORM pg_temp.ok('entitlement_revoke', jsonb_build_object('actor', 'op:test', 'tenantId', v_ta, 'service', 'authority'), 'lapse');
    IF pg_temp.scopes(v_skarlis, v_ta) ? (v_svc || '/project:create') THEN RAISE EXCEPTION 'a lapse returns him to his own type'; END IF;
    PERFORM pg_temp.ok('entitlement_grant', jsonb_build_object('actor', 'op:test', 'tenantId', v_ta, 'service', 'authority'), 'again');
    IF NOT (pg_temp.scopes(v_skarlis, v_ta) ? (v_svc || '/project:create')) THEN RAISE EXCEPTION 'and back'; END IF;

    PERFORM pg_temp.ok('chart_person_remove', jsonb_build_object('actor', 'op:test', 'tenantId', v_ta, 'userId', v_karlis), 'Kārlis out');
    IF pg_temp.scopes(v_skarlis, v_ta) ? (v_svc || '/project:create') THEN RAISE EXCEPTION 'out of the position, his own type again'; END IF;
    PERFORM pg_temp.ok('chart_person_place', jsonb_build_object('actor', 'op:test', 'tenantId', v_ta, 'userId', v_karlis, 'positionId', v_site), 'back in');

    -- A position that names no type changes nothing.
    PERFORM pg_temp.ok('chart_position_user_type_set', jsonb_build_object('actor', 'op:test', 'tenantId', v_ta,
        'positionId', v_site, 'userTypeId', ''), 'none');
    IF pg_temp.scopes(v_skarlis, v_ta) ? (v_svc || '/project:create') THEN RAISE EXCEPTION 'a position naming none keeps his own'; END IF;
    IF NOT EXISTS (SELECT 1 FROM rolebyte.event WHERE kind = 'chartPositionUserTypeSet' AND payload->>'positionId' = v_site
                    AND payload->>'from' = v_pm) THEN
        RAISE EXCEPTION 'naming a user type is an event carrying the previous one';
    END IF;

    -- The administrator sets his own type: the chart's does not overwrite it.
    PERFORM pg_temp.ok('chart_position_user_type_set', jsonb_build_object('actor', 'op:test', 'tenantId', v_ta,
        'positionId', v_site, 'userTypeId', v_pm), 'Site manager sets Project manager again');
    PERFORM pg_temp.ok('user_type_assign', jsonb_build_object('actor', 'op:test', 'tenantId', v_ta, 'userId', v_karlis,
        'userTypeId', v_def), 'Laura chooses Member');
    IF NOT (pg_temp.scopes(v_skarlis, v_ta) ? (v_svc || '/project:create')) THEN
        RAISE EXCEPTION 'the chart''s type applies over the administrator''s while he sits there';
    END IF;

    ----------------------------------------------------------------
    -- 8. One Member per tenant, however many members arrived.
    ----------------------------------------------------------------
    SELECT count(*) INTO v_n FROM rolebyte.user_type WHERE tenant_id = v_ta AND lower(name) = 'member';
    IF v_n <> 1 THEN RAISE EXCEPTION 'one Member per tenant: %', v_n; END IF;
END $$;

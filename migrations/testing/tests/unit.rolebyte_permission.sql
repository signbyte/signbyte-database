-- Unit test: a service declares the permissions it enforces.
-- A declaration is additive and strict: a new permission is added, the same one
-- again changes nothing, a new description is an update, a different class is
-- refused, and anything malformed or unknown is refused with nothing stored. The
-- configuration document carries permissions beside roles, a get→apply round trip
-- changes nothing, and one refused entry rolls the whole section back. A role's
-- group can no longer be spelled like a permission. Every permission says where it
-- may be granted and that never changes; it carries a label per language; and it
-- is retired, or brought back, by its declaration.
--   psql -v ON_ERROR_STOP=1 -f migrations/testing/tests/unit.rolebyte_permission.sql

-- Declares one permission for the test service and returns the answer.
CREATE OR REPLACE FUNCTION pg_temp.declare(p_service text, p_decl jsonb) RETURNS jsonb
LANGUAGE plpgsql AS $$
DECLARE
    v jsonb;
BEGIN
    CALL rolebyte.permission_declare(jsonb_build_object(
        'actor', 'permission-test', 'service', p_service, 'permission', p_decl), v);
    RETURN v;
END $$;

-- The declaration must be refused with exactly this code, and store nothing.
CREATE OR REPLACE FUNCTION pg_temp.refused(p_service text, p_decl jsonb, p_code text, p_why text) RETURNS void
LANGUAGE plpgsql AS $$
DECLARE
    v      jsonb;
    before int;
BEGIN
    SELECT count(*) INTO before FROM rolebyte.service_permission;
    v := pg_temp.declare(p_service, p_decl);
    IF v->>'result' IS DISTINCT FROM 'error' OR v->>'code' IS DISTINCT FROM p_code THEN
        RAISE EXCEPTION '% should be refused %: %', p_why, p_code, v;
    END IF;
    IF (SELECT count(*) FROM rolebyte.service_permission) <> before THEN
        RAISE EXCEPTION '% was refused but stored a row', p_why;
    END IF;
END $$;

DO $$
DECLARE
    v         jsonb;
    v_tenant  text;
    v_events  int;
    v_section jsonb;
BEGIN
    CALL rolebyte.service_register('{"actor":"permission-test","service":"permdemo","displayName":"Permission demo"}'::jsonb, v);
    IF v->>'result' IS DISTINCT FROM 'success' THEN
        RAISE EXCEPTION 'service_register failed: %', v;
    END IF;

    -- 1. A new permission is added, answers its wire spelling, and is history.
    v := pg_temp.declare('permdemo', '{"feature":"task/attachment","act":"deleteAny",
        "description":"Remove any file on a task","class":"ordinary","plane":"object"}'::jsonb);
    IF v->>'result' IS DISTINCT FROM 'success' THEN
        RAISE EXCEPTION 'declare failed: %', v;
    END IF;
    IF v->'data'->>'status' IS DISTINCT FROM 'added' THEN
        RAISE EXCEPTION 'a new permission should be added: %', v;
    END IF;
    IF v->'data'->>'permission' IS DISTINCT FROM 'permdemo/task/attachment:deleteAny' THEN
        RAISE EXCEPTION 'the answer should name the permission as it travels: %', v;
    END IF;
    IF NOT EXISTS (SELECT 1 FROM rolebyte.event
                   WHERE kind = 'permissionDeclared'
                     AND payload->>'permission' = 'permdemo/task/attachment:deleteAny'
                     AND payload->>'class' = 'ordinary'
                     AND actor = 'permission-test'
                     AND tenant_id IS NULL) THEN
        RAISE EXCEPTION 'a declaration must land in the event stream, attributed and tenant-free';
    END IF;

    -- 2. The same declaration again changes nothing and records nothing.
    SELECT count(*) INTO v_events FROM rolebyte.event;
    v := pg_temp.declare('permdemo', '{"feature":"task/attachment","act":"deleteAny",
        "description":"Remove any file on a task","class":"ordinary","plane":"object"}'::jsonb);
    IF v->'data'->>'status' IS DISTINCT FROM 'unchanged' THEN
        RAISE EXCEPTION 'the same declaration should be unchanged: %', v;
    END IF;
    IF (SELECT count(*) FROM rolebyte.event) <> v_events THEN
        RAISE EXCEPTION 'an unchanged declaration must not record an event';
    END IF;

    -- 3. A new description is an update, and history.
    v := pg_temp.declare('permdemo', '{"feature":"task/attachment","act":"deleteAny",
        "description":"Remove a file anyone attached to a task","class":"ordinary","plane":"object"}'::jsonb);
    IF v->'data'->>'status' IS DISTINCT FROM 'changed' THEN
        RAISE EXCEPTION 'a new description should be changed: %', v;
    END IF;
    IF (SELECT description FROM rolebyte.service_permission
         WHERE service_key = 'permdemo' AND feature_key = 'task/attachment' AND act = 'deleteAny')
       IS DISTINCT FROM 'Remove a file anyone attached to a task' THEN
        RAISE EXCEPTION 'the description should follow the declaration';
    END IF;
    IF NOT EXISTS (SELECT 1 FROM rolebyte.event
                   WHERE kind = 'permissionDescribed'
                     AND payload->>'from' = 'Remove any file on a task'
                     AND payload->>'to' = 'Remove a file anyone attached to a task') THEN
        RAISE EXCEPTION 'a description change must land in the event stream with both texts';
    END IF;

    -- 4. A different class is refused, naming the permission, and changes nothing.
    PERFORM pg_temp.refused('permdemo', '{"feature":"task/attachment","act":"deleteAny",
        "description":"Remove a file anyone attached to a task","class":"tenantConfiguration","plane":"tenant"}'::jsonb,
        'membership:conflict', 'a re-classed permission');
    v := pg_temp.declare('permdemo', '{"feature":"task/attachment","act":"deleteAny",
        "class":"roleManagement","plane":"tenant"}'::jsonb);
    IF v->>'message' NOT LIKE '%permdemo/task/attachment:deleteAny%' THEN
        RAISE EXCEPTION 'the class refusal should name the permission: %', v;
    END IF;
    IF (SELECT class FROM rolebyte.service_permission
         WHERE service_key = 'permdemo' AND feature_key = 'task/attachment' AND act = 'deleteAny')
       IS DISTINCT FROM 'ordinary' THEN
        RAISE EXCEPTION 'a refused re-class must leave the class as declared';
    END IF;

    -- 5. Nesting grants nothing and names nothing twice: the task's own act and the
    --    same act on its attachment are two permissions.
    v := pg_temp.declare('permdemo', '{"feature":"task","act":"deleteAny","class":"ordinary","plane":"object"}'::jsonb);
    IF v->'data'->>'status' IS DISTINCT FROM 'added' THEN
        RAISE EXCEPTION 'a parent feature''s act is its own permission: %', v;
    END IF;

    -- 6. Strict reading: an unknown property is refused rather than dropped.
    PERFORM pg_temp.refused('permdemo', '{"feature":"task","act":"view","class":"ordinary","plane":"object",
        "minAssurance":"high"}'::jsonb, 'membership:invalid', 'an unknown property');
    PERFORM pg_temp.refused('permdemo', '"task:view"'::jsonb, 'membership:invalid', 'a declaration that is not an object');

    -- 7. Every part keeps its grammar.
    PERFORM pg_temp.refused('permdemo', '{"act":"view","class":"ordinary","plane":"object"}'::jsonb, 'membership:invalid', 'a missing feature');
    PERFORM pg_temp.refused('permdemo', '{"feature":"task","class":"ordinary","plane":"object"}'::jsonb, 'membership:invalid', 'a missing act');
    PERFORM pg_temp.refused('permdemo', '{"feature":"task","act":"view","plane":"object"}'::jsonb, 'membership:invalid', 'a missing class');
    PERFORM pg_temp.refused('permdemo', '{"feature":"Task","act":"view","class":"ordinary","plane":"object"}'::jsonb, 'membership:invalid', 'a capitalised feature');
    PERFORM pg_temp.refused('permdemo', '{"feature":"task//comment","act":"view","class":"ordinary","plane":"object"}'::jsonb, 'membership:invalid', 'an empty feature segment');
    PERFORM pg_temp.refused('permdemo', '{"feature":"task/","act":"view","class":"ordinary","plane":"object"}'::jsonb, 'membership:invalid', 'a trailing "/"');
    PERFORM pg_temp.refused('permdemo', '{"feature":"task comment","act":"view","class":"ordinary","plane":"object"}'::jsonb, 'membership:invalid', 'a space in a feature');
    PERFORM pg_temp.refused('permdemo', '{"feature":"task:comment","act":"view","class":"ordinary","plane":"object"}'::jsonb, 'membership:invalid', 'a ":" in a feature');
    PERFORM pg_temp.refused('permdemo', '{"feature":"task","act":"view,edit","class":"ordinary","plane":"object"}'::jsonb, 'membership:invalid', 'a "," in an act');
    PERFORM pg_temp.refused('permdemo', '{"feature":"task","act":"delete-any","class":"ordinary","plane":"object"}'::jsonb, 'membership:invalid', 'a "-" in an act');
    PERFORM pg_temp.refused('permdemo', '{"feature":"task","act":"view","class":"admin","plane":"object"}'::jsonb, 'membership:invalid', 'an unknown class');
    PERFORM pg_temp.refused('permdemo', '{"feature":"task","act":7,"class":"ordinary","plane":"object"}'::jsonb, 'membership:invalid', 'a number for an act');

    -- 8. Only a registered service declares, and only one whose key can open a permission.
    PERFORM pg_temp.refused('no-such-service', '{"feature":"task","act":"view","class":"ordinary","plane":"object"}'::jsonb,
        'membership:not_found', 'an unregistered service');
    CALL rolebyte.service_register('{"actor":"permission-test","service":"Perm:Demo"}'::jsonb, v);
    PERFORM pg_temp.refused('Perm:Demo', '{"feature":"task","act":"view","class":"ordinary","plane":"object"}'::jsonb,
        'membership:invalid', 'a service key carrying a separator');

    -- 9. A role's group can no longer be spelled like a permission, at the procedure
    --    and at the table.
    CALL rolebyte.role_define('{"actor":"permission-test","service":"permdemo","group":"task/attachment","level":"write"}'::jsonb, v);
    IF v->>'code' IS DISTINCT FROM 'membership:invalid' THEN
        RAISE EXCEPTION 'a role group containing "/" should be refused: %', v;
    END IF;
    BEGIN
        INSERT INTO rolebyte.role_definition (id, service_key, role_group, role_level)
        VALUES ('perm-test-bad-role', 'permdemo', 'task/attachment', 'write');
        RAISE EXCEPTION 'the table should refuse a role group containing "/"';
    EXCEPTION WHEN check_violation THEN NULL;
    END;
    CALL rolebyte.role_define('{"actor":"permission-test","service":"permdemo","group":"demo","level":"read"}'::jsonb, v);
    IF v->>'result' IS DISTINCT FROM 'success' THEN
        RAISE EXCEPTION 'an ordinary role must still be definable: %', v;
    END IF;

    -- 10. The configuration document carries permissions beside roles.
    CALL rolebyte.tenant_create('{"actor":"permission-test","name":"Permission demo"}'::jsonb, v);
    v_tenant := v->'data'->>'id';
    CALL rolebyte.config_apply(jsonb_build_object(
        'tenantId', v_tenant, 'actor', 'permission-test',
        'section', '{"services":[{"key":"permcfg","displayName":"Permission config demo",
            "roles":[],
            "permissions":[
              {"feature":"spentTime","act":"viewAll","description":"See everybody''s hours","class":"ordinary","plane":"object"},
              {"feature":"configuration","act":"edit","description":"","class":"tenantConfiguration","plane":"tenant",
               "labels":{"lv":"Mainīt konfigurāciju","de":"Konfiguration ändern"}}]}]}'::jsonb), v);
    IF v->>'result' IS DISTINCT FROM 'success' THEN
        RAISE EXCEPTION 'apply with permissions failed: %', v;
    END IF;
    IF jsonb_array_length(v->'data'->'permissions') <> 2
       OR EXISTS (SELECT 1 FROM jsonb_array_elements(v->'data'->'permissions') e WHERE e->>'status' <> 'added') THEN
        RAISE EXCEPTION 'both permissions should be added: %', v;
    END IF;
    IF NOT EXISTS (SELECT 1 FROM jsonb_array_elements(v->'data'->'permissions') e
                   WHERE e->>'permission' = 'permcfg/spentTime:viewAll') THEN
        RAISE EXCEPTION 'the apply report should name each permission as it travels: %', v;
    END IF;

    -- config_get answers them, with the class.
    CALL rolebyte.config_get(jsonb_build_object('tenantId', v_tenant), v);
    SELECT s INTO v_section FROM jsonb_array_elements(v->'data'->'services') s WHERE s->>'key' = 'permcfg';
    IF jsonb_array_length(v_section->'permissions') <> 2 THEN
        RAISE EXCEPTION 'config_get should answer the service''s permissions: %', v_section;
    END IF;
    IF NOT EXISTS (SELECT 1 FROM jsonb_array_elements(v_section->'permissions') p
                   WHERE p->>'feature' = 'configuration' AND p->>'act' = 'edit'
                     AND p->>'class' = 'tenantConfiguration') THEN
        RAISE EXCEPTION 'config_get should carry each permission''s class: %', v_section;
    END IF;
    IF NOT EXISTS (SELECT 1 FROM jsonb_array_elements(v_section->'permissions') p
                   WHERE p->>'feature' = 'configuration' AND p->>'act' = 'edit'
                     AND p->>'plane' = 'tenant' AND p->'retired' = 'false'::jsonb
                     AND p->'labels'->>'lv' = 'Mainīt konfigurāciju'
                     AND p->'labels'->>'de' = 'Konfiguration ändern') THEN
        RAISE EXCEPTION 'config_get should carry each permission''s plane, labels and retired mark: %', v_section;
    END IF;

    -- The whole document read back re-applies as all-unchanged.
    CALL rolebyte.config_apply(jsonb_build_object(
        'tenantId', v_tenant, 'actor', 'permission-test', 'section', v->'data'), v);
    IF v->>'result' IS DISTINCT FROM 'success' THEN
        RAISE EXCEPTION 'round-trip apply failed: %', v;
    END IF;
    IF EXISTS (SELECT 1 FROM jsonb_array_elements(v->'data'->'permissions') e WHERE e->>'status' <> 'unchanged') THEN
        RAISE EXCEPTION 'a round trip should change no permission: %', v;
    END IF;

    -- 11. One refused entry rolls the whole section back — the service before it and
    --     the permission before it included.
    BEGIN
        CALL rolebyte.config_apply(jsonb_build_object(
            'tenantId', v_tenant, 'actor', 'permission-test',
            'section', '{"services":[
              {"key":"permpoison","displayName":"Should not survive","roles":[],
               "permissions":[{"feature":"task","act":"view","class":"ordinary","plane":"object"}]},
              {"key":"permcfg","displayName":"Permission config demo","roles":[],
               "permissions":[{"feature":"spentTime","act":"viewAll","class":"tenantConfiguration","plane":"tenant"}]}
            ]}'::jsonb), v);
        RAISE EXCEPTION 'a re-classing document should have been refused';
    EXCEPTION WHEN sqlstate 'P0001' THEN
        IF SQLERRM NOT LIKE '%membership:conflict%' THEN
            RAISE EXCEPTION 'the refused document raised the wrong code: %', SQLERRM;
        END IF;
    END;
    IF EXISTS (SELECT 1 FROM rolebyte.service WHERE key = 'permpoison')
       OR EXISTS (SELECT 1 FROM rolebyte.service_permission WHERE service_key = 'permpoison') THEN
        RAISE EXCEPTION 'a refused document must write nothing';
    END IF;

    BEGIN
        CALL rolebyte.config_apply(jsonb_build_object(
            'tenantId', v_tenant, 'actor', 'permission-test',
            'section', '{"services":[{"key":"permcfg","roles":[],"permissions":{"feature":"task"}}]}'::jsonb), v);
        RAISE EXCEPTION 'permissions that are not a list should have been refused';
    EXCEPTION WHEN sqlstate 'P0001' THEN
        IF SQLERRM NOT LIKE '%membership:config_bad_document%' THEN
            RAISE EXCEPTION 'a non-list permissions entry raised the wrong code: %', SQLERRM;
        END IF;
    END;

    -- 12. Every permission says where it may be granted, and that never changes.
    IF (SELECT plane FROM rolebyte.service_permission
         WHERE service_key = 'permdemo' AND feature_key = 'task/attachment' AND act = 'deleteAny')
       IS DISTINCT FROM 'object' THEN
        RAISE EXCEPTION 'the declared plane should be stored';
    END IF;
    PERFORM pg_temp.refused('permdemo', '{"feature":"task","act":"view","class":"ordinary"}'::jsonb,
        'membership:invalid', 'a missing plane');
    PERFORM pg_temp.refused('permdemo', '{"feature":"task","act":"view","class":"ordinary","plane":"project"}'::jsonb,
        'membership:invalid', 'an unknown plane');
    PERFORM pg_temp.refused('permdemo', '{"feature":"task","act":"view","class":"ordinary","plane":7}'::jsonb,
        'membership:invalid', 'a number for a plane');
    v := pg_temp.declare('permdemo', '{"feature":"task/attachment","act":"deleteAny",
        "description":"Remove a file anyone attached to a task","class":"ordinary","plane":"tenant"}'::jsonb);
    IF v->>'code' IS DISTINCT FROM 'membership:conflict'
       OR v->>'message' NOT LIKE '%permdemo/task/attachment:deleteAny%' THEN
        RAISE EXCEPTION 'a moved plane should be refused, naming the permission: %', v;
    END IF;
    IF (SELECT plane FROM rolebyte.service_permission
         WHERE service_key = 'permdemo' AND feature_key = 'task/attachment' AND act = 'deleteAny')
       IS DISTINCT FROM 'object' THEN
        RAISE EXCEPTION 'a refused move must leave the plane as declared';
    END IF;

    --     A permission declared before planes existed takes its plane once, from
    --     its next declaration, and keeps it.
    UPDATE rolebyte.service_permission SET plane = NULL
     WHERE service_key = 'permdemo' AND feature_key = 'task' AND act = 'deleteAny';
    v := pg_temp.declare('permdemo', '{"feature":"task","act":"deleteAny","class":"ordinary","plane":"object"}'::jsonb);
    IF v->'data'->>'status' IS DISTINCT FROM 'changed' THEN
        RAISE EXCEPTION 'a permission without a plane should take one: %', v;
    END IF;
    IF NOT EXISTS (SELECT 1 FROM rolebyte.event
                   WHERE kind = 'permissionPlaneDeclared'
                     AND payload->>'permission' = 'permdemo/task:deleteAny'
                     AND payload->>'plane' = 'object') THEN
        RAISE EXCEPTION 'taking a plane must land in the event stream';
    END IF;
    PERFORM pg_temp.refused('permdemo', '{"feature":"task","act":"deleteAny","class":"ordinary","plane":"tenant"}'::jsonb,
        'membership:conflict', 'a plane moved after it was taken');

    -- 13. A permission carries its label per language; a changed label is an
    --     update and history, the same labels again change nothing, and a label
    --     map that is not one is refused.
    v := pg_temp.declare('permdemo', '{"feature":"task/attachment","act":"deleteAny",
        "description":"Remove a file anyone attached to a task","class":"ordinary","plane":"object",
        "labels":{"lv":"  Noņemt jebkuru failu  ","pt-BR":"Remover qualquer arquivo"}}'::jsonb);
    IF v->'data'->>'status' IS DISTINCT FROM 'changed' THEN
        RAISE EXCEPTION 'new labels should be changed: %', v;
    END IF;
    IF (SELECT labels->>'lv' FROM rolebyte.service_permission
         WHERE service_key = 'permdemo' AND feature_key = 'task/attachment' AND act = 'deleteAny')
       IS DISTINCT FROM 'Noņemt jebkuru failu' THEN
        RAISE EXCEPTION 'a label should be stored trimmed';
    END IF;
    IF NOT EXISTS (SELECT 1 FROM rolebyte.event
                   WHERE kind = 'permissionLabelled'
                     AND payload->>'permission' = 'permdemo/task/attachment:deleteAny'
                     AND payload->'from' = '{}'::jsonb
                     AND payload->'to'->>'lv' = 'Noņemt jebkuru failu') THEN
        RAISE EXCEPTION 'a label change must land in the event stream with both maps';
    END IF;
    SELECT count(*) INTO v_events FROM rolebyte.event;
    v := pg_temp.declare('permdemo', '{"feature":"task/attachment","act":"deleteAny",
        "description":"Remove a file anyone attached to a task","class":"ordinary","plane":"object",
        "labels":{"pt-BR":"Remover qualquer arquivo","lv":"Noņemt jebkuru failu"}}'::jsonb);
    IF v->'data'->>'status' IS DISTINCT FROM 'unchanged' OR (SELECT count(*) FROM rolebyte.event) <> v_events THEN
        RAISE EXCEPTION 'the same labels again should change nothing: %', v;
    END IF;
    PERFORM pg_temp.refused('permdemo', '{"feature":"task","act":"view","class":"ordinary","plane":"object",
        "labels":"Skatīt"}'::jsonb, 'membership:invalid', 'labels that are not a map');
    PERFORM pg_temp.refused('permdemo', '{"feature":"task","act":"view","class":"ordinary","plane":"object",
        "labels":{"LV":"Skatīt"}}'::jsonb, 'membership:invalid', 'an upper-case language tag');
    PERFORM pg_temp.refused('permdemo', '{"feature":"task","act":"view","class":"ordinary","plane":"object",
        "labels":{"latvian":"Skatīt"}}'::jsonb, 'membership:invalid', 'a language name for a tag');
    PERFORM pg_temp.refused('permdemo', '{"feature":"task","act":"view","class":"ordinary","plane":"object",
        "labels":{"lv":"   "}}'::jsonb, 'membership:invalid', 'an empty label');
    PERFORM pg_temp.refused('permdemo', '{"feature":"task","act":"view","class":"ordinary","plane":"object",
        "labels":{"lv":7}}'::jsonb, 'membership:invalid', 'a number for a label');

    --     Leaving the labels out clears them, as a declaration is the whole truth.
    v := pg_temp.declare('permdemo', '{"feature":"task/attachment","act":"deleteAny",
        "description":"Remove a file anyone attached to a task","class":"ordinary","plane":"object"}'::jsonb);
    IF v->'data'->>'status' IS DISTINCT FROM 'changed'
       OR (SELECT labels FROM rolebyte.service_permission
            WHERE service_key = 'permdemo' AND feature_key = 'task/attachment' AND act = 'deleteAny') <> '{}'::jsonb THEN
        RAISE EXCEPTION 'a declaration without labels should clear them: %', v;
    END IF;

    --     The table holds the same shape whatever writes to it.
    BEGIN
        UPDATE rolebyte.service_permission SET labels = '{"LV":"x"}'::jsonb
         WHERE service_key = 'permdemo' AND feature_key = 'task/attachment' AND act = 'deleteAny';
        RAISE EXCEPTION 'the table should refuse a bad label map';
    EXCEPTION WHEN check_violation THEN NULL;
    END;
    BEGIN
        UPDATE rolebyte.service_permission SET plane = 'project'
         WHERE service_key = 'permdemo' AND feature_key = 'task/attachment' AND act = 'deleteAny';
        RAISE EXCEPTION 'the table should refuse an unknown plane';
    EXCEPTION WHEN check_violation THEN NULL;
    END;

    -- 14. A permission is retired by declaring it so, and brought back by
    --     declaring it without the mark; each is an update and history.
    v := pg_temp.declare('permdemo', '{"feature":"task","act":"deleteAny","class":"ordinary","plane":"object","retired":true}'::jsonb);
    IF v->'data'->>'status' IS DISTINCT FROM 'changed'
       OR (SELECT retired_at FROM rolebyte.service_permission
            WHERE service_key = 'permdemo' AND feature_key = 'task' AND act = 'deleteAny') IS NULL THEN
        RAISE EXCEPTION 'declaring a permission retired should retire it: %', v;
    END IF;
    SELECT count(*) INTO v_events FROM rolebyte.event;
    v := pg_temp.declare('permdemo', '{"feature":"task","act":"deleteAny","class":"ordinary","plane":"object","retired":true}'::jsonb);
    IF v->'data'->>'status' IS DISTINCT FROM 'unchanged' OR (SELECT count(*) FROM rolebyte.event) <> v_events THEN
        RAISE EXCEPTION 'retiring a retired permission should change nothing: %', v;
    END IF;
    v := pg_temp.declare('permdemo', '{"feature":"task","act":"deleteAny","class":"ordinary","plane":"object","retired":false}'::jsonb);
    IF v->'data'->>'status' IS DISTINCT FROM 'changed'
       OR (SELECT retired_at FROM rolebyte.service_permission
            WHERE service_key = 'permdemo' AND feature_key = 'task' AND act = 'deleteAny') IS NOT NULL
       OR NOT EXISTS (SELECT 1 FROM rolebyte.event WHERE kind = 'permissionReinstated'
                       AND payload->>'permission' = 'permdemo/task:deleteAny') THEN
        RAISE EXCEPTION 'declaring it without the mark should bring it back: %', v;
    END IF;
    PERFORM pg_temp.refused('permdemo', '{"feature":"task","act":"view","class":"ordinary","plane":"object",
        "retired":"yes"}'::jsonb, 'membership:invalid', 'a retired mark that is not true or false');
    v := pg_temp.declare('permdemo', '{"feature":"task","act":"archive","class":"ordinary","plane":"object","retired":true}'::jsonb);
    IF v->'data'->>'status' IS DISTINCT FROM 'added'
       OR (SELECT retired_at FROM rolebyte.service_permission
            WHERE service_key = 'permdemo' AND feature_key = 'task' AND act = 'archive') IS NULL THEN
        RAISE EXCEPTION 'a permission first declared retired should be stored retired: %', v;
    END IF;

    RAISE NOTICE 'unit.rolebyte_permission: all assertions passed';
END $$;

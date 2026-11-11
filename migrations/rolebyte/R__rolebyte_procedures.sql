-- R (repeatable): rolebyte procedure bodies. Re-applied whenever this file's
-- checksum changes; table/role changes belong in versioned migrations.
--
-- Every procedure is SECURITY DEFINER with a pinned search_path, takes the
-- uniform (pi_data jsonb, INOUT po_data jsonb) envelope, and returns through
-- util.result_success / util.result_error('<domain>:<reason>', ...). Error
-- domains follow the resource, not the service: `tenant:*` for the tenant
-- register, `membership:*` for everything about people and their roles.
--
-- Two invariants every body below preserves:
--   1. Every state change is FIRST an attributed event (the append-only
--      stream is the source of truth; the tables are the fast projection).
--      No procedure mutates `event` — and none may ever be added: the guard
--      trigger raising on UPDATE/DELETE is the second, independent layer.
--   2. Administration is tenant-scoped: admin procedures take the tenant and
--      filter on it, and a foreign tenant's row answers `not_found`,
--      indistinguishable from absence. Only `claim_attach` and `resolve` are
--      subject-keyed — they exist to answer "which tenants know this
--      authenticated person", which is the identity provider's question —
--      and the person's own settings (`person_language_get` / `_set`), which
--      belong to the person and to no tenant.

-- ping — the data-path proof for the walking skeleton: echoes its input and
-- returns a freshly generated id, proving that the EXECUTE-only role can call
-- a procedure and that the shared util helpers resolve. Carries no data.
CREATE OR REPLACE PROCEDURE rolebyte.ping(IN pi_data jsonb, INOUT po_data jsonb)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = rolebyte, util, pg_temp
AS $$
BEGIN
    po_data := util.result_success(jsonb_build_object(
        'echo', COALESCE(pi_data->>'echo', ''),
        'id',   util.generate_ulid()
    ));
EXCEPTION
    WHEN sqlstate 'P0001' THEN
        RAISE;
    WHEN OTHERS THEN
        RAISE EXCEPTION '%', util.result_error('membership:error', sqlerrm) USING errcode = 'P0001';
END;
$$;

REVOKE ALL ON PROCEDURE rolebyte.ping(jsonb, jsonb) FROM PUBLIC;
GRANT EXECUTE ON PROCEDURE rolebyte.ping(jsonb, jsonb) TO rolebyte_public;

-- tenant_create — register the paying organisation, with the roles every new
-- tenant starts with (see seed_roles). Emits `tenantCreated` and a
-- `tenantRoleSeeded` per role.
CREATE OR REPLACE PROCEDURE rolebyte.tenant_create(IN pi_data jsonb, INOUT po_data jsonb)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = rolebyte, util, pg_temp
AS $$
DECLARE
    v_actor text;
    v_name  text;
    v_row   rolebyte.tenant%ROWTYPE;
BEGIN
    v_actor := NULLIF(trim(pi_data->>'actor'), '');
    IF v_actor IS NULL THEN
        po_data := util.result_error('tenant:invalid', 'actor is required');
        RETURN;
    END IF;

    v_name := NULLIF(trim(pi_data->>'name'), '');
    IF v_name IS NULL THEN
        po_data := util.result_error('tenant:invalid', 'name is required');
        RETURN;
    END IF;

    INSERT INTO rolebyte.tenant (id, name)
    VALUES (util.generate_ulid(), v_name)
    RETURNING * INTO v_row;

    INSERT INTO rolebyte.event (id, actor, tenant_id, kind, payload)
    VALUES (util.generate_ulid(), v_actor, v_row.id, 'tenantCreated',
            jsonb_build_object('name', v_row.name));

    -- Every new tenant starts with the roles the register creates for it.
    PERFORM rolebyte.seed_roles(v_actor, v_row.id, NULLIF(btrim(pi_data->>'language'), ''));

    po_data := util.result_success(jsonb_build_object(
        'id',        v_row.id,
        'name',      v_row.name,
        'status',    v_row.status,
        'createdAt', v_row.created_at
    ));
EXCEPTION
    WHEN sqlstate 'P0001' THEN
        RAISE;
    WHEN OTHERS THEN
        RAISE EXCEPTION '%', util.result_error('membership:error', sqlerrm) USING errcode = 'P0001';
END;
$$;

REVOKE ALL ON PROCEDURE rolebyte.tenant_create(jsonb, jsonb) FROM PUBLIC;
GRANT EXECUTE ON PROCEDURE rolebyte.tenant_create(jsonb, jsonb) TO rolebyte_public;

-- service_register — a consumer service is registered (idempotent upsert), by
-- whoever runs the deployment. Emits `serviceRegistered` only when the row is new.
CREATE OR REPLACE PROCEDURE rolebyte.service_register(IN pi_data jsonb, INOUT po_data jsonb)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = rolebyte, util, pg_temp
AS $$
DECLARE
    v_actor    text;
    v_key      text;
    v_display  text;
    v_inserted boolean;
BEGIN
    v_actor := NULLIF(trim(pi_data->>'actor'), '');
    IF v_actor IS NULL THEN
        po_data := util.result_error('membership:invalid', 'actor is required');
        RETURN;
    END IF;

    v_key := NULLIF(trim(pi_data->>'service'), '');
    IF v_key IS NULL THEN
        po_data := util.result_error('membership:invalid', 'service is required');
        RETURN;
    END IF;

    -- `deployment` is the register's own word: a permission is spelled
    -- service/feature:act, so a service under this key could declare a scope that
    -- reads as one of the deployment's own group.
    IF v_key = 'deployment' THEN
        po_data := util.result_error('membership:invalid', 'the service key deployment is the register''s own and is not a service');
        RETURN;
    END IF;

    v_display := COALESCE(NULLIF(trim(pi_data->>'displayName'), ''), v_key);

    INSERT INTO rolebyte.service (key, display_name)
    VALUES (v_key, v_display)
    ON CONFLICT (key) DO NOTHING;
    v_inserted := FOUND;

    IF v_inserted THEN
        INSERT INTO rolebyte.event (id, actor, kind, payload)
        VALUES (util.generate_ulid(), v_actor, 'serviceRegistered',
                jsonb_build_object('service', v_key, 'displayName', v_display));
    END IF;

    po_data := util.result_success(jsonb_build_object(
        'service', v_key,
        'created', v_inserted
    ));
EXCEPTION
    WHEN sqlstate 'P0001' THEN
        RAISE;
    WHEN OTHERS THEN
        RAISE EXCEPTION '%', util.result_error('membership:error', sqlerrm) USING errcode = 'P0001';
END;
$$;

-- The deployment's list, not a tenant's: the procedures that write it run as the
-- location's owner, from the deployment's own tools, and the register's role is
-- refused them. A grant an earlier release gave is taken back here, because a
-- repeatable file's CREATE OR REPLACE keeps it.
REVOKE ALL ON PROCEDURE rolebyte.service_register(jsonb, jsonb) FROM PUBLIC;
REVOKE EXECUTE ON PROCEDURE rolebyte.service_register(jsonb, jsonb) FROM rolebyte_public;

-- role_define — one (group, level) role of a service, as data (idempotent
-- upsert), defined by whoever runs the deployment. Emits `roleDefined` only when the row is new.
-- The group `deployment` is the register's own and is refused for every service
-- (`membership:invalid`): it is not a level anything may define.
CREATE OR REPLACE PROCEDURE rolebyte.role_define(IN pi_data jsonb, INOUT po_data jsonb)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = rolebyte, util, pg_temp
AS $$
DECLARE
    v_actor    text;
    v_service  text;
    v_group    text;
    v_level    text;
    v_desc     text;
    v_id       text;
    v_inserted boolean;
BEGIN
    v_actor := NULLIF(trim(pi_data->>'actor'), '');
    IF v_actor IS NULL THEN
        po_data := util.result_error('membership:invalid', 'actor is required');
        RETURN;
    END IF;

    v_service := NULLIF(trim(pi_data->>'service'), '');
    v_group   := NULLIF(trim(pi_data->>'group'), '');
    v_level   := NULLIF(trim(pi_data->>'level'), '');
    IF v_service IS NULL OR v_group IS NULL OR v_level IS NULL THEN
        po_data := util.result_error('membership:invalid', 'service, group and level are required');
        RETURN;
    END IF;

    -- A role is rendered into a token as group:level, and a scope is split on white
    -- space where a token is read, including white space outside ASCII (a no-break
    -- space, say), which a list of forbidden characters would miss. So only a
    -- known-safe alphabet is accepted: a group and a level are each one lower-case
    -- word. That also keeps out `/`, which marks a permission, and `:`.
    IF v_group !~ '^[a-z][a-z0-9-]{0,63}$' THEN
        po_data := util.result_error('membership:invalid', 'a role group is a lower-case word of letters, digits and hyphens, at most 64 characters long');
        RETURN;
    END IF;
    IF v_level !~ '^[a-z][a-z0-9-]{0,63}$' THEN
        po_data := util.result_error('membership:invalid', 'a role level is a lower-case word of letters, digits and hyphens, at most 64 characters long');
        RETURN;
    END IF;
    -- The register's own group: nothing may define a level in it.
    IF v_group = 'deployment' THEN
        po_data := util.result_error('membership:invalid', 'the group deployment is the register''s own and is not a level anything may define');
        RETURN;
    END IF;

    IF NOT EXISTS (SELECT 1 FROM rolebyte.service WHERE key = v_service) THEN
        po_data := util.result_error('membership:not_found', 'service is not registered');
        RETURN;
    END IF;

    v_desc := COALESCE(trim(pi_data->>'description'), '');

    INSERT INTO rolebyte.role_definition (id, service_key, role_group, role_level, description)
    VALUES (util.generate_ulid(), v_service, v_group, v_level, v_desc)
    ON CONFLICT (service_key, role_group, role_level) DO NOTHING;
    v_inserted := FOUND;

    SELECT id INTO v_id
    FROM rolebyte.role_definition
    WHERE service_key = v_service AND role_group = v_group AND role_level = v_level;

    IF v_inserted THEN
        INSERT INTO rolebyte.event (id, actor, kind, payload)
        VALUES (util.generate_ulid(), v_actor, 'roleDefined',
                jsonb_build_object('service', v_service, 'group', v_group, 'level', v_level));
    END IF;

    po_data := util.result_success(jsonb_build_object(
        'id',      v_id,
        'created', v_inserted
    ));
EXCEPTION
    WHEN sqlstate 'P0001' THEN
        RAISE;
    WHEN OTHERS THEN
        RAISE EXCEPTION '%', util.result_error('membership:error', sqlerrm) USING errcode = 'P0001';
END;
$$;

-- The deployment's list, not a tenant's: the procedures that write it run as the
-- location's owner, from the deployment's own tools, and the register's role is
-- refused them. A grant an earlier release gave is taken back here, because a
-- repeatable file's CREATE OR REPLACE keeps it.
REVOKE ALL ON PROCEDURE rolebyte.role_define(jsonb, jsonb) FROM PUBLIC;
REVOKE EXECUTE ON PROCEDURE rolebyte.role_define(jsonb, jsonb) FROM rolebyte_public;

-- permission_declare — a service declares one act it enforces on one of its
-- features. Additive: a new permission is created, an identical one reports
-- `unchanged`, and a changed description, labels or retired mark is updated and
-- reports `changed`. A permission's class and plane never change — re-classing
-- would change who may hand it out, and moving it between planes would move a
-- right between tenant-wide grants and grants placed on objects — so a
-- declaration naming a different one is refused, naming the permission. A
-- permission declared before planes existed takes its plane from its next
-- declaration. The declaration is read strictly: a property this register does
-- not know is refused rather than dropped, so a later property carrying a
-- requirement can never be stored without it. Emits `permissionDeclared` for a
-- new permission, and for an existing one `permissionDescribed`,
-- `permissionLabelled`, `permissionPlaneDeclared`, `permissionSeeded`,
-- `permissionRetired` or `permissionReinstated` for each thing that changed;
-- nothing otherwise; the answer's `changes` names each of those members. `seeds`
-- names the roles the register creates with every new tenant that hold the
-- permission (`worker`, `manager`; Guest holds nothing); only an ordinary
-- permission on the object plane carries any.
CREATE OR REPLACE PROCEDURE rolebyte.permission_declare(IN pi_data jsonb, INOUT po_data jsonb)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = rolebyte, util, pg_temp
AS $$
DECLARE
    v_actor   text;
    v_service text;
    v_decl    jsonb;
    v_unknown text;
    v_feature text;
    v_act     text;
    v_desc    text;
    v_class   text;
    v_plane   text;
    v_labels  jsonb;
    v_retired boolean;
    v_seeds   text[];
    v_name    text;
    v_changed boolean := false;
    v_changes text[] := '{}'::text[];
    v_row     rolebyte.service_permission%ROWTYPE;
BEGIN
    v_actor := NULLIF(trim(pi_data->>'actor'), '');
    IF v_actor IS NULL THEN
        po_data := util.result_error('membership:invalid', 'actor is required');
        RETURN;
    END IF;

    v_service := NULLIF(trim(pi_data->>'service'), '');
    IF v_service IS NULL THEN
        po_data := util.result_error('membership:invalid', 'service is required');
        RETURN;
    END IF;

    v_decl := pi_data->'permission';
    IF jsonb_typeof(v_decl) IS DISTINCT FROM 'object' THEN
        po_data := util.result_error('membership:invalid', 'permission must be an object');
        RETURN;
    END IF;

    SELECT k INTO v_unknown
    FROM jsonb_object_keys(v_decl) AS k
    WHERE k NOT IN ('feature', 'act', 'description', 'class', 'plane', 'labels', 'retired', 'seeds')
    ORDER BY k
    LIMIT 1;
    IF v_unknown IS NOT NULL THEN
        po_data := util.result_error('membership:invalid',
            format('a permission has no property "%s"', v_unknown));
        RETURN;
    END IF;

    IF jsonb_typeof(v_decl->'feature') IS DISTINCT FROM 'string'
       OR jsonb_typeof(v_decl->'act') IS DISTINCT FROM 'string'
       OR jsonb_typeof(v_decl->'class') IS DISTINCT FROM 'string'
       OR jsonb_typeof(v_decl->'plane') IS DISTINCT FROM 'string'
       OR (v_decl ? 'description' AND jsonb_typeof(v_decl->'description') IS DISTINCT FROM 'string') THEN
        po_data := util.result_error('membership:invalid',
            'feature, act, class and plane are required strings, and description is a string');
        RETURN;
    END IF;
    IF v_decl ? 'labels' AND rolebyte.is_permission_labels(v_decl->'labels') IS NOT TRUE THEN
        po_data := util.result_error('membership:invalid',
            'labels must map a language tag such as "lv" to a non-empty label');
        RETURN;
    END IF;
    IF v_decl ? 'retired' AND jsonb_typeof(v_decl->'retired') IS DISTINCT FROM 'boolean' THEN
        po_data := util.result_error('membership:invalid', 'retired must be true or false');
        RETURN;
    END IF;
    IF v_decl ? 'seeds' AND (jsonb_typeof(v_decl->'seeds') IS DISTINCT FROM 'array'
        OR EXISTS (SELECT 1 FROM jsonb_array_elements(v_decl->'seeds') e
                    WHERE jsonb_typeof(e) <> 'string' OR (e #>> '{}') NOT IN ('worker', 'manager', 'assistant'))
        OR (SELECT count(DISTINCT e #>> '{}') FROM jsonb_array_elements(v_decl->'seeds') e)
           <> jsonb_array_length(v_decl->'seeds')) THEN
        po_data := util.result_error('membership:invalid',
            'seeds name the shipped roles that hold the permission: "worker", "manager", "assistant", each once');
        RETURN;
    END IF;

    v_feature := v_decl->>'feature';
    v_act     := v_decl->>'act';
    v_class   := v_decl->>'class';
    v_plane   := v_decl->>'plane';
    v_desc    := COALESCE(trim(v_decl->>'description'), '');
    v_retired := COALESCE((v_decl->>'retired')::boolean, false);
    v_seeds   := COALESCE(ARRAY(SELECT e FROM jsonb_array_elements_text(COALESCE(v_decl->'seeds', '[]'::jsonb)) e
                                ORDER BY e COLLATE "C"), '{}');
    SELECT COALESCE(jsonb_object_agg(l.lang, btrim(l.label #>> '{}')), '{}'::jsonb)
      INTO v_labels
      FROM jsonb_each(COALESCE(v_decl->'labels', '{}'::jsonb)) AS l(lang, label);

    IF NOT rolebyte.is_permission_feature(v_feature) THEN
        po_data := util.result_error('membership:invalid',
            'feature must be one or more lower-camel words joined by "/"');
        RETURN;
    END IF;
    IF NOT rolebyte.is_permission_act(v_act) THEN
        po_data := util.result_error('membership:invalid', 'act must be one lower-camel word');
        RETURN;
    END IF;
    IF v_class NOT IN ('ordinary', 'tenantConfiguration', 'roleManagement', 'perField') THEN
        po_data := util.result_error('membership:invalid',
            'class must be ordinary, tenantConfiguration, roleManagement or perField');
        RETURN;
    END IF;
    IF v_plane NOT IN ('tenant', 'object', 'chart') THEN
        po_data := util.result_error('membership:invalid', 'plane must be tenant, object or chart');
        RETURN;
    END IF;
    IF v_plane = 'chart' AND v_class <> 'ordinary' THEN
        po_data := util.result_error('membership:invalid',
            'a permission a position in the chart carries is ordinary in class');
        RETURN;
    END IF;
    IF v_class = 'perField' AND v_plane <> 'object' THEN
        po_data := util.result_error('membership:invalid',
            'a per-field family is held where a role is placed, so its plane is object');
        RETURN;
    END IF;
    IF cardinality(v_seeds) > 0 AND (v_plane <> 'object' OR v_class <> 'ordinary') THEN
        po_data := util.result_error('membership:invalid',
            'only an ordinary permission on the object plane is given to a seeded role');
        RETURN;
    END IF;

    IF NOT EXISTS (SELECT 1 FROM rolebyte.service WHERE key = v_service) THEN
        po_data := util.result_error('membership:not_found', 'service is not registered');
        RETURN;
    END IF;
    IF NOT rolebyte.is_permission_service(v_service) THEN
        po_data := util.result_error('membership:invalid',
            'this service key cannot open a permission: lower-case letters, digits and "-" only');
        RETURN;
    END IF;

    v_name := v_service || '/' || v_feature || ':' || v_act;

    SELECT * INTO v_row
    FROM rolebyte.service_permission
    WHERE service_key = v_service AND feature_key = v_feature AND act = v_act
    FOR UPDATE;

    IF NOT FOUND THEN
        INSERT INTO rolebyte.service_permission
               (id, service_key, feature_key, act, description, class, plane, labels, retired_at, seeds)
        VALUES (util.generate_ulid(), v_service, v_feature, v_act, v_desc, v_class, v_plane, v_labels,
                CASE WHEN v_retired THEN now() END, v_seeds)
        ON CONFLICT (service_key, feature_key, act) DO NOTHING;
        IF NOT FOUND THEN
            -- A concurrent declaration of the same permission won the insert:
            -- read what it stored and answer against that.
            SELECT * INTO v_row
            FROM rolebyte.service_permission
            WHERE service_key = v_service AND feature_key = v_feature AND act = v_act
            FOR UPDATE;
        ELSE
            INSERT INTO rolebyte.event (id, actor, kind, payload)
            VALUES (util.generate_ulid(), v_actor, 'permissionDeclared',
                    jsonb_build_object('service', v_service, 'permission', v_name, 'class', v_class,
                                       'plane', v_plane, 'retired', v_retired));
            po_data := util.result_success(jsonb_build_object('permission', v_name, 'status', 'added'));
            RETURN;
        END IF;
    END IF;

    IF v_row.class <> v_class THEN
        po_data := util.result_error('membership:conflict',
            format('%s is declared as %s, and a permission''s class never changes', v_name, v_row.class));
        RETURN;
    END IF;
    IF v_row.plane IS NOT NULL AND v_row.plane <> v_plane THEN
        po_data := util.result_error('membership:conflict',
            format('%s is declared as a %s permission, and a permission''s plane never changes',
                   v_name, v_row.plane));
        RETURN;
    END IF;

    IF v_row.plane IS NULL THEN
        UPDATE rolebyte.service_permission SET plane = v_plane WHERE id = v_row.id;
        INSERT INTO rolebyte.event (id, actor, kind, payload)
        VALUES (util.generate_ulid(), v_actor, 'permissionPlaneDeclared',
                jsonb_build_object('service', v_service, 'permission', v_name, 'plane', v_plane));
        v_changed := true;
        v_changes := v_changes || 'plane'::text;
    END IF;

    IF v_row.description <> v_desc THEN
        UPDATE rolebyte.service_permission SET description = v_desc WHERE id = v_row.id;
        INSERT INTO rolebyte.event (id, actor, kind, payload)
        VALUES (util.generate_ulid(), v_actor, 'permissionDescribed',
                jsonb_build_object('service', v_service, 'permission', v_name,
                                   'from', v_row.description, 'to', v_desc));
        v_changed := true;
        v_changes := v_changes || 'description'::text;
    END IF;

    IF v_row.labels <> v_labels THEN
        UPDATE rolebyte.service_permission SET labels = v_labels WHERE id = v_row.id;
        INSERT INTO rolebyte.event (id, actor, kind, payload)
        VALUES (util.generate_ulid(), v_actor, 'permissionLabelled',
                jsonb_build_object('service', v_service, 'permission', v_name,
                                   'from', v_row.labels, 'to', v_labels));
        v_changed := true;
        v_changes := v_changes || 'labels'::text;
    END IF;

    IF v_row.seeds <> v_seeds THEN
        UPDATE rolebyte.service_permission SET seeds = v_seeds WHERE id = v_row.id;
        INSERT INTO rolebyte.event (id, actor, kind, payload)
        VALUES (util.generate_ulid(), v_actor, 'permissionSeeded',
                jsonb_build_object('service', v_service, 'permission', v_name,
                                   'from', to_jsonb(v_row.seeds), 'to', to_jsonb(v_seeds)));
        v_changed := true;
        v_changes := v_changes || 'seeds'::text;
    END IF;

    IF (v_row.retired_at IS NOT NULL) <> v_retired THEN
        UPDATE rolebyte.service_permission
           SET retired_at = CASE WHEN v_retired THEN now() END
         WHERE id = v_row.id;
        INSERT INTO rolebyte.event (id, actor, kind, payload)
        VALUES (util.generate_ulid(), v_actor,
                CASE WHEN v_retired THEN 'permissionRetired' ELSE 'permissionReinstated' END,
                jsonb_build_object('service', v_service, 'permission', v_name));
        v_changed := true;
        v_changes := v_changes || 'retired'::text;
    END IF;

    po_data := util.result_success(jsonb_build_object('permission', v_name,
        'status', CASE WHEN v_changed THEN 'changed' ELSE 'unchanged' END,
        'changes', to_jsonb(v_changes)));
EXCEPTION
    WHEN sqlstate 'P0001' THEN
        RAISE;
    WHEN OTHERS THEN
        RAISE EXCEPTION '%', util.result_error('membership:error', sqlerrm) USING errcode = 'P0001';
END;
$$;

-- The deployment's list, not a tenant's: the procedures that write it run as the
-- location's owner, from the deployment's own tools, and the register's role is
-- refused them. A grant an earlier release gave is taken back here, because a
-- repeatable file's CREATE OR REPLACE keeps it.
REVOKE ALL ON PROCEDURE rolebyte.permission_declare(jsonb, jsonb) FROM PUBLIC;
REVOKE EXECUTE ON PROCEDURE rolebyte.permission_declare(jsonb, jsonb) FROM rolebyte_public;

-- user_invite — a tenant admin adds a person by typed subject key, with the
-- role grants they should hold, status `invited`. All requested roles are
-- validated BEFORE any write so the call is atomic at the envelope level.
-- Emits `userInvited` + one `roleGranted` per role.
CREATE OR REPLACE PROCEDURE rolebyte.user_invite(IN pi_data jsonb, INOUT po_data jsonb)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = rolebyte, util, pg_temp
AS $$
DECLARE
    v_actor   text;
    v_tenant  text;
    v_subject text;
    v_display text;
    v_roles   jsonb;
    v_role    jsonb;
    v_defs    text[] := '{}'::text[];
    v_def_id  text;
    v_user    rolebyte.user_account%ROWTYPE;
    v_type    text;
BEGIN
    v_actor := NULLIF(trim(pi_data->>'actor'), '');
    IF v_actor IS NULL THEN
        po_data := util.result_error('membership:invalid', 'actor is required');
        RETURN;
    END IF;

    v_tenant := NULLIF(trim(pi_data->>'tenantId'), '');
    IF v_tenant IS NULL THEN
        po_data := util.result_error('membership:invalid', 'tenantId is required');
        RETURN;
    END IF;

    IF NOT EXISTS (SELECT 1 FROM rolebyte.tenant WHERE id = v_tenant) THEN
        po_data := util.result_error('tenant:not_found', 'tenant does not exist');
        RETURN;
    END IF;

    -- The key must be of a kind this register defines: a person by their platform
    -- subject (`sub:<person id>` — the identifier the identity store keys them on,
    -- and the `sub` of every token issued for them), a machine by its client id
    -- (`svc:<client id>`). The key an administrator types must be identical to the
    -- key the invited person's own login will produce, or the invitation is one
    -- nobody can claim and nothing says why — so a person is invited by their
    -- subject, obtained from the identity store, never by a spelling of something
    -- else. The column's constraint refuses any other kind; this is the pre-check
    -- that turns a would-be constraint violation into a structured error.
    --
    -- The message deliberately does not echo the value: this text reaches logs.
    v_subject := NULLIF(trim(pi_data->>'subjectKey'), '');
    IF v_subject IS NULL OR NOT rolebyte.is_typed_subject_key(v_subject) THEN
        po_data := util.result_error('membership:invalid',
            'subjectKey must be a typed key: sub:<person id> for a person, svc:<client id> for a service account');
        RETURN;
    END IF;

    v_display := NULLIF(trim(pi_data->>'displayName'), '');
    IF v_display IS NULL THEN
        po_data := util.result_error('membership:invalid', 'displayName is required');
        RETURN;
    END IF;

    IF EXISTS (SELECT 1 FROM rolebyte.user_account
               WHERE tenant_id = v_tenant AND subject_key = v_subject) THEN
        po_data := util.result_error('membership:conflict', 'this subject already exists in the tenant');
        RETURN;
    END IF;

    -- Validate every requested role before the first write.
    v_roles := COALESCE(pi_data->'roles', '[]'::jsonb);
    IF jsonb_typeof(v_roles) <> 'array' THEN
        po_data := util.result_error('membership:invalid', 'roles must be an array of {service, group, level}');
        RETURN;
    END IF;

    FOR i IN 0 .. jsonb_array_length(v_roles) - 1 LOOP
        v_role := v_roles->i;
        SELECT id INTO v_def_id
        FROM rolebyte.role_definition
        WHERE service_key = trim(COALESCE(v_role->>'service', ''))
          AND role_group  = trim(COALESCE(v_role->>'group', ''))
          AND role_level  = trim(COALESCE(v_role->>'level', ''));
        IF v_def_id IS NULL THEN
            po_data := util.result_error('membership:unknown_role',
                format('no such role: %s %s:%s', v_role->>'service', v_role->>'group', v_role->>'level'));
            RETURN;
        END IF;
        v_defs := array_append(v_defs, v_def_id);
    END LOOP;

    v_type := rolebyte.ensure_default_user_type(v_actor, v_tenant, NULL);
    INSERT INTO rolebyte.user_account (id, tenant_id, subject_key, display_name, status,
                                       user_type_id, user_type_source)
    VALUES (util.generate_ulid(), v_tenant, v_subject, v_display, 'invited', v_type, 'workspaceDefault')
    RETURNING * INTO v_user;

    INSERT INTO rolebyte.event (id, actor, tenant_id, user_id, kind, payload)
    VALUES (util.generate_ulid(), v_actor, v_tenant, v_user.id, 'userInvited',
            jsonb_build_object('subjectKey', v_subject, 'displayName', v_display));
    INSERT INTO rolebyte.event (id, actor, tenant_id, user_id, kind, payload)
    VALUES (util.generate_ulid(), v_actor, v_tenant, v_user.id, 'userTypeAssigned',
            jsonb_build_object('userTypeId', v_type, 'from', '', 'source', 'workspaceDefault'));

    FOR i IN 1 .. COALESCE(array_length(v_defs, 1), 0) LOOP
        INSERT INTO rolebyte.assignment (id, user_id, role_definition_id)
        VALUES (util.generate_ulid(), v_user.id, v_defs[i]);

        INSERT INTO rolebyte.event (id, actor, tenant_id, user_id, kind, payload)
        SELECT util.generate_ulid(), v_actor, v_tenant, v_user.id, 'roleGranted',
               jsonb_build_object('service', rd.service_key, 'group', rd.role_group, 'level', rd.role_level)
        FROM rolebyte.role_definition rd
        WHERE rd.id = v_defs[i];
    END LOOP;

    po_data := util.result_success(jsonb_build_object(
        'id',          v_user.id,
        'tenantId',    v_user.tenant_id,
        'subjectKey',  v_user.subject_key,
        'displayName', v_user.display_name,
        'status',      v_user.status,
        'createdAt',   v_user.created_at
    ));
EXCEPTION
    WHEN sqlstate 'P0001' THEN
        RAISE;
    WHEN OTHERS THEN
        RAISE EXCEPTION '%', util.result_error('membership:error', sqlerrm) USING errcode = 'P0001';
END;
$$;

REVOKE ALL ON PROCEDURE rolebyte.user_invite(jsonb, jsonb) FROM PUBLIC;
GRANT EXECUTE ON PROCEDURE rolebyte.user_invite(jsonb, jsonb) TO rolebyte_public;

-- claim_attach — an authenticated subject presents (first login): every
-- `invited` row bearing that subject key flips to `active`, each emitting
-- `claimAttached`. A subject nobody invited claims nothing — the answer is a
-- success with an empty list, and refusal is the caller's decision.
CREATE OR REPLACE PROCEDURE rolebyte.claim_attach(IN pi_data jsonb, INOUT po_data jsonb)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = rolebyte, util, pg_temp
AS $$
DECLARE
    v_actor   text;
    v_subject text;
    v_claimed jsonb;
BEGIN
    v_actor := NULLIF(trim(pi_data->>'actor'), '');
    IF v_actor IS NULL THEN
        po_data := util.result_error('membership:invalid', 'actor is required');
        RETURN;
    END IF;

    v_subject := NULLIF(trim(pi_data->>'subjectKey'), '');
    IF v_subject IS NULL THEN
        po_data := util.result_error('membership:invalid', 'subjectKey is required');
        RETURN;
    END IF;

    -- Matching is plain equality on the stored key: a person's key is their
    -- platform subject, which has exactly one spelling. A key of a kind this
    -- register does not define simply matches nothing — a lookup must not refuse
    -- a caller, it must fail to find them.

    WITH flipped AS (
        UPDATE rolebyte.user_account u
        SET status = 'active'
        FROM rolebyte.tenant t
        WHERE u.tenant_id = t.id
          AND t.status = 'active'
          AND u.subject_key = v_subject
          AND u.status = 'invited'
        RETURNING u.id, u.tenant_id
    ),
    logged AS (
        INSERT INTO rolebyte.event (id, actor, tenant_id, user_id, kind, payload)
        SELECT util.generate_ulid(), v_actor, f.tenant_id, f.id, 'claimAttached',
               jsonb_build_object('subjectKey', v_subject)
        FROM flipped f
        RETURNING user_id, tenant_id
    )
    SELECT COALESCE(jsonb_agg(jsonb_build_object('userId', user_id, 'tenantId', tenant_id)), '[]'::jsonb)
    INTO v_claimed
    FROM logged;

    po_data := util.result_success(jsonb_build_object('claimed', v_claimed));
EXCEPTION
    WHEN sqlstate 'P0001' THEN
        RAISE;
    WHEN OTHERS THEN
        RAISE EXCEPTION '%', util.result_error('membership:error', sqlerrm) USING errcode = 'P0001';
END;
$$;

REVOKE ALL ON PROCEDURE rolebyte.claim_attach(jsonb, jsonb) FROM PUBLIC;
GRANT EXECUTE ON PROCEDURE rolebyte.claim_attach(jsonb, jsonb) TO rolebyte_public;

-- directory_attach — an administration act on the tenant: name the directory the
-- tenant trusts as its own (the issuer of the identity provider its people sign
-- in through), replace it, or detach it (an empty or missing issuer). Emits
-- `directoryAttached` (with the previous issuer when there was one) or
-- `directoryDetached`; an attach of the value already held changes nothing and
-- emits nothing. One directory belongs to at most one tenant: attaching an
-- issuer another tenant holds is `membership:conflict`. The issuer is stored
-- exactly as given — identity providers compare issuers byte for byte.
CREATE OR REPLACE PROCEDURE rolebyte.directory_attach(IN pi_data jsonb, INOUT po_data jsonb)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = rolebyte, util, pg_temp
AS $$
DECLARE
    v_actor   text;
    v_tenant  text;
    v_issuer  text;
    v_current text;
    v_changed boolean := false;
BEGIN
    v_actor := NULLIF(trim(pi_data->>'actor'), '');
    IF v_actor IS NULL THEN
        po_data := util.result_error('membership:invalid', 'actor is required');
        RETURN;
    END IF;

    v_tenant := NULLIF(trim(pi_data->>'tenantId'), '');
    IF v_tenant IS NULL THEN
        po_data := util.result_error('membership:invalid', 'tenantId is required');
        RETURN;
    END IF;

    SELECT directory_issuer INTO v_current FROM rolebyte.tenant WHERE id = v_tenant;
    IF NOT FOUND THEN
        po_data := util.result_error('tenant:not_found', 'tenant does not exist');
        RETURN;
    END IF;

    v_issuer := NULLIF(trim(pi_data->>'issuer'), '');

    IF v_issuer IS NULL THEN
        -- Detach. Nothing to do when nothing is attached.
        IF v_current IS NOT NULL THEN
            UPDATE rolebyte.tenant SET directory_issuer = NULL WHERE id = v_tenant;
            INSERT INTO rolebyte.event (id, actor, tenant_id, kind, payload)
            VALUES (util.generate_ulid(), v_actor, v_tenant, 'directoryDetached',
                    jsonb_build_object('issuer', v_current));
            v_changed := true;
        END IF;
    ELSE
        -- The shape the constraint requires, checked first so a bad value is a
        -- structured refusal rather than a constraint violation. The message does
        -- not repeat the value: an error text is the least controlled place a
        -- value ends up.
        IF NOT rolebyte.is_directory_issuer(v_issuer) THEN
            po_data := util.result_error('membership:invalid',
                'issuer must be an absolute http(s) URL with no whitespace, query or fragment');
            RETURN;
        END IF;

        IF v_current IS DISTINCT FROM v_issuer THEN
            IF EXISTS (SELECT 1 FROM rolebyte.tenant
                       WHERE directory_issuer = v_issuer AND id <> v_tenant) THEN
                po_data := util.result_error('membership:conflict',
                    'this directory is attached to another tenant');
                RETURN;
            END IF;

            UPDATE rolebyte.tenant SET directory_issuer = v_issuer WHERE id = v_tenant;
            INSERT INTO rolebyte.event (id, actor, tenant_id, kind, payload)
            VALUES (util.generate_ulid(), v_actor, v_tenant, 'directoryAttached',
                    jsonb_strip_nulls(jsonb_build_object('issuer', v_issuer, 'from', v_current)));
            v_changed := true;
        END IF;
    END IF;

    po_data := util.result_success(jsonb_build_object(
        'tenantId', v_tenant,
        'issuer',   v_issuer,
        'changed',  v_changed
    ));
EXCEPTION
    WHEN sqlstate 'P0001' THEN
        RAISE;
    WHEN unique_violation THEN
        -- Two administrators attaching the same issuer to two tenants at the same
        -- moment: the unique index decides, and the loser gets the same answer the
        -- pre-check gives.
        RAISE EXCEPTION '%', util.result_error('membership:conflict', 'this directory is attached to another tenant') USING errcode = 'P0001';
    WHEN OTHERS THEN
        RAISE EXCEPTION '%', util.result_error('membership:error', sqlerrm) USING errcode = 'P0001';
END;
$$;

REVOKE ALL ON PROCEDURE rolebyte.directory_attach(jsonb, jsonb) FROM PUBLIC;
GRANT EXECUTE ON PROCEDURE rolebyte.directory_attach(jsonb, jsonb) TO rolebyte_public;

-- directory_admit — the identity provider's door beside `claim_attach`: a person
-- has just authenticated through an issuer, and the tenant whose attached
-- directory that issuer is admits them as an ACTIVE member with NO grants — a
-- member, not a role-holder, until an administrator gives them one — holding
-- the tenant's user type for people arriving through its corporate login, when
-- it has one. That default is given once, to a person the directory brings in
-- for the first time, and recorded as its own source; an invitation the person
-- claims keeps what the inviter chose. Emits `directoryAdmitted`, and
-- `userTypeAssigned` from `corporateLoginDefault` when the default was given.
-- Outcomes, all a success answer (refusing a login is the caller's decision,
-- and the caller's words):
--   * `admitted`    — a membership row was created, or an invited row for the same
--                     person in that tenant was activated (the invitation's roles
--                     are kept; `claimedInvitation` says so in the event);
--   * `member`      — already an active member: nothing changes, nothing is logged;
--   * `revoked`     — an administrator revoked this person here; the directory
--                     does not overrule that, nothing changes;
--   * `noDirectory` — no active tenant attached this issuer: nobody is admitted.
-- Only a person is admitted (`sub:<person id>`): a service account does not sign
-- in through a directory, and a key of any other kind is refused. Nothing but the
-- issuer decides the tenant — never a name, never an e-mail address.
CREATE OR REPLACE PROCEDURE rolebyte.directory_admit(IN pi_data jsonb, INOUT po_data jsonb)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = rolebyte, util, pg_temp
AS $$
DECLARE
    v_actor   text;
    v_subject text;
    v_issuer  text;
    v_display text;
    v_tenant  text;
    v_user    rolebyte.user_account%ROWTYPE;
    v_outcome text;
    v_admitted jsonb := '[]'::jsonb;
BEGIN
    v_actor := NULLIF(trim(pi_data->>'actor'), '');
    IF v_actor IS NULL THEN
        po_data := util.result_error('membership:invalid', 'actor is required');
        RETURN;
    END IF;

    -- A write door: the key must be of a kind the register defines, and a person's.
    v_subject := NULLIF(trim(pi_data->>'subjectKey'), '');
    IF v_subject IS NULL OR NOT rolebyte.is_typed_subject_key(v_subject) THEN
        po_data := util.result_error('membership:invalid',
            'subjectKey must be a typed key: sub:<person id> for a person, svc:<client id> for a service account');
        RETURN;
    END IF;
    IF v_subject NOT LIKE 'sub:%' THEN
        po_data := util.result_error('membership:invalid',
            'a directory admits persons only: subjectKey must be sub:<person id>');
        RETURN;
    END IF;

    v_issuer := NULLIF(trim(pi_data->>'issuer'), '');
    IF v_issuer IS NULL THEN
        po_data := util.result_error('membership:invalid', 'issuer is required');
        RETURN;
    END IF;

    v_display := NULLIF(trim(pi_data->>'displayName'), '');
    IF v_display IS NULL THEN
        po_data := util.result_error('membership:invalid', 'displayName is required');
        RETURN;
    END IF;

    -- Two first logins of one person at the same moment must not race each other
    -- into two rows and a unique-key failure; the lock serialises the admission of
    -- ONE subject, and different people are not queued behind each other.
    PERFORM pg_advisory_xact_lock(hashtextextended('rolebyte.directory_admit:' || v_subject, 0));

    SELECT t.id INTO v_tenant
      FROM rolebyte.tenant t
     WHERE t.directory_issuer = v_issuer
       AND t.status = 'active';

    IF v_tenant IS NULL THEN
        po_data := util.result_success(jsonb_build_object(
            'outcome', 'noDirectory', 'tenantId', NULL, 'admitted', v_admitted));
        RETURN;
    END IF;

    SELECT * INTO v_user
      FROM rolebyte.user_account
     WHERE tenant_id = v_tenant AND subject_key = v_subject;

    IF FOUND THEN
        CASE v_user.status
            WHEN 'active' THEN
                v_outcome := 'member';
            WHEN 'revoked' THEN
                v_outcome := 'revoked';
            ELSE
                -- Invited by an administrator AND arriving through the directory: the
                -- admission activates the invitation, roles included.
                UPDATE rolebyte.user_account SET status = 'active' WHERE id = v_user.id;
                INSERT INTO rolebyte.event (id, actor, tenant_id, user_id, kind, payload)
                VALUES (util.generate_ulid(), v_actor, v_tenant, v_user.id, 'directoryAdmitted',
                        jsonb_build_object('subjectKey', v_subject, 'issuer', v_issuer,
                                           'displayName', v_user.display_name, 'claimedInvitation', true));
                v_outcome  := 'admitted';
                v_admitted := jsonb_build_array(jsonb_build_object('userId', v_user.id, 'tenantId', v_tenant));
        END CASE;
    ELSE
        PERFORM rolebyte.ensure_default_user_type(v_actor, v_tenant, NULL);
        INSERT INTO rolebyte.user_account (id, tenant_id, subject_key, display_name, status,
                                           user_type_id, user_type_source)
        SELECT util.generate_ulid(), v_tenant, v_subject, v_display, 'active',
               COALESCE(t.corporate_login_user_type_id, t.default_user_type_id),
               CASE WHEN t.corporate_login_user_type_id IS NOT NULL THEN 'corporateLoginDefault'
                    ELSE 'workspaceDefault' END
          FROM rolebyte.tenant t WHERE t.id = v_tenant
        RETURNING * INTO v_user;

        INSERT INTO rolebyte.event (id, actor, tenant_id, user_id, kind, payload)
        VALUES (util.generate_ulid(), v_actor, v_tenant, v_user.id, 'directoryAdmitted',
                jsonb_build_object('subjectKey', v_subject, 'issuer', v_issuer, 'displayName', v_display));
        INSERT INTO rolebyte.event (id, actor, tenant_id, user_id, kind, payload)
        VALUES (util.generate_ulid(), v_actor, v_tenant, v_user.id, 'userTypeAssigned',
                jsonb_build_object('userTypeId', v_user.user_type_id, 'from', '', 'source', v_user.user_type_source));

        v_outcome  := 'admitted';
        v_admitted := jsonb_build_array(jsonb_build_object('userId', v_user.id, 'tenantId', v_tenant));
    END IF;

    po_data := util.result_success(jsonb_build_object(
        'outcome',  v_outcome,
        'tenantId', v_tenant,
        'admitted', v_admitted
    ));
EXCEPTION
    WHEN sqlstate 'P0001' THEN
        RAISE;
    WHEN OTHERS THEN
        RAISE EXCEPTION '%', util.result_error('membership:error', sqlerrm) USING errcode = 'P0001';
END;
$$;

REVOKE ALL ON PROCEDURE rolebyte.directory_admit(jsonb, jsonb) FROM PUBLIC;
GRANT EXECUTE ON PROCEDURE rolebyte.directory_admit(jsonb, jsonb) TO rolebyte_public;

-- ---------------------------------------------------------------------------
-- The administrator. A tenant's administrator is a member holding the
-- `membership:admin` rung, whose account is not revoked: the rung is what every
-- administration act checks, and the first administrator receives it when a
-- tenant is opened. An administrator holds every permission of every product
-- the tenant has (resolve), and is the only holder of the permissions that
-- change the tenant's own setup, because no role may tick them
-- (tenant_role_permissions_set).
--
-- Every tenant keeps at least one administrator. Each door that can remove
-- one asks administrator_removal_refusal first, under a lock per tenant, so
-- two administrators removing each other at the same moment cannot both
-- succeed. An invited administrator counts: the first one is invited until
-- they first sign in.
-- ---------------------------------------------------------------------------

-- is_administrator_rung — whether a service role's coordinates are the
-- administrator rung. The ONE home of that pair.
CREATE OR REPLACE FUNCTION rolebyte.is_administrator_rung(p_group text, p_level text)
RETURNS boolean
LANGUAGE sql
IMMUTABLE
SET search_path = pg_temp
AS $$
    SELECT p_group IS NOT DISTINCT FROM 'membership' AND p_level IS NOT DISTINCT FROM 'admin';
$$;

REVOKE ALL ON FUNCTION rolebyte.is_administrator_rung(text, text) FROM PUBLIC;

-- is_administrator — whether a member is an administrator of their tenant now:
-- the rung granted, and the account not revoked.
CREATE OR REPLACE FUNCTION rolebyte.is_administrator(p_user_id text)
RETURNS boolean
LANGUAGE sql
STABLE
SET search_path = rolebyte, pg_temp
AS $$
    SELECT EXISTS (
        SELECT 1
          FROM rolebyte.assignment a
          JOIN rolebyte.role_definition rd ON rd.id = a.role_definition_id
          JOIN rolebyte.user_account u ON u.id = a.user_id
         WHERE a.user_id = p_user_id
           AND a.state = 'granted'
           AND rolebyte.is_administrator_rung(rd.role_group, rd.role_level)
           AND u.status <> 'revoked'
    );
$$;

REVOKE ALL ON FUNCTION rolebyte.is_administrator(text) FROM PUBLIC;

-- administrator_lock — serialise every change to who administers a tenant.
-- Transaction-scoped, so it is released when the calling procedure's
-- transaction ends. A key pair of its own, apart from the bootstrap lock.
CREATE OR REPLACE FUNCTION rolebyte.administrator_lock(p_tenant text)
RETURNS void
LANGUAGE sql
VOLATILE
SET search_path = pg_temp
AS $$
    SELECT pg_advisory_xact_lock(hashtext('rolebyte.administrators'), hashtext(p_tenant));
$$;

REVOKE ALL ON FUNCTION rolebyte.administrator_lock(text) FROM PUBLIC;

-- administrator_removal_refusal — the lockout invariant, asked by every door
-- that can remove an administrator, before it writes: removing this member
-- would leave the tenant with no administrator. Takes the tenant's lock first
-- and only then counts, so of two concurrent removals the second counts after
-- the first has committed. NULL when the removal may go ahead, including when
-- the member is not in this tenant (the caller answers that as it always has).
CREATE OR REPLACE FUNCTION rolebyte.administrator_removal_refusal(p_tenant text, p_user_id text)
RETURNS jsonb
LANGUAGE plpgsql
VOLATILE
SET search_path = rolebyte, util, pg_temp
AS $$
DECLARE
    v_name text;
BEGIN
    PERFORM rolebyte.administrator_lock(p_tenant);

    SELECT u.display_name INTO v_name
      FROM rolebyte.user_account u
     WHERE u.id = p_user_id
       AND u.tenant_id = p_tenant
       AND rolebyte.is_administrator(u.id);
    IF NOT FOUND THEN
        RETURN NULL;
    END IF;

    IF EXISTS (SELECT 1 FROM rolebyte.user_account o
                WHERE o.tenant_id = p_tenant
                  AND o.id <> p_user_id
                  AND rolebyte.is_administrator(o.id)) THEN
        RETURN NULL;
    END IF;

    RETURN util.result_error('membership:conflict',
        format('%s is this tenant''s last administrator; make someone else an administrator first', v_name));
END;
$$;

REVOKE ALL ON FUNCTION rolebyte.administrator_removal_refusal(text, text) FROM PUBLIC;

-- administrator_rung — the rung's role definition, created with this
-- service's registration when the deployment never had them (a tenant opened
-- by the operator before anyone used the bootstrap door). Each creation is the
-- same event the defining procedures write. Returns the definition's id.
CREATE OR REPLACE FUNCTION rolebyte.administrator_rung(p_actor text)
RETURNS text
LANGUAGE plpgsql
VOLATILE
SET search_path = rolebyte, util, pg_temp
AS $$
DECLARE
    v_id text;
BEGIN
    INSERT INTO rolebyte.service (key, display_name)
    VALUES ('rolebyte', 'Membership administration')
    ON CONFLICT (key) DO NOTHING;
    IF FOUND THEN
        INSERT INTO rolebyte.event (id, actor, kind, payload)
        VALUES (util.generate_ulid(), p_actor, 'serviceRegistered',
                jsonb_build_object('service', 'rolebyte', 'displayName', 'Membership administration'));
    END IF;

    INSERT INTO rolebyte.role_definition (id, service_key, role_group, role_level, description)
    VALUES (util.generate_ulid(), 'rolebyte', 'membership', 'admin',
            'administer this tenant''s users and their roles')
    ON CONFLICT (service_key, role_group, role_level) DO NOTHING;
    IF FOUND THEN
        INSERT INTO rolebyte.event (id, actor, kind, payload)
        VALUES (util.generate_ulid(), p_actor, 'roleDefined',
                jsonb_build_object('service', 'rolebyte', 'group', 'membership', 'level', 'admin'));
    END IF;

    SELECT id INTO v_id
      FROM rolebyte.role_definition
     WHERE service_key = 'rolebyte' AND role_group = 'membership' AND role_level = 'admin';
    RETURN v_id;
END;
$$;

REVOKE ALL ON FUNCTION rolebyte.administrator_rung(text) FROM PUBLIC;

-- own_rung_register — the register's own service and its administrator rung put
-- on the deployment's list, for the one-time bootstrap door, which runs as the
-- register's own role. It names nothing a caller chooses: the service and the
-- rung are fixed, so the register's role can add nothing else to the list
-- through it. Idempotent.
CREATE OR REPLACE PROCEDURE rolebyte.own_rung_register(IN pi_data jsonb, INOUT po_data jsonb)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = rolebyte, util, pg_temp
AS $$
DECLARE
    v_actor text := NULLIF(trim(pi_data->>'actor'), '');
BEGIN
    IF v_actor IS NULL THEN
        po_data := util.result_error('membership:invalid', 'actor is required');
        RETURN;
    END IF;

    PERFORM rolebyte.administrator_rung(v_actor);
    po_data := util.result_success(jsonb_build_object(
        'service', 'rolebyte', 'group', 'membership', 'level', 'admin'));
EXCEPTION
    WHEN sqlstate 'P0001' THEN
        RAISE;
    WHEN OTHERS THEN
        RAISE EXCEPTION '%', util.result_error('membership:error', sqlerrm) USING errcode = 'P0001';
END;
$$;

REVOKE ALL ON PROCEDURE rolebyte.own_rung_register(jsonb, jsonb) FROM PUBLIC;
GRANT EXECUTE ON PROCEDURE rolebyte.own_rung_register(jsonb, jsonb) TO rolebyte_public;

-- invited_member_add — add someone who is not yet a member of the tenant, invited,
-- under the tenant's default user type, holding no role. Writes the account and
-- its two history lines (`userInvited`, `userTypeAssigned`) and answers the new
-- account. The caller has already checked that no account exists and holds the
-- tenant's administrators' lock.
CREATE OR REPLACE FUNCTION rolebyte.invited_member_add(p_actor text, p_tenant text, p_subject text, p_display text)
RETURNS rolebyte.user_account
LANGUAGE plpgsql
VOLATILE
SET search_path = rolebyte, util, pg_temp
AS $$
DECLARE
    v_user rolebyte.user_account%ROWTYPE;
    v_type text;
BEGIN
    v_type := rolebyte.ensure_default_user_type(p_actor, p_tenant, NULL);
    INSERT INTO rolebyte.user_account (id, tenant_id, subject_key, display_name, status,
                                       user_type_id, user_type_source)
    VALUES (util.generate_ulid(), p_tenant, p_subject, p_display, 'invited', v_type, 'workspaceDefault')
    RETURNING * INTO v_user;

    INSERT INTO rolebyte.event (id, actor, tenant_id, user_id, kind, payload)
    VALUES (util.generate_ulid(), p_actor, p_tenant, v_user.id, 'userInvited',
            jsonb_build_object('subjectKey', p_subject, 'displayName', p_display));
    INSERT INTO rolebyte.event (id, actor, tenant_id, user_id, kind, payload)
    VALUES (util.generate_ulid(), p_actor, p_tenant, v_user.id, 'userTypeAssigned',
            jsonb_build_object('userTypeId', v_type, 'from', '', 'source', 'workspaceDefault'));
    RETURN v_user;
END;
$$;

REVOKE ALL ON FUNCTION rolebyte.invited_member_add(text, text, text, text) FROM PUBLIC;

-- administrator_make — the one step the operator's acts share: make the person
-- with this subject key an administrator of this tenant, whatever anyone else's
-- state. A member receives the rung; someone not yet a member is added,
-- invited, holding it, which needs a display name. A member whose access was
-- revoked is refused: nothing in this register gives access back, so naming
-- them is a mistake to report, not an act to perform.
--
-- Everything is checked before the first write, so a refusal changes nothing
-- and the caller returns it as it stands. On success it answers the member's
-- id and whether anything changed; the caller writes its own event beside the
-- ones written here.
CREATE OR REPLACE FUNCTION rolebyte.administrator_make(p_actor text, p_tenant text, p_subject text, p_display text)
RETURNS jsonb
LANGUAGE plpgsql
VOLATILE
SET search_path = rolebyte, util, pg_temp
AS $$
DECLARE
    v_user    rolebyte.user_account%ROWTYPE;
    v_rung    text;
    v_invited boolean := false;
    v_changed boolean := false;
BEGIN
    -- The message does not echo the key: this text reaches logs.
    IF p_subject IS NULL OR NOT rolebyte.is_typed_subject_key(p_subject) THEN
        RETURN util.result_error('membership:invalid',
            'subjectKey must be a typed key: sub:<person id> for a person, svc:<client id> for a service account');
    END IF;

    PERFORM rolebyte.administrator_lock(p_tenant);

    SELECT * INTO v_user
      FROM rolebyte.user_account
     WHERE tenant_id = p_tenant AND subject_key = p_subject
       FOR UPDATE;

    IF FOUND AND v_user.status = 'revoked' THEN
        RETURN util.result_error('membership:conflict',
            format('%s no longer has access to this tenant, so cannot be made its administrator', v_user.display_name));
    END IF;
    IF NOT FOUND AND p_display IS NULL THEN
        RETURN util.result_error('membership:invalid',
            'displayName is required to add someone who is not yet a member of the tenant');
    END IF;

    IF NOT FOUND THEN
        v_user := rolebyte.invited_member_add(p_actor, p_tenant, p_subject, p_display);
        v_invited := true;
    END IF;

    v_rung := rolebyte.administrator_rung(p_actor);

    INSERT INTO rolebyte.assignment (id, user_id, role_definition_id)
    VALUES (util.generate_ulid(), v_user.id, v_rung)
    ON CONFLICT (user_id, role_definition_id)
        DO UPDATE SET state = 'granted', granted_at = now(), revoked_at = NULL
        WHERE rolebyte.assignment.state = 'revoked';
    v_changed := FOUND;

    IF v_changed THEN
        INSERT INTO rolebyte.event (id, actor, tenant_id, user_id, kind, payload)
        VALUES (util.generate_ulid(), p_actor, p_tenant, v_user.id, 'roleGranted',
                jsonb_build_object('service', 'rolebyte', 'group', 'membership', 'level', 'admin'));
    END IF;

    RETURN util.result_success(jsonb_build_object(
        'userId',  v_user.id,
        'status',  v_user.status,
        'invited', v_invited,
        'changed', v_changed
    ));
END;
$$;

REVOKE ALL ON FUNCTION rolebyte.administrator_make(text, text, text, text) FROM PUBLIC;

-- role_grant — grant one defined role to a user in the caller's tenant.
-- Re-granting a revoked pair flips it back; the events keep both moments.
CREATE OR REPLACE PROCEDURE rolebyte.role_grant(IN pi_data jsonb, INOUT po_data jsonb)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = rolebyte, util, pg_temp
AS $$
DECLARE
    v_actor   text;
    v_tenant  text;
    v_user_id text;
    v_service text;
    v_group   text;
    v_level   text;
    v_def_id  text;
    v_changed boolean := false;
BEGIN
    v_actor   := NULLIF(trim(pi_data->>'actor'), '');
    v_tenant  := NULLIF(trim(pi_data->>'tenantId'), '');
    v_user_id := NULLIF(trim(pi_data->>'userId'), '');
    v_service := NULLIF(trim(pi_data->>'service'), '');
    v_group   := NULLIF(trim(pi_data->>'group'), '');
    v_level   := NULLIF(trim(pi_data->>'level'), '');
    IF v_actor IS NULL OR v_tenant IS NULL OR v_user_id IS NULL
       OR v_service IS NULL OR v_group IS NULL OR v_level IS NULL THEN
        po_data := util.result_error('membership:invalid', 'actor, tenantId, userId, service, group and level are required');
        RETURN;
    END IF;

    -- Tenant-scoped user lookup: a foreign tenant's user answers not_found.
    IF NOT EXISTS (SELECT 1 FROM rolebyte.user_account
                   WHERE id = v_user_id AND tenant_id = v_tenant AND status <> 'revoked') THEN
        po_data := util.result_error('membership:not_found', 'user does not exist');
        RETURN;
    END IF;

    SELECT id INTO v_def_id
    FROM rolebyte.role_definition
    WHERE service_key = v_service AND role_group = v_group AND role_level = v_level;
    IF v_def_id IS NULL THEN
        po_data := util.result_error('membership:unknown_role',
            format('no such role: %s %s:%s', v_service, v_group, v_level));
        RETURN;
    END IF;

    INSERT INTO rolebyte.assignment (id, user_id, role_definition_id)
    VALUES (util.generate_ulid(), v_user_id, v_def_id)
    ON CONFLICT (user_id, role_definition_id)
        DO UPDATE SET state = 'granted', granted_at = now(), revoked_at = NULL
        WHERE rolebyte.assignment.state = 'revoked';
    v_changed := FOUND;

    IF v_changed THEN
        INSERT INTO rolebyte.event (id, actor, tenant_id, user_id, kind, payload)
        VALUES (util.generate_ulid(), v_actor, v_tenant, v_user_id, 'roleGranted',
                jsonb_build_object('service', v_service, 'group', v_group, 'level', v_level));
    END IF;

    po_data := util.result_success(jsonb_build_object('changed', v_changed));
EXCEPTION
    WHEN sqlstate 'P0001' THEN
        RAISE;
    WHEN OTHERS THEN
        RAISE EXCEPTION '%', util.result_error('membership:error', sqlerrm) USING errcode = 'P0001';
END;
$$;

REVOKE ALL ON PROCEDURE rolebyte.role_grant(jsonb, jsonb) FROM PUBLIC;
GRANT EXECUTE ON PROCEDURE rolebyte.role_grant(jsonb, jsonb) TO rolebyte_public;

-- role_revoke — revoke one granted role from a user in the caller's tenant.
-- Revoking the administrator rung is refused when it would leave the tenant
-- without an administrator (administrator_removal_refusal).
CREATE OR REPLACE PROCEDURE rolebyte.role_revoke(IN pi_data jsonb, INOUT po_data jsonb)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = rolebyte, util, pg_temp
AS $$
DECLARE
    v_actor   text;
    v_tenant  text;
    v_user_id text;
    v_service text;
    v_group   text;
    v_level   text;
    v_def_id  text;
    v_refusal jsonb;
    v_changed boolean := false;
BEGIN
    v_actor   := NULLIF(trim(pi_data->>'actor'), '');
    v_tenant  := NULLIF(trim(pi_data->>'tenantId'), '');
    v_user_id := NULLIF(trim(pi_data->>'userId'), '');
    v_service := NULLIF(trim(pi_data->>'service'), '');
    v_group   := NULLIF(trim(pi_data->>'group'), '');
    v_level   := NULLIF(trim(pi_data->>'level'), '');
    IF v_actor IS NULL OR v_tenant IS NULL OR v_user_id IS NULL
       OR v_service IS NULL OR v_group IS NULL OR v_level IS NULL THEN
        po_data := util.result_error('membership:invalid', 'actor, tenantId, userId, service, group and level are required');
        RETURN;
    END IF;

    IF NOT EXISTS (SELECT 1 FROM rolebyte.user_account
                   WHERE id = v_user_id AND tenant_id = v_tenant) THEN
        po_data := util.result_error('membership:not_found', 'user does not exist');
        RETURN;
    END IF;

    SELECT id INTO v_def_id
    FROM rolebyte.role_definition
    WHERE service_key = v_service AND role_group = v_group AND role_level = v_level;
    IF v_def_id IS NULL THEN
        po_data := util.result_error('membership:unknown_role',
            format('no such role: %s %s:%s', v_service, v_group, v_level));
        RETURN;
    END IF;

    IF rolebyte.is_administrator_rung(v_group, v_level) THEN
        v_refusal := rolebyte.administrator_removal_refusal(v_tenant, v_user_id);
        IF v_refusal IS NOT NULL THEN
            po_data := v_refusal;
            RETURN;
        END IF;
    END IF;

    UPDATE rolebyte.assignment
    SET state = 'revoked', revoked_at = now()
    WHERE user_id = v_user_id AND role_definition_id = v_def_id AND state = 'granted';
    v_changed := FOUND;

    IF v_changed THEN
        INSERT INTO rolebyte.event (id, actor, tenant_id, user_id, kind, payload)
        VALUES (util.generate_ulid(), v_actor, v_tenant, v_user_id, 'roleRevoked',
                jsonb_build_object('service', v_service, 'group', v_group, 'level', v_level));
    END IF;

    po_data := util.result_success(jsonb_build_object('changed', v_changed));
EXCEPTION
    WHEN sqlstate 'P0001' THEN
        RAISE;
    WHEN OTHERS THEN
        RAISE EXCEPTION '%', util.result_error('membership:error', sqlerrm) USING errcode = 'P0001';
END;
$$;

REVOKE ALL ON PROCEDURE rolebyte.role_revoke(jsonb, jsonb) FROM PUBLIC;
GRANT EXECUTE ON PROCEDURE rolebyte.role_revoke(jsonb, jsonb) TO rolebyte_public;

-- user_revoke — the offboarding switch: the user stops resolving everywhere
-- at the next session refresh. Assignment rows are left as they stand — the
-- user-level status gates resolution, and the event stream keeps the truth.
-- A person who lost access also leaves their place in the chart of authority,
-- in the same act and with its own line (`chartPersonRemoved`, marked
-- `revoked`), so the chart's editor never lists or counts someone who lifts
-- nothing. The administrators' note about them is cleared in the same act, with
-- its own line (`noteChanged`, marked `revoked`) when there was one. An account on
-- the deployment's list of administrators leaves it in the same act, with its own
-- line (`deploymentAdminRemoved`, marked `revoked`). Revoking the
-- tenant's last administrator is refused (administrator_removal_refusal).
CREATE OR REPLACE PROCEDURE rolebyte.user_revoke(IN pi_data jsonb, INOUT po_data jsonb)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = rolebyte, util, pg_temp
AS $$
DECLARE
    v_actor   text;
    v_tenant  text;
    v_user_id text;
    v_refusal jsonb;
    v_left    text;
    v_note    text;
BEGIN
    v_actor   := NULLIF(trim(pi_data->>'actor'), '');
    v_tenant  := NULLIF(trim(pi_data->>'tenantId'), '');
    v_user_id := NULLIF(trim(pi_data->>'userId'), '');
    IF v_actor IS NULL OR v_tenant IS NULL OR v_user_id IS NULL THEN
        po_data := util.result_error('membership:invalid', 'actor, tenantId and userId are required');
        RETURN;
    END IF;

    -- The deployment's lock first, before any account row is locked. The acts that
    -- write the deployment's list take that lock and then the account's row
    -- (`deployment_admin_add` shares the row, `deployment_admin_remove` writes a
    -- line that references it), so every path locks in the order lock, then row,
    -- and two of them can never wait for each other. It is taken for every revoke,
    -- not only for a listed account: whether the account is listed cannot be known
    -- without a read that a concurrent add would make stale. A revoke is an
    -- offboarding act, rare, and the lock is held only to the end of the act.
    PERFORM pg_advisory_xact_lock(hashtextextended('rolebyte.deployment', 0));

    v_refusal := rolebyte.administrator_removal_refusal(v_tenant, v_user_id);
    IF v_refusal IS NOT NULL THEN
        po_data := v_refusal;
        RETURN;
    END IF;

    UPDATE rolebyte.user_account u
       SET status = 'revoked', note = ''
      FROM (SELECT id, note FROM rolebyte.user_account
             WHERE id = v_user_id AND tenant_id = v_tenant AND status <> 'revoked'
               FOR UPDATE) old
     WHERE u.id = old.id
    RETURNING old.note INTO v_note;

    IF NOT FOUND THEN
        po_data := util.result_error('membership:not_found', 'user does not exist');
        RETURN;
    END IF;

    INSERT INTO rolebyte.event (id, actor, tenant_id, user_id, kind, payload)
    VALUES (util.generate_ulid(), v_actor, v_tenant, v_user_id, 'userRevoked', '{}'::jsonb);

    -- The administrators' note about them goes with their access: it was kept to
    -- tell members apart, and they are not one any more.
    IF v_note <> '' THEN
        INSERT INTO rolebyte.event (id, actor, tenant_id, user_id, kind, payload)
        VALUES (util.generate_ulid(), v_actor, v_tenant, v_user_id, 'noteChanged',
                jsonb_build_object('cleared', true, 'revoked', true));
    END IF;

    DELETE FROM rolebyte.chart_holder
     WHERE tenant_id = v_tenant AND user_id = v_user_id
    RETURNING position_id INTO v_left;
    IF v_left IS NOT NULL THEN
        INSERT INTO rolebyte.event (id, actor, tenant_id, user_id, kind, payload)
        VALUES (util.generate_ulid(), v_actor, v_tenant, v_user_id, 'chartPersonRemoved',
                jsonb_build_object('positionId', v_left, 'revoked', true));
    END IF;

    -- A person who lost access also stops administering the deployment, in the
    -- same act: the entry is deleted and its own line written, so nothing remains
    -- to come back with the account.
    DELETE FROM rolebyte.deployment_admin WHERE user_id = v_user_id;
    IF FOUND THEN
        INSERT INTO rolebyte.event (id, actor, tenant_id, user_id, kind, payload)
        VALUES (util.generate_ulid(), v_actor, v_tenant, v_user_id, 'deploymentAdminRemoved',
                jsonb_build_object('revoked', true));
    END IF;

    po_data := util.result_success(jsonb_build_object('revoked', true));
EXCEPTION
    WHEN sqlstate 'P0001' THEN
        RAISE;
    WHEN OTHERS THEN
        RAISE EXCEPTION '%', util.result_error('membership:error', sqlerrm) USING errcode = 'P0001';
END;
$$;

REVOKE ALL ON PROCEDURE rolebyte.user_revoke(jsonb, jsonb) FROM PUBLIC;
GRANT EXECUTE ON PROCEDURE rolebyte.user_revoke(jsonb, jsonb) TO rolebyte_public;

-- resolve — the identity provider's hot path at token issue: an authenticated
-- subject key answers the memberships it may act under, each with one flat scope
-- set from what is currently granted there: a service's role as `group:level`,
-- and each permission a tenant's own role ticks as `service/feature:act`. A
-- stranger resolves to an empty list.
--
-- Its one write, only when the caller says it is issuing the person's access
-- (`issuing: true`, the identity provider's door): the day each answered
-- membership was given access, at most once a day. The register's own checks of
-- who may administer what read the same answer without it, so using the register
-- is never taken for signing in. A later answer the same day finds the date
-- already there and writes nothing, and a row another session holds locked is
-- skipped rather than waited for, so the hot path never queues behind a write.
-- The day is UTC's. A person in two tenants is dated in both, because the
-- register answers every tenant at once and which one the sign-in picks is
-- decided after it.
--
-- Both kinds feed ONE distinct aggregate, so a person who holds no tenant role
-- resolves exactly as before tenant roles existed, and a box ticked by two roles
-- appears once. The two kinds cannot collide: a permission always carries a `/`
-- and a role's group never does.
--
-- A tick reaches the answer only while the tenant has its feature: an
-- entitlement to the whole service, to the feature itself, or to a feature it is
-- nested under. Without one the tick is simply absent — the role keeps it, so it
-- returns unchanged when the entitlement does. A service's role is not a catalog
-- permission and is never filtered.
--
-- An administrator of the tenant holds every declared permission the tenant has,
-- whatever their roles tick, so a permission declared later reaches them with no
-- write and a product the tenant does not have gives them nothing. Nobody else
-- holds a permission that changes the tenant's own setup: a role cannot be given
-- one, and a tick stored before that rule is skipped here. Where no service
-- declares a permission, an administrator resolves exactly as before.
--
-- A retired permission still reaches everyone whose role ticks it, and no longer
-- reaches an administrator through the checkbox: it is kept for the roles that
-- hold it, not handed out anew.
--
-- A membership carries a further member, `highScopes`, only for a person (a `sub:`
-- key) whose account is in the deployment's own company and is on the list of the
-- deployment's administrators: `["deployment:admin"]`, a scope that counts only on
-- a strong sign-in, which the caller decides. In every other case the member is
-- absent, not empty, so every other answer is unchanged. The group `deployment` is
-- the register's own: a granted level in it is never answered in `scopes`.
CREATE OR REPLACE PROCEDURE rolebyte.resolve(IN pi_data jsonb, INOUT po_data jsonb)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = rolebyte, util, pg_temp
AS $$
DECLARE
    v_subject     text;
    v_memberships jsonb;
    v_today       date := (now() AT TIME ZONE 'UTC')::date;
BEGIN
    v_subject := NULLIF(trim(pi_data->>'subjectKey'), '');
    IF v_subject IS NULL THEN
        po_data := util.result_error('membership:invalid', 'subjectKey is required');
        RETURN;
    END IF;

    -- The day each membership answered below was last given access, when this
    -- answer issues it. Only a date older than today is written, so the second
    -- answer of a day changes nothing.
    IF pi_data->'issuing' = 'true'::jsonb THEN
        UPDATE rolebyte.user_account u
           SET last_signed_in_on = v_today
         WHERE u.id IN (
               SELECT a.id
                 FROM rolebyte.user_account a
                 JOIN rolebyte.tenant t ON t.id = a.tenant_id
                WHERE a.subject_key = v_subject
                  AND a.status = 'active'
                  AND t.status = 'active'
                  AND (a.last_signed_in_on IS NULL OR a.last_signed_in_on < v_today)
                  FOR UPDATE OF a SKIP LOCKED);
    END IF;

    -- Matching is plain equality on the stored key: a person's key is their
    -- platform subject, which has exactly one spelling. A key of a kind this
    -- register does not define simply matches nothing — a lookup must not refuse
    -- a caller, it must fail to find them.

    SELECT COALESCE(jsonb_agg(m ORDER BY m->>'tenantId'), '[]'::jsonb)
    INTO v_memberships
    FROM (
        SELECT jsonb_build_object(
            'tenantId',    u.tenant_id,
            'userId',      u.id,
            'displayName', u.display_name,
            'scopes',      COALESCE((
                SELECT jsonb_agg(DISTINCT s.scope)
                FROM (
                    SELECT rd.role_group || ':' || rd.role_level AS scope
                    FROM rolebyte.assignment a
                    JOIN rolebyte.role_definition rd ON rd.id = a.role_definition_id
                    WHERE a.user_id = u.id AND a.state = 'granted'
                      -- The group `deployment` is the register's own: a level in it
                      -- never reaches `scopes`, whatever is stored. The deployment's
                      -- own right is answered only as `highScopes`, below.
                      AND rd.role_group <> 'deployment'
                    UNION ALL
                    -- An administrator holds every declared permission, a
                    -- per-field family bare: every field of its kind. A role's
                    -- ticks resolve only when ordinary, so one field's permission
                    -- never reaches a token; the services that place roles read it
                    -- from the roles they copy.
                    SELECT sp.service_key || '/' || sp.feature_key || ':' || sp.act
                    FROM rolebyte.service_permission sp
                    WHERE ((adm.yes AND sp.retired_at IS NULL AND sp.plane IS DISTINCT FROM 'chart')
                           OR (sp.class = 'ordinary' AND EXISTS (
                               SELECT 1
                                 FROM rolebyte.tenant_role_assignment ta
                                 JOIN rolebyte.tenant_role_permission tp ON tp.tenant_role_id = ta.tenant_role_id
                                WHERE ta.user_id = u.id AND ta.tenant_id = u.tenant_id AND ta.state = 'granted'
                                  AND tp.permission_id = sp.id AND tp.param IS NULL))
                           -- A person's user type: tenant-wide permissions only. It
                           -- is the type of the position they sit in while the tenant
                           -- holds the chart, and their own otherwise.
                           OR (sp.class = 'ordinary' AND sp.plane = 'tenant' AND EXISTS (
                               SELECT 1 FROM rolebyte.user_type_permission up
                                WHERE up.user_type_id = rolebyte.effective_user_type(u.tenant_id, u.id)
                                  AND up.permission_id = sp.id))
                           -- A box the position they sit in carries; the entitlement
                           -- clause below keeps it off a token once the chart lapses.
                           OR (sp.class = 'ordinary' AND sp.plane = 'chart' AND EXISTS (
                               SELECT 1
                                 FROM rolebyte.chart_holder h
                                 JOIN rolebyte.chart_position_permission cp ON cp.position_id = h.position_id
                                WHERE h.tenant_id = u.tenant_id AND h.user_id = u.id
                                  AND cp.permission_id = sp.id)))
                      AND EXISTS (
                          SELECT 1 FROM rolebyte.tenant_entitlement e
                           WHERE e.tenant_id = u.tenant_id
                             AND e.service_key = sp.service_key
                             AND e.state = 'entitled'
                             AND (e.feature_key = ''
                                  OR sp.feature_key = e.feature_key
                                  OR starts_with(sp.feature_key, e.feature_key || '/')))
                ) s
            ), '[]'::jsonb)
        )
        -- The scopes that count only on a strong sign-in, a member of the answer
        -- only when due: this membership is a person's account in the deployment's
        -- own company and is on the list of the deployment's administrators. Every
        -- other membership answers exactly as it did without this member.
        || CASE WHEN left(u.subject_key, 4) = 'sub:'
                     AND EXISTS (SELECT 1
                                   FROM rolebyte.deployment d
                                   JOIN rolebyte.deployment_admin da ON da.user_id = u.id
                                  WHERE d.company_tenant_id = u.tenant_id)
                THEN jsonb_build_object('highScopes', jsonb_build_array('deployment:admin'))
                ELSE '{}'::jsonb END
        AS m
        FROM rolebyte.user_account u
        JOIN rolebyte.tenant t ON t.id = u.tenant_id
        CROSS JOIN LATERAL (SELECT rolebyte.is_administrator(u.id) AS yes) adm
        WHERE u.subject_key = v_subject
          AND u.status = 'active'
          AND t.status = 'active'
    ) sub;

    po_data := util.result_success(jsonb_build_object('memberships', v_memberships));
EXCEPTION
    WHEN sqlstate 'P0001' THEN
        RAISE;
    WHEN OTHERS THEN
        RAISE EXCEPTION '%', util.result_error('membership:error', sqlerrm) USING errcode = 'P0001';
END;
$$;

REVOKE ALL ON PROCEDURE rolebyte.resolve(jsonb, jsonb) FROM PUBLIC;
GRANT EXECUTE ON PROCEDURE rolebyte.resolve(jsonb, jsonb) TO rolebyte_public;

-- rolebyte.user_list — the tenant's people, by name, for a picker.
--
-- The narrowest possible read of the membership register: who is in this
-- workspace and what they are called. No roles, no grants, no history, no
-- identity code — a name and the opaque key work is attributed to.
--
-- It exists because every product that shows work has to show WHO HOLDS IT,
-- and a screen cannot put a name to a key it may not read. The administration
-- read (members with their grants) answers a different question for a different
-- audience: anyone who may see a task needs this one, and almost none of them
-- may see that one. One cannot stand in for the other without handing
-- everybody's grants to anyone who can open a task.
--
-- MACHINE MEMBERS ARE EXCLUDED, in the procedure rather than in a caller. A
-- service account is a member row like any other, so a list that returned
-- every member would offer the storage service as a person to assign work to.
--
-- Revoked members are included and say so: work attributed to somebody who has
-- left still has to show their name, and a screen decides for itself whether to
-- offer them. Anonymised rows carry whatever name the erasure left behind,
-- which is the point of anonymising rather than deleting.
CREATE OR REPLACE PROCEDURE rolebyte.user_list(IN pi_data jsonb, INOUT po_data jsonb)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = rolebyte, util, pg_temp
AS $$
DECLARE
    v_tenant text;
    v_items  jsonb;
BEGIN
    v_tenant := NULLIF(trim(pi_data->>'tenantId'), '');
    IF v_tenant IS NULL THEN
        po_data := util.result_error('membership:invalid', 'tenantId is required');
        RETURN;
    END IF;

    IF NOT EXISTS (SELECT 1 FROM rolebyte.tenant WHERE id = v_tenant) THEN
        po_data := util.result_error('tenant:not_found', 'tenant does not exist');
        RETURN;
    END IF;

    SELECT COALESCE(jsonb_agg(jsonb_build_object(
               'id',          u.id,
               'subjectKey',  u.subject_key,
               'displayName', u.display_name,
               'status',      u.status
           ) ORDER BY lower(u.display_name), u.id), '[]'::jsonb)
      INTO v_items
      FROM rolebyte.user_account u
     WHERE u.tenant_id = v_tenant
       AND u.subject_key NOT LIKE 'svc:%';

    po_data := util.result_success(jsonb_build_object('users', v_items));
EXCEPTION
    WHEN sqlstate 'P0001' THEN
        RAISE;
    WHEN OTHERS THEN
        RAISE EXCEPTION '%', util.result_error('membership:error', sqlerrm) USING errcode = 'P0001';
END;
$$;

REVOKE ALL ON PROCEDURE rolebyte.user_list(jsonb, jsonb) FROM PUBLIC;
GRANT EXECUTE ON PROCEDURE rolebyte.user_list(jsonb, jsonb) TO rolebyte_public;

-- rolebyte.access_list — who holds what in a tenant, for its administrators.
--
-- Every member of the tenant with what the register holds for them: their
-- service roles, their tenant roles, and whether the Administrator checkbox is
-- ticked (the `membership:admin` rung, answered as `administrator` rather than
-- as a service role, because that is how it is set and unset).
--
-- It answers what is STORED, not what reaches a token. A revoked member's
-- grants stay on record when their access ends, and they are listed here as
-- held; `status` is what says none of them reaches a token any more. So nobody
-- disappears from this list: a person who has left is still somebody whose
-- work carries their name.
--
-- Service accounts are listed, marked `kind: service`. The names read leaves
-- them out because a picker must not offer a machine as somebody to give work
-- to; this read is for the administrator, who has to be able to see every
-- holder of a grant in their tenant, a machine's included.
--
-- `userType` is the user type the member holds, the one an administrator sets.
-- `chartUserType` is the one the chart position they sit in gives while the
-- tenant has the chart, which is then the type in force; otherwise it is null.
-- Each tenant role and user type is named as entered (`name`) and in the app's
-- other languages (`labels`).
-- `lastSignedInOn` is the day the register last gave them access (null: not
-- since that date was first kept). `note` is what the tenant's administrators
-- wrote about them (empty: nothing).
--
-- `arrival` marks a person who has signed in and holds nothing yet: an active
-- account (an invitation becomes active only at its first sign-in, and a
-- directory admits a person active and with nothing), no service role, no
-- tenant role, not an administrator, a user type in force that holds nothing,
-- and no chart position carrying a box. A person whose last grant was taken away
-- is one again: they can sign in and do nothing, which is what an administrator
-- looking at arrivals is there to change. A service account never is one: it
-- does not sign in to be given something. It is decided here so that every
-- screen showing arrivals shows the same people.
--
-- No paging: a tenant is tens of people, the same as the names read.
CREATE OR REPLACE PROCEDURE rolebyte.access_list(IN pi_data jsonb, INOUT po_data jsonb)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = rolebyte, util, pg_temp
AS $$
DECLARE
    v_tenant text;
    v_items  jsonb;
BEGIN
    v_tenant := NULLIF(trim(pi_data->>'tenantId'), '');
    IF v_tenant IS NULL THEN
        po_data := util.result_error('membership:invalid', 'tenantId is required');
        RETURN;
    END IF;

    IF NOT EXISTS (SELECT 1 FROM rolebyte.tenant WHERE id = v_tenant) THEN
        po_data := util.result_error('tenant:not_found', 'tenant does not exist');
        RETURN;
    END IF;

    SELECT COALESCE(jsonb_agg(jsonb_build_object(
               'id',            m.id,
               'subjectKey',    m.subject_key,
               'displayName',   m.display_name,
               'kind',          m.kind,
               'status',        m.status,
               'administrator', m.administrator,
               'arrival',       m.kind = 'person' AND m.status = 'active' AND NOT m.administrator
                                AND jsonb_array_length(m.service_roles) = 0
                                AND jsonb_array_length(m.tenant_roles) = 0
                                AND NOT m.type_holds AND NOT m.seat_holds,
               'serviceRoles',  m.service_roles,
               'tenantRoles',   m.tenant_roles,
               'userType',      m.user_type,
               'chartUserType', m.chart_user_type,
               'lastSignedInOn', to_jsonb(m.last_signed_in_on),
               'note',          m.note
           ) ORDER BY lower(m.display_name), m.id), '[]'::jsonb)
      INTO v_items
      FROM (
          SELECT u.id, u.subject_key, u.display_name, u.status, u.last_signed_in_on, u.note,
                 CASE WHEN u.subject_key LIKE 'svc:%' THEN 'service' ELSE 'person' END AS kind,
                 (SELECT jsonb_build_object('id', t.id, 'name', t.name, 'labels', t.labels)
                    FROM rolebyte.user_type t
                   WHERE t.tenant_id = u.tenant_id AND t.id = u.user_type_id) AS user_type,
                 (SELECT jsonb_build_object('id', t.id, 'name', t.name, 'labels', t.labels)
                    FROM rolebyte.chart_holder h
                    JOIN rolebyte.chart_position p ON p.tenant_id = h.tenant_id AND p.id = h.position_id
                    JOIN rolebyte.user_type t ON t.tenant_id = p.tenant_id AND t.id = p.user_type_id
                   WHERE h.tenant_id = u.tenant_id AND h.user_id = u.id
                     AND rolebyte.chart_entitled(u.tenant_id)) AS chart_user_type,
                 EXISTS (
                     SELECT 1 FROM rolebyte.user_type_permission up
                      WHERE up.user_type_id = rolebyte.effective_user_type(u.tenant_id, u.id)
                 ) AS type_holds,
                 rolebyte.chart_entitled(u.tenant_id) AND EXISTS (
                     SELECT 1
                       FROM rolebyte.chart_holder h
                       JOIN rolebyte.chart_position_permission cp ON cp.position_id = h.position_id
                      WHERE h.tenant_id = u.tenant_id AND h.user_id = u.id
                 ) AS seat_holds,
                 EXISTS (
                     SELECT 1
                       FROM rolebyte.assignment a
                       JOIN rolebyte.role_definition rd ON rd.id = a.role_definition_id
                      WHERE a.user_id = u.id AND a.state = 'granted'
                        AND rolebyte.is_administrator_rung(rd.role_group, rd.role_level)
                 ) AS administrator,
                 COALESCE((
                     SELECT jsonb_agg(jsonb_build_object(
                                'service', rd.service_key,
                                'group',   rd.role_group,
                                'level',   rd.role_level
                            ) ORDER BY rd.service_key, rd.role_group, rd.role_level)
                       FROM rolebyte.assignment a
                       JOIN rolebyte.role_definition rd ON rd.id = a.role_definition_id
                      WHERE a.user_id = u.id AND a.state = 'granted'
                        AND NOT rolebyte.is_administrator_rung(rd.role_group, rd.role_level)
                 ), '[]'::jsonb) AS service_roles,
                 COALESCE((
                     SELECT jsonb_agg(jsonb_build_object('id', r.id, 'name', r.name, 'labels', r.labels)
                                      ORDER BY lower(r.name), r.id)
                       FROM rolebyte.tenant_role_assignment ta
                       JOIN rolebyte.tenant_role r ON r.id = ta.tenant_role_id AND r.tenant_id = ta.tenant_id
                      WHERE ta.user_id = u.id AND ta.tenant_id = u.tenant_id AND ta.state = 'granted'
                 ), '[]'::jsonb) AS tenant_roles
            FROM rolebyte.user_account u
           WHERE u.tenant_id = v_tenant
      ) m;

    po_data := util.result_success(jsonb_build_object('members', v_items));
EXCEPTION
    WHEN sqlstate 'P0001' THEN
        RAISE;
    WHEN OTHERS THEN
        RAISE EXCEPTION '%', util.result_error('membership:error', sqlerrm) USING errcode = 'P0001';
END;
$$;

REVOKE ALL ON PROCEDURE rolebyte.access_list(jsonb, jsonb) FROM PUBLIC;
GRANT EXECUTE ON PROCEDURE rolebyte.access_list(jsonb, jsonb) TO rolebyte_public;

-- user_note_set — an administrator's note on a member of the tenant, kept on the
-- member and read with the access list. Replaces the note whole; an empty one
-- clears it.
--
-- The note is trimmed and a Windows line break kept as one; line breaks and tabs
-- are kept, every other control character (C0 and C1), the line and paragraph
-- separators, and every character that changes the direction text runs in is
-- refused (a note is shown beside a name, and a direction override could make it
-- read as another name). At most 1000 characters. A service is given no note. A
-- refusal never repeats the note. A member whose access is revoked keeps none.
--
-- The history line says a note was set or cleared, under the administrator and
-- about the member, and never what it says: the history cannot be rewritten, so
-- a note's words in it could never be erased. An unchanged note writes nothing.
CREATE OR REPLACE PROCEDURE rolebyte.user_note_set(IN pi_data jsonb, INOUT po_data jsonb)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = rolebyte, util, pg_temp
AS $$
DECLARE
    v_actor  text := NULLIF(btrim(pi_data->>'actor'), '');
    v_tenant text := NULLIF(btrim(pi_data->>'tenantId'), '');
    v_user   text := NULLIF(btrim(pi_data->>'userId'), '');
    v_note   text := pi_data->>'note';
    v_member rolebyte.user_account%ROWTYPE;
BEGIN
    IF v_actor IS NULL OR v_tenant IS NULL OR v_user IS NULL THEN
        po_data := util.result_error('membership:invalid', 'actor, tenantId and userId are required');
        RETURN;
    END IF;
    IF v_note IS NULL OR jsonb_typeof(pi_data->'note') <> 'string' THEN
        po_data := util.result_error('membership:invalid', 'note is required; send an empty one to clear it');
        RETURN;
    END IF;

    v_note := btrim(replace(v_note, E'\r\n', E'\n'), E' \t\n\r');
    IF char_length(v_note) > 1000 THEN
        po_data := util.result_error('membership:invalid', 'a note is at most 1000 characters');
        RETURN;
    END IF;
    IF v_note ~ E'[\\x01-\\x08\\x0B-\\x1F\\x7F-\\x9F\\u061C\\u200E\\u200F\\u2028-\\u202E\\u2066-\\u2069]' THEN
        po_data := util.result_error('membership:invalid', 'a note may not carry control or direction-changing characters');
        RETURN;
    END IF;

    -- A revoked member is no longer one: their note went with their access, and
    -- none is written on them again.
    SELECT * INTO v_member FROM rolebyte.user_account
     WHERE tenant_id = v_tenant AND id = v_user AND status <> 'revoked'
       FOR UPDATE;
    IF NOT FOUND THEN
        po_data := util.result_error('membership:not_found', 'no such member');
        RETURN;
    END IF;
    IF v_member.subject_key LIKE 'svc:%' THEN
        po_data := util.result_error('membership:invalid', 'a service is given no note');
        RETURN;
    END IF;

    IF v_member.note = v_note THEN
        po_data := util.result_success(jsonb_build_object('userId', v_user, 'changed', false));
        RETURN;
    END IF;

    UPDATE rolebyte.user_account SET note = v_note WHERE id = v_user;
    INSERT INTO rolebyte.event (id, actor, tenant_id, user_id, kind, payload)
    VALUES (util.generate_ulid(), v_actor, v_tenant, v_user, 'noteChanged',
            jsonb_build_object('cleared', v_note = ''));

    po_data := util.result_success(jsonb_build_object('userId', v_user, 'changed', true));
EXCEPTION
    WHEN sqlstate 'P0001' THEN
        RAISE;
    WHEN OTHERS THEN
        RAISE EXCEPTION '%', util.result_error('membership:error', sqlerrm) USING errcode = 'P0001';
END;
$$;

REVOKE ALL ON PROCEDURE rolebyte.user_note_set(jsonb, jsonb) FROM PUBLIC;
GRANT EXECUTE ON PROCEDURE rolebyte.user_note_set(jsonb, jsonb) TO rolebyte_public;

-- history — the append-only promise made queryable: a tenant's membership
-- events, newest first, one page at a time. The billing seat-count source.
--
-- Narrowed by a time window (`from` inclusive, `to` exclusive), by one service
-- (the events carry the service in their payload) and by `kindPrefix`, the
-- family of kinds whose name starts with it (`chart` is every chart line). A
-- page is at most `limit` lines (100 when not given, never more than 500);
-- `before` names a line already read, and the page holds the lines older than
-- it, so a reader walks the whole history page by page with no line missed or
-- repeated, lines sharing a moment included. `more` says whether older lines
-- exist beyond the page.
--
-- `actor` narrows to one actor. A typed key (`sub:…` a person, `svc:…` a
-- service) keeps the lines that key wrote; for a person of this tenant it also
-- keeps the lines about them that no person wrote — their arrival through an
-- invitation claim or the corporate login, and the deployment's own acts on
-- them — so a person's story begins where they joined. `operator` keeps the
-- lines written by whoever runs the deployment: an actor that is neither a
-- person nor a service. It only narrows: nothing outside the tenant's history
-- is ever answered.
CREATE OR REPLACE PROCEDURE rolebyte.history(IN pi_data jsonb, INOUT po_data jsonb)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = rolebyte, util, pg_temp
AS $$
DECLARE
    v_tenant  text;
    v_service text;
    v_prefix  text;
    v_from    timestamptz;
    v_to      timestamptz;
    v_limit   text;
    v_n       int := 100;
    v_before  text;
    v_at      timestamptz;
    v_events  jsonb;
    v_more    boolean;
    v_actor   text;
    v_about   text;
BEGIN
    v_tenant := NULLIF(trim(pi_data->>'tenantId'), '');
    IF v_tenant IS NULL THEN
        po_data := util.result_error('membership:invalid', 'tenantId is required');
        RETURN;
    END IF;

    v_actor := NULLIF(trim(pi_data->>'actor'), '');
    IF v_actor IS NOT NULL AND v_actor <> 'operator' THEN
        IF v_actor !~ '^[a-z]+:.+$' THEN
            po_data := util.result_error('membership:invalid',
                'actor is a typed key, such as sub:<person>, or operator');
            RETURN;
        END IF;
        IF starts_with(v_actor, 'sub:') THEN
            SELECT u.id INTO v_about
              FROM rolebyte.user_account u
             WHERE u.tenant_id = v_tenant AND u.subject_key = v_actor;
        END IF;
    END IF;

    v_service := NULLIF(trim(pi_data->>'service'), '');
    v_prefix  := NULLIF(trim(pi_data->>'kindPrefix'), '');
    v_from    := NULLIF(trim(pi_data->>'from'), '')::timestamptz;
    v_to      := NULLIF(trim(pi_data->>'to'), '')::timestamptz;

    v_limit := NULLIF(trim(pi_data->>'limit'), '');
    IF v_limit IS NOT NULL THEN
        -- Checked as text before any cast: SQL does not promise to stop an OR at
        -- its first true side, so a word must never reach the cast.
        IF v_limit !~ '^[0-9]{1,6}$' THEN
            po_data := util.result_error('membership:invalid', 'limit must be a whole number from 1');
            RETURN;
        END IF;
        v_n := LEAST(v_limit::int, 500);
        IF v_n < 1 THEN
            po_data := util.result_error('membership:invalid', 'limit must be a whole number from 1');
            RETURN;
        END IF;
    END IF;

    v_before := NULLIF(trim(pi_data->>'before'), '');
    IF v_before IS NOT NULL THEN
        SELECT ev.at INTO v_at FROM rolebyte.event ev WHERE ev.id = v_before AND ev.tenant_id = v_tenant;
        IF NOT FOUND THEN
            po_data := util.result_error('membership:invalid', 'before names no line of this history');
            RETURN;
        END IF;
    END IF;

    -- One line past the page is read to learn whether older lines exist.
    SELECT COALESCE(jsonb_agg(jsonb_build_object(
               'id',      e.id,
               'at',      e.at,
               'actor',   e.actor,
               'userId',  COALESCE(e.user_id, ''),
               'kind',    e.kind,
               'payload', e.payload
           ) ORDER BY e.at DESC, e.id DESC) FILTER (WHERE e.n <= v_n), '[]'::jsonb),
           count(*) > v_n
      INTO v_events, v_more
      FROM (
          SELECT ev.*, row_number() OVER (ORDER BY ev.at DESC, ev.id DESC) AS n
            FROM (
                SELECT *
                  FROM rolebyte.event
                 WHERE tenant_id = v_tenant
                   AND (v_from IS NULL OR at >= v_from)
                   AND (v_to IS NULL OR at < v_to)
                   AND (v_service IS NULL OR payload->>'service' = v_service)
                   AND (v_prefix IS NULL OR starts_with(kind, v_prefix))
                   AND (v_actor IS NULL
                        OR (v_actor = 'operator' AND actor !~ '^(sub|svc):')
                        OR (v_actor <> 'operator'
                            AND (actor = v_actor
                                 OR (v_about IS NOT NULL AND user_id = v_about
                                     AND NOT starts_with(actor, 'sub:')))))
                   AND (v_before IS NULL OR (at, id) < (v_at, v_before))
                 ORDER BY at DESC, id DESC
                 LIMIT v_n + 1
            ) ev
      ) e;

    po_data := util.result_success(jsonb_build_object('events', v_events, 'more', v_more));
EXCEPTION
    WHEN sqlstate 'P0001' THEN
        RAISE;
    WHEN invalid_datetime_format OR datetime_field_overflow THEN
        RAISE EXCEPTION '%', util.result_error('membership:invalid', 'from/to must be ISO timestamps') USING errcode = 'P0001';
    WHEN OTHERS THEN
        RAISE EXCEPTION '%', util.result_error('membership:error', sqlerrm) USING errcode = 'P0001';
END;
$$;

REVOKE ALL ON PROCEDURE rolebyte.history(jsonb, jsonb) FROM PUBLIC;
GRANT EXECUTE ON PROCEDURE rolebyte.history(jsonb, jsonb) TO rolebyte_public;

-- bootstrap_state — whether the one-time bootstrap door is spent: true once
-- any non-revoked user holds a granted `membership:admin` assignment. Takes a
-- transaction-scoped advisory lock so concurrent bootstrap attempts serialize
-- on it: the caller runs this FIRST inside its bootstrap transaction, and the
-- second attempt blocks until the first commits, then sees bootstrapped=true.
CREATE OR REPLACE PROCEDURE rolebyte.bootstrap_state(IN pi_data jsonb, INOUT po_data jsonb)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = rolebyte, util, pg_temp
AS $$
BEGIN
    PERFORM pg_advisory_xact_lock(hashtext('rolebyte.bootstrap'));

    po_data := util.result_success(jsonb_build_object(
        'bootstrapped', EXISTS (
            SELECT 1
            FROM rolebyte.assignment a
            JOIN rolebyte.role_definition rd ON rd.id = a.role_definition_id
            JOIN rolebyte.user_account u ON u.id = a.user_id
            WHERE rd.role_group = 'membership'
              AND rd.role_level = 'admin'
              AND a.state = 'granted'
              AND u.status <> 'revoked'
        )
    ));
EXCEPTION
    WHEN sqlstate 'P0001' THEN
        RAISE;
    WHEN OTHERS THEN
        RAISE EXCEPTION '%', util.result_error('membership:error', sqlerrm) USING errcode = 'P0001';
END;
$$;

REVOKE ALL ON PROCEDURE rolebyte.bootstrap_state(jsonb, jsonb) FROM PUBLIC;
GRANT EXECUTE ON PROCEDURE rolebyte.bootstrap_state(jsonb, jsonb) TO rolebyte_public;

-- ---------------------------------------------------------------------------
-- Tenant roles. A tenant's own roles, each made of ticks over the permissions
-- services declare, identified by id and named as the tenant names them. Every
-- procedure below takes the tenant, and a role of any other tenant answers
-- exactly as one that never existed. What a granted role ticks reaches the
-- person's token through `resolve`, so a change to the ticks or the grants
-- changes what they resolve to.
-- ---------------------------------------------------------------------------

-- tenant_role_permission_names — the permissions a role holds, spelled as they
-- travel (`<service>/<feature path>:<act>`, and `…@<key>.<generation>` for one
-- field of a per-field family), ordered by service, feature, act and field.
CREATE OR REPLACE FUNCTION rolebyte.tenant_role_permission_names(p_role_id text)
RETURNS jsonb
LANGUAGE sql
STABLE
SET search_path = rolebyte, pg_temp
AS $$
    SELECT COALESCE(jsonb_agg(sp.service_key || '/' || sp.feature_key || ':' || sp.act || COALESCE('@' || t.param, '')
                              ORDER BY sp.service_key, sp.feature_key, sp.act, t.param NULLS FIRST), '[]'::jsonb)
      FROM rolebyte.tenant_role_permission t
      JOIN rolebyte.service_permission sp ON sp.id = t.permission_id
     WHERE t.tenant_role_id = p_role_id;
$$;

REVOKE ALL ON FUNCTION rolebyte.tenant_role_permission_names(text) FROM PUBLIC;

-- name_labels_refusal — why a write's names in other languages (`labels`) of a
-- tenant role, a user type or a chart position cannot be taken, or NULL when
-- they can. The map is judged as every configured list's is (languages the app
-- speaks, each holding a name or null, a blank name refused), and then each
-- name, trimmed, as the name itself is: 1 to 100 characters on one line. A name
-- in another language is still a name on a screen, so it is held to the same
-- rule as the one typed in the workspace's language.
CREATE OR REPLACE FUNCTION rolebyte.name_labels_refusal(p_labels jsonb)
RETURNS text
LANGUAGE plpgsql
STABLE
SET search_path = rolebyte, util, pg_temp
AS $$
DECLARE
    v_why text;
    r     record;
BEGIN
    v_why := util.labels_refusal(p_labels);
    IF v_why IS NOT NULL OR p_labels IS NULL OR jsonb_typeof(p_labels) <> 'object' THEN
        RETURN v_why;
    END IF;
    FOR r IN SELECT e.key, e.value FROM jsonb_each(p_labels) e ORDER BY e.key LOOP
        IF jsonb_typeof(r.value) = 'string'
           AND rolebyte.is_tenant_role_name(trim(r.value #>> '{}')) IS NOT TRUE THEN
            RETURN 'labels: the name in ' || r.key || ' is 1 to 100 characters on one line';
        END IF;
    END LOOP;
    RETURN NULL;
END;
$$;

REVOKE ALL ON FUNCTION rolebyte.name_labels_refusal(jsonb) FROM PUBLIC;

-- tenant_role_reads_alike — the first language the app speaks in which another
-- of the tenant's roles reads the same as a role named `p_name`, with these
-- names in other languages, would; NULL when there is none. What a reader sees
-- is the name in their language where one was given and the name as entered
-- otherwise, compared ignoring case, so a role named Strādnieks and another
-- named Worker with {"lv": "Strādnieks"} read alike to a Latvian reader. The
-- role itself (`p_role`, NULL for a new one) is never compared with itself.
-- Only right while the caller holds the tenant's row: that is what makes a
-- second act naming a role wait for the first, then read what it wrote.
--
-- Answers {"language", "name"}: the language and the other role's name as
-- entered, which a refusal names — the administrator may know that role under
-- another word than the one that clashed.
CREATE OR REPLACE FUNCTION rolebyte.tenant_role_reads_alike(p_tenant text, p_role text, p_name text, p_labels jsonb)
RETURNS jsonb
LANGUAGE sql
STABLE
SET search_path = rolebyte, util, pg_temp
AS $$
    SELECT jsonb_build_object('language', l.lang, 'name', r.name)
      FROM unnest(util.app_languages()) WITH ORDINALITY AS l(lang, n)
      JOIN rolebyte.tenant_role r
        ON r.tenant_id = p_tenant
       AND r.id IS DISTINCT FROM p_role
       AND lower(COALESCE(r.labels->>l.lang, r.name)) = lower(COALESCE(p_labels->>l.lang, p_name))
     ORDER BY l.n, r.name
     LIMIT 1;
$$;

REVOKE ALL ON FUNCTION rolebyte.tenant_role_reads_alike(text, text, text, jsonb) FROM PUBLIC;

-- tenant_role_list — the tenant's roles with what each holds, ordered by name.
-- Each carries its name as entered and its names in other languages (`labels`);
-- the order is the name as entered, and a screen re-sorts in its reader's words.
-- A role the tenant was opened with carries its `seed` (`guest` · `worker` ·
-- `manager`), so a screen can tell it from one the tenant made; empty otherwise.
CREATE OR REPLACE PROCEDURE rolebyte.tenant_role_list(IN pi_data jsonb, INOUT po_data jsonb)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = rolebyte, util, pg_temp
AS $$
DECLARE
    v_tenant text;
    v_roles  jsonb;
BEGIN
    v_tenant := NULLIF(trim(pi_data->>'tenantId'), '');
    IF v_tenant IS NULL THEN
        po_data := util.result_error('membership:invalid', 'tenantId is required');
        RETURN;
    END IF;

    IF NOT EXISTS (SELECT 1 FROM rolebyte.tenant WHERE id = v_tenant) THEN
        po_data := util.result_error('tenant:not_found', 'tenant does not exist');
        RETURN;
    END IF;

    SELECT COALESCE(jsonb_agg(jsonb_build_object(
               'id',          r.id,
               'seed',        r.seed,
               'name',        r.name,
               'labels',      r.labels,
               'description', r.description,
               'permissions', rolebyte.tenant_role_permission_names(r.id)
           ) ORDER BY lower(r.name), r.id), '[]'::jsonb)
      INTO v_roles
      FROM rolebyte.tenant_role r
     WHERE r.tenant_id = v_tenant;

    po_data := util.result_success(jsonb_build_object('roles', v_roles));
EXCEPTION
    WHEN sqlstate 'P0001' THEN
        RAISE;
    WHEN OTHERS THEN
        RAISE EXCEPTION '%', util.result_error('membership:error', sqlerrm) USING errcode = 'P0001';
END;
$$;

REVOKE ALL ON PROCEDURE rolebyte.tenant_role_list(jsonb, jsonb) FROM PUBLIC;
GRANT EXECUTE ON PROCEDURE rolebyte.tenant_role_list(jsonb, jsonb) TO rolebyte_public;

-- tenant_role_define — the tenant makes a role: a name, its names in the app's
-- other languages (`labels`, optional, taken as given), an optional
-- description, and no permissions yet. A name another role of the tenant
-- already carries, in any letter case, is refused, and so is a role that would
-- read the same as another in any language the app speaks. Emits
-- `tenantRoleDefined`, carrying the names.
CREATE OR REPLACE PROCEDURE rolebyte.tenant_role_define(IN pi_data jsonb, INOUT po_data jsonb)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = rolebyte, util, pg_temp
AS $$
DECLARE
    v_actor  text;
    v_tenant text;
    v_name   text;
    v_labels jsonb;
    v_desc   text;
    v_why    text;
    v_clash  jsonb;
    v_row    rolebyte.tenant_role%ROWTYPE;
BEGIN
    v_actor := NULLIF(trim(pi_data->>'actor'), '');
    IF v_actor IS NULL THEN
        po_data := util.result_error('membership:invalid', 'actor is required');
        RETURN;
    END IF;

    v_tenant := NULLIF(trim(pi_data->>'tenantId'), '');
    IF v_tenant IS NULL THEN
        po_data := util.result_error('membership:invalid', 'tenantId is required');
        RETURN;
    END IF;

    IF jsonb_typeof(pi_data->'name') IS DISTINCT FROM 'string' THEN
        po_data := util.result_error('membership:invalid', 'name is required');
        RETURN;
    END IF;
    v_name := trim(pi_data->>'name');
    IF rolebyte.is_tenant_role_name(v_name) IS NOT TRUE THEN
        po_data := util.result_error('membership:invalid',
            'a role name is 1 to 100 characters on one line');
        RETURN;
    END IF;

    IF pi_data ? 'description' AND jsonb_typeof(pi_data->'description') IS DISTINCT FROM 'string' THEN
        po_data := util.result_error('membership:invalid', 'description must be a string');
        RETURN;
    END IF;
    v_desc := COALESCE(trim(pi_data->>'description'), '');
    IF length(v_desc) > 1000 THEN
        po_data := util.result_error('membership:invalid', 'a role description is at most 1000 characters');
        RETURN;
    END IF;

    v_why := rolebyte.name_labels_refusal(pi_data->'labels');
    IF v_why IS NOT NULL THEN
        po_data := util.result_error('membership:invalid', v_why);
        RETURN;
    END IF;
    v_labels := util.labels_merge('{}'::jsonb, pi_data->'labels');

    -- The tenant's row is held to the end of the act, as by every act that names
    -- the tenant's roles, so two administrators naming roles at the same moment
    -- take turns: the second reads the first's role and is refused if the two
    -- would read alike.
    PERFORM 1 FROM rolebyte.tenant WHERE id = v_tenant FOR UPDATE;
    IF NOT FOUND THEN
        po_data := util.result_error('tenant:not_found', 'tenant does not exist');
        RETURN;
    END IF;

    IF EXISTS (SELECT 1 FROM rolebyte.tenant_role
               WHERE tenant_id = v_tenant AND lower(name) = lower(v_name)) THEN
        po_data := util.result_error('membership:conflict', 'a role with this name already exists in the tenant');
        RETURN;
    END IF;
    v_clash := rolebyte.tenant_role_reads_alike(v_tenant, NULL, v_name, v_labels);
    IF v_clash IS NOT NULL THEN
        po_data := util.result_error('membership:conflict',
            'a role reading the same in ' || (v_clash->>'language') || ' already exists in the tenant: '
                || (v_clash->>'name'));
        RETURN;
    END IF;

    INSERT INTO rolebyte.tenant_role (id, tenant_id, name, labels, description)
    VALUES (util.generate_ulid(), v_tenant, v_name, v_labels, v_desc)
    RETURNING * INTO v_row;

    INSERT INTO rolebyte.event (id, actor, tenant_id, kind, payload)
    VALUES (util.generate_ulid(), v_actor, v_tenant, 'tenantRoleDefined',
            jsonb_build_object('roleId', v_row.id, 'name', v_row.name, 'labels', v_row.labels,
                               'description', v_row.description));

    po_data := util.result_success(jsonb_build_object(
        'id',          v_row.id,
        'name',        v_row.name,
        'labels',      v_row.labels,
        'description', v_row.description,
        'permissions', '[]'::jsonb
    ));
EXCEPTION
    WHEN sqlstate 'P0001' THEN
        RAISE;
    WHEN unique_violation THEN
        -- Two administrators naming two roles alike at the same moment: the unique
        -- index decides, and the loser gets the same answer the pre-check gives.
        RAISE EXCEPTION '%', util.result_error('membership:conflict', 'a role with this name already exists in the tenant') USING errcode = 'P0001';
    WHEN OTHERS THEN
        RAISE EXCEPTION '%', util.result_error('membership:error', sqlerrm) USING errcode = 'P0001';
END;
$$;

REVOKE ALL ON PROCEDURE rolebyte.tenant_role_define(jsonb, jsonb) FROM PUBLIC;
GRANT EXECUTE ON PROCEDURE rolebyte.tenant_role_define(jsonb, jsonb) TO rolebyte_public;

-- tenant_role_update — change what a role is called and how it is described:
-- its name (`name`), its names in the app's other languages (`labels`, merged
-- per language: a language sent with a name sets it, one sent with null removes
-- it, one not sent is left), its description (`description`; an empty one
-- clears it), or any of them. Only what is sent changes, so a screen editing one
-- language cannot erase another; a call sending none of the three is refused.
-- Changing nothing records nothing. Emits `tenantRoleRenamed` when the name or
-- the names in other languages change — carrying the name before and after and
-- every name in another language the role holds after the change — and
-- `tenantRoleDescribed` for a new description.
CREATE OR REPLACE PROCEDURE rolebyte.tenant_role_update(IN pi_data jsonb, INOUT po_data jsonb)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = rolebyte, util, pg_temp
AS $$
DECLARE
    v_actor   text;
    v_tenant  text;
    v_role    text;
    v_name    text;
    v_labels  jsonb;
    v_names   boolean := COALESCE(jsonb_typeof(pi_data->'labels') = 'object', false);
    v_desc    text;
    v_why     text;
    v_clash   jsonb;
    v_row     rolebyte.tenant_role%ROWTYPE;
    v_changed boolean := false;
BEGIN
    v_actor  := NULLIF(trim(pi_data->>'actor'), '');
    v_tenant := NULLIF(trim(pi_data->>'tenantId'), '');
    v_role   := NULLIF(trim(pi_data->>'roleId'), '');
    IF v_actor IS NULL OR v_tenant IS NULL OR v_role IS NULL THEN
        po_data := util.result_error('membership:invalid', 'actor, tenantId and roleId are required');
        RETURN;
    END IF;

    -- Sent at all, a name is a name: anything but text, or a blank, is refused,
    -- never read as "leave it".
    IF pi_data ? 'name' THEN
        IF jsonb_typeof(pi_data->'name') IS DISTINCT FROM 'string' THEN
            po_data := util.result_error('membership:invalid', 'name must be a string');
            RETURN;
        END IF;
        v_name := trim(pi_data->>'name');
        IF rolebyte.is_tenant_role_name(v_name) IS NOT TRUE THEN
            po_data := util.result_error('membership:invalid',
                'a role name is 1 to 100 characters on one line');
            RETURN;
        END IF;
    END IF;

    v_why := rolebyte.name_labels_refusal(pi_data->'labels');
    IF v_why IS NOT NULL THEN
        po_data := util.result_error('membership:invalid', v_why);
        RETURN;
    END IF;

    IF pi_data ? 'description' AND jsonb_typeof(pi_data->'description') IS DISTINCT FROM 'string' THEN
        po_data := util.result_error('membership:invalid', 'description must be a string');
        RETURN;
    END IF;

    IF v_name IS NULL AND NOT v_names AND NOT (pi_data ? 'description') THEN
        po_data := util.result_error('membership:invalid', 'a name, labels, a description or more are required');
        RETURN;
    END IF;

    -- The tenant's row first, as every act naming the tenant's roles takes it:
    -- a second rename at the same moment waits, then reads this one's names.
    PERFORM 1 FROM rolebyte.tenant WHERE id = v_tenant FOR UPDATE;
    IF NOT FOUND THEN
        po_data := util.result_error('membership:not_found', 'role does not exist');
        RETURN;
    END IF;

    SELECT * INTO v_row
      FROM rolebyte.tenant_role
     WHERE id = v_role AND tenant_id = v_tenant
       FOR UPDATE;
    IF NOT FOUND THEN
        po_data := util.result_error('membership:not_found', 'role does not exist');
        RETURN;
    END IF;

    v_name   := COALESCE(v_name, v_row.name);
    v_labels := CASE WHEN v_names THEN util.labels_merge(v_row.labels, pi_data->'labels')
                     ELSE v_row.labels END;
    v_desc := CASE WHEN pi_data ? 'description' THEN trim(pi_data->>'description')
                   ELSE v_row.description END;
    IF length(v_desc) > 1000 THEN
        po_data := util.result_error('membership:invalid', 'a role description is at most 1000 characters');
        RETURN;
    END IF;

    IF v_name <> v_row.name
       AND EXISTS (SELECT 1 FROM rolebyte.tenant_role
                   WHERE tenant_id = v_tenant AND lower(name) = lower(v_name) AND id <> v_row.id) THEN
        po_data := util.result_error('membership:conflict', 'a role with this name already exists in the tenant');
        RETURN;
    END IF;
    IF v_name <> v_row.name OR v_labels <> v_row.labels THEN
        v_clash := rolebyte.tenant_role_reads_alike(v_tenant, v_row.id, v_name, v_labels);
        IF v_clash IS NOT NULL THEN
            po_data := util.result_error('membership:conflict',
                'a role reading the same in ' || (v_clash->>'language') || ' already exists in the tenant: '
                || (v_clash->>'name'));
            RETURN;
        END IF;
    END IF;

    IF v_name <> v_row.name OR v_labels <> v_row.labels OR v_desc <> v_row.description THEN
        UPDATE rolebyte.tenant_role SET name = v_name, labels = v_labels, description = v_desc WHERE id = v_row.id;
        v_changed := true;
    END IF;

    IF v_name <> v_row.name OR v_labels <> v_row.labels THEN
        INSERT INTO rolebyte.event (id, actor, tenant_id, kind, payload)
        VALUES (util.generate_ulid(), v_actor, v_tenant, 'tenantRoleRenamed',
                jsonb_build_object('roleId', v_row.id, 'from', v_row.name, 'to', v_name, 'labels', v_labels));
    END IF;
    IF v_desc <> v_row.description THEN
        INSERT INTO rolebyte.event (id, actor, tenant_id, kind, payload)
        VALUES (util.generate_ulid(), v_actor, v_tenant, 'tenantRoleDescribed',
                jsonb_build_object('roleId', v_row.id, 'name', v_name,
                                   'from', v_row.description, 'to', v_desc));
    END IF;

    po_data := util.result_success(jsonb_build_object(
        'id',          v_row.id,
        'name',        v_name,
        'labels',      v_labels,
        'description', v_desc,
        'changed',     v_changed
    ));
EXCEPTION
    WHEN sqlstate 'P0001' THEN
        RAISE;
    WHEN unique_violation THEN
        RAISE EXCEPTION '%', util.result_error('membership:conflict', 'a role with this name already exists in the tenant') USING errcode = 'P0001';
    WHEN OTHERS THEN
        RAISE EXCEPTION '%', util.result_error('membership:error', sqlerrm) USING errcode = 'P0001';
END;
$$;

REVOKE ALL ON PROCEDURE rolebyte.tenant_role_update(jsonb, jsonb) FROM PUBLIC;
GRANT EXECUTE ON PROCEDURE rolebyte.tenant_role_update(jsonb, jsonb) TO rolebyte_public;

-- permission_name_parts — a permission's name split as it travels: the service
-- before the first `/`, the feature path up to the first `:`, the act, and, for
-- one field of a per-field family, the key and generation after `@`
-- (`projects/task:viewField@rate.2`). Every part is NULL when the name is not
-- shaped like one. The ONE parser of a name that arrives from outside.
CREATE OR REPLACE FUNCTION rolebyte.permission_name_parts(
    p_name text, OUT service text, OUT feature text, OUT act text, OUT param text)
LANGUAGE plpgsql
IMMUTABLE
SET search_path = rolebyte, pg_temp
AS $$
DECLARE
    v_base  text := p_name;
    v_at    int;
    v_slash int;
    v_colon int;
BEGIN
    IF p_name IS NULL THEN
        RETURN;
    END IF;

    v_at := position('@' IN p_name);
    IF v_at > 0 THEN
        v_base := left(p_name, v_at - 1);
        IF rolebyte.is_permission_param(substr(p_name, v_at + 1)) IS NOT TRUE THEN
            RETURN;
        END IF;
    END IF;

    v_slash := position('/' IN v_base);
    v_colon := position(':' IN v_base);
    IF v_slash = 0 OR v_colon < v_slash THEN
        RETURN;
    END IF;
    IF rolebyte.is_permission_service(left(v_base, v_slash - 1)) IS NOT TRUE
       OR rolebyte.is_permission_feature(substr(v_base, v_slash + 1, v_colon - v_slash - 1)) IS NOT TRUE
       OR rolebyte.is_permission_act(substr(v_base, v_colon + 1)) IS NOT TRUE THEN
        RETURN;
    END IF;

    service := left(v_base, v_slash - 1);
    feature := substr(v_base, v_slash + 1, v_colon - v_slash - 1);
    act     := substr(v_base, v_colon + 1);
    param   := CASE WHEN v_at > 0 THEN substr(p_name, v_at + 1) END;
END;
$$;

REVOKE ALL ON FUNCTION rolebyte.permission_name_parts(text) FROM PUBLIC;

-- tenant_role_permissions_set — replace what a role holds with the given set of
-- permission names, and answer the difference. The whole list is checked before
-- anything is written: one name that is not a declared permission refuses the
-- call and the set stays as it was. A name given twice counts once; an empty
-- list clears the role. The same set again changes nothing and records nothing.
-- A retired permission may stay in the set of a role that already holds it and
-- cannot be added to one that does not.
-- A per-field family is held one field at a time (`<family>@<key>.<generation>`):
-- the bare family is every field of its kind, which only the Administrator
-- checkbox holds, and `@` on any other permission names nothing.
-- Emits `tenantRoleReconfigured` with what was added and what was removed.
CREATE OR REPLACE PROCEDURE rolebyte.tenant_role_permissions_set(IN pi_data jsonb, INOUT po_data jsonb)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = rolebyte, util, pg_temp
AS $$
DECLARE
    v_actor   text;
    v_tenant  text;
    v_role    text;
    v_list    jsonb;
    v_perm    text;
    v_parts   record;
    v_base    text;
    v_pid     text;
    v_class   text;
    v_plane   text;
    v_retired boolean;
    v_ids     text[] := '{}'::text[];
    v_params  text[] := '{}'::text[];
    v_added   jsonb;
    v_removed jsonb;
    v_row     rolebyte.tenant_role%ROWTYPE;
BEGIN
    v_actor  := NULLIF(trim(pi_data->>'actor'), '');
    v_tenant := NULLIF(trim(pi_data->>'tenantId'), '');
    v_role   := NULLIF(trim(pi_data->>'roleId'), '');
    IF v_actor IS NULL OR v_tenant IS NULL OR v_role IS NULL THEN
        po_data := util.result_error('membership:invalid', 'actor, tenantId and roleId are required');
        RETURN;
    END IF;

    v_list := pi_data->'permissions';
    IF jsonb_typeof(v_list) IS DISTINCT FROM 'array'
       OR EXISTS (SELECT 1 FROM jsonb_array_elements(v_list) e WHERE jsonb_typeof(e) <> 'string') THEN
        po_data := util.result_error('membership:invalid', 'permissions must be a list of permission names');
        RETURN;
    END IF;

    SELECT * INTO v_row
      FROM rolebyte.tenant_role
     WHERE id = v_role AND tenant_id = v_tenant
       FOR UPDATE;
    IF NOT FOUND THEN
        po_data := util.result_error('membership:not_found', 'role does not exist');
        RETURN;
    END IF;

    -- Every name must be a declared permission. A name that is not even shaped
    -- like one is not repeated back: the caller wrote it, and this text reaches logs.
    FOR v_perm IN SELECT DISTINCT e FROM jsonb_array_elements_text(v_list) AS e ORDER BY e LOOP
        SELECT * INTO v_parts FROM rolebyte.permission_name_parts(v_perm);
        IF v_parts.service IS NULL THEN
            po_data := util.result_error('membership:unknown_permission', 'an entry is not a permission name');
            RETURN;
        END IF;
        v_base := v_parts.service || '/' || v_parts.feature || ':' || v_parts.act;

        SELECT id, class, plane, retired_at IS NOT NULL INTO v_pid, v_class, v_plane, v_retired
          FROM rolebyte.service_permission
         WHERE service_key = v_parts.service AND feature_key = v_parts.feature AND act = v_parts.act;
        IF v_pid IS NULL THEN
            po_data := util.result_error('membership:unknown_permission',
                format('%s is not a declared permission', v_base));
            RETURN;
        END IF;
        -- A box a position in the chart carries is on no other list.
        IF v_plane = 'chart' THEN
            po_data := util.result_error('membership:invalid',
                format('%s is held by a position in the chart of authority; no role carries it', v_base));
            RETURN;
        END IF;
        -- A per-field family is ticked one field at a time. The bare family is
        -- every field of its kind, the administrators' alone, as below.
        IF v_class = 'perField' AND v_parts.param IS NULL THEN
            po_data := util.result_error('membership:invalid',
                format('%s is every field of its kind; only the Administrator checkbox holds it, and a role holds one field of it', v_perm));
            RETURN;
        END IF;
        IF v_class <> 'perField' AND v_parts.param IS NOT NULL THEN
            po_data := util.result_error('membership:invalid',
                format('%s is not a per-field family, so it names no field', v_base));
            RETURN;
        END IF;
        -- A permission that changes the tenant's own setup, or who may do what,
        -- is held only by the tenant's administrators. No role carries one, so
        -- nobody can hand out a role that grants more than they were given.
        IF v_class NOT IN ('ordinary', 'perField') THEN
            po_data := util.result_error('membership:invalid',
                format('%s changes the tenant''s own setup; only the Administrator checkbox holds it', v_perm));
            RETURN;
        END IF;
        -- A retired permission keeps working for a role that already ticks it,
        -- and no role can be given it again.
        IF v_retired AND NOT EXISTS (SELECT 1 FROM rolebyte.tenant_role_permission t
                                      WHERE t.tenant_role_id = v_row.id AND t.permission_id = v_pid
                                        AND t.param IS NOT DISTINCT FROM v_parts.param) THEN
            po_data := util.result_error('membership:invalid',
                format('%s is retired: a role that holds it keeps it, and no role can be given it again', v_perm));
            RETURN;
        END IF;
        v_ids    := array_append(v_ids, v_pid);
        v_params := array_append(v_params, v_parts.param);
    END LOOP;

    SELECT COALESCE(jsonb_agg(sp.service_key || '/' || sp.feature_key || ':' || sp.act || COALESCE('@' || x.param, '')
                              ORDER BY sp.service_key, sp.feature_key, sp.act, x.param NULLS FIRST), '[]'::jsonb)
      INTO v_added
      FROM unnest(v_ids, v_params) AS x(pid, param)
      JOIN rolebyte.service_permission sp ON sp.id = x.pid
     WHERE NOT EXISTS (SELECT 1 FROM rolebyte.tenant_role_permission t
                       WHERE t.tenant_role_id = v_row.id AND t.permission_id = x.pid
                         AND t.param IS NOT DISTINCT FROM x.param);

    SELECT COALESCE(jsonb_agg(sp.service_key || '/' || sp.feature_key || ':' || sp.act || COALESCE('@' || t.param, '')
                              ORDER BY sp.service_key, sp.feature_key, sp.act, t.param NULLS FIRST), '[]'::jsonb)
      INTO v_removed
      FROM rolebyte.tenant_role_permission t
      JOIN rolebyte.service_permission sp ON sp.id = t.permission_id
     WHERE t.tenant_role_id = v_row.id
       AND NOT EXISTS (SELECT 1 FROM unnest(v_ids, v_params) AS x(pid, param)
                        WHERE x.pid = t.permission_id AND x.param IS NOT DISTINCT FROM t.param);

    IF v_added = '[]'::jsonb AND v_removed = '[]'::jsonb THEN
        po_data := util.result_success(jsonb_build_object(
            'id',          v_row.id,
            'permissions', rolebyte.tenant_role_permission_names(v_row.id),
            'added',       v_added,
            'removed',     v_removed,
            'changed',     false
        ));
        RETURN;
    END IF;

    DELETE FROM rolebyte.tenant_role_permission t
     WHERE t.tenant_role_id = v_row.id
       AND NOT EXISTS (SELECT 1 FROM unnest(v_ids, v_params) AS x(pid, param)
                        WHERE x.pid = t.permission_id AND x.param IS NOT DISTINCT FROM t.param);

    INSERT INTO rolebyte.tenant_role_permission (tenant_role_id, permission_id, param)
    SELECT v_row.id, x.pid, x.param FROM unnest(v_ids, v_params) AS x(pid, param)
    ON CONFLICT DO NOTHING;

    INSERT INTO rolebyte.event (id, actor, tenant_id, kind, payload)
    VALUES (util.generate_ulid(), v_actor, v_tenant, 'tenantRoleReconfigured',
            jsonb_build_object('roleId', v_row.id, 'name', v_row.name,
                               'added', v_added, 'removed', v_removed));

    po_data := util.result_success(jsonb_build_object(
        'id',          v_row.id,
        'permissions', rolebyte.tenant_role_permission_names(v_row.id),
        'added',       v_added,
        'removed',     v_removed,
        'changed',     true
    ));
EXCEPTION
    WHEN sqlstate 'P0001' THEN
        RAISE;
    WHEN OTHERS THEN
        RAISE EXCEPTION '%', util.result_error('membership:error', sqlerrm) USING errcode = 'P0001';
END;
$$;

REVOKE ALL ON PROCEDURE rolebyte.tenant_role_permissions_set(jsonb, jsonb) FROM PUBLIC;
GRANT EXECUTE ON PROCEDURE rolebyte.tenant_role_permissions_set(jsonb, jsonb) TO rolebyte_public;

-- field_permission_roles_set — which of the tenant's roles hold one field of a
-- per-field family, as one whole set: every role named is given it, every other
-- role of the tenant loses it. It serves the screen where a field is
-- restricted, which asks which roles see it, so a role's other ticks are never
-- read or rewritten. The whole call is checked before anything is written: a
-- name that is not one field of a declared family, or an id that is not one of
-- the tenant's roles, refuses it and changes nothing. A retired family keeps the
-- roles that hold a field of it, and no other role can be given one. The same
-- set again changes nothing and records nothing; each role whose ticks change
-- records `tenantRoleReconfigured`, as when its whole set is written.
CREATE OR REPLACE PROCEDURE rolebyte.field_permission_roles_set(IN pi_data jsonb, INOUT po_data jsonb)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = rolebyte, util, pg_temp
AS $$
DECLARE
    v_actor   text;
    v_tenant  text;
    v_name    text;
    v_list    jsonb;
    v_parts   record;
    v_base    text;
    v_pid     text;
    v_class   text;
    v_retired boolean;
    v_want    text[];
    v_role    record;
    v_holds   boolean;
    v_changed boolean := false;
    v_held    jsonb;
BEGIN
    v_actor  := NULLIF(trim(pi_data->>'actor'), '');
    v_tenant := NULLIF(trim(pi_data->>'tenantId'), '');
    IF v_actor IS NULL OR v_tenant IS NULL THEN
        po_data := util.result_error('membership:invalid', 'actor and tenantId are required');
        RETURN;
    END IF;

    IF jsonb_typeof(pi_data->'permission') IS DISTINCT FROM 'string' THEN
        po_data := util.result_error('membership:invalid', 'permission is required');
        RETURN;
    END IF;
    v_name := pi_data->>'permission';

    v_list := pi_data->'roleIds';
    IF jsonb_typeof(v_list) IS DISTINCT FROM 'array'
       OR EXISTS (SELECT 1 FROM jsonb_array_elements(v_list) e WHERE jsonb_typeof(e) <> 'string') THEN
        po_data := util.result_error('membership:invalid', 'roleIds must be a list of role ids');
        RETURN;
    END IF;
    v_want := ARRAY(SELECT DISTINCT e FROM jsonb_array_elements_text(v_list) AS e);

    IF NOT EXISTS (SELECT 1 FROM rolebyte.tenant WHERE id = v_tenant) THEN
        po_data := util.result_error('tenant:not_found', 'tenant does not exist');
        RETURN;
    END IF;

    -- Not repeated back unless shaped like a name: the caller wrote it, and this
    -- text reaches logs.
    SELECT * INTO v_parts FROM rolebyte.permission_name_parts(v_name);
    IF v_parts.service IS NULL OR v_parts.param IS NULL THEN
        po_data := util.result_error('membership:unknown_permission',
            'the permission is not one field of a per-field family');
        RETURN;
    END IF;
    v_base := v_parts.service || '/' || v_parts.feature || ':' || v_parts.act;

    SELECT id, class, retired_at IS NOT NULL INTO v_pid, v_class, v_retired
      FROM rolebyte.service_permission
     WHERE service_key = v_parts.service AND feature_key = v_parts.feature AND act = v_parts.act;
    IF v_pid IS NULL THEN
        po_data := util.result_error('membership:unknown_permission',
            format('%s is not a declared permission', v_base));
        RETURN;
    END IF;
    IF v_class <> 'perField' THEN
        po_data := util.result_error('membership:invalid',
            format('%s is not a per-field family, so it names no field', v_base));
        RETURN;
    END IF;

    -- The tenant's roles are locked in one order, so two calls on the same tenant
    -- queue rather than deadlock, and a role deleted in flight is waited for.
    PERFORM 1 FROM rolebyte.tenant_role r
     WHERE r.tenant_id = v_tenant
     ORDER BY r.id COLLATE "C"
       FOR UPDATE;

    IF EXISTS (SELECT 1 FROM unnest(v_want) AS w(id)
                WHERE NOT EXISTS (SELECT 1 FROM rolebyte.tenant_role r
                                   WHERE r.id = w.id AND r.tenant_id = v_tenant)) THEN
        po_data := util.result_error('membership:unknown_role', 'no such role');
        RETURN;
    END IF;

    IF v_retired AND EXISTS (SELECT 1 FROM unnest(v_want) AS w(id)
                              WHERE NOT EXISTS (SELECT 1 FROM rolebyte.tenant_role_permission t
                                                 WHERE t.tenant_role_id = w.id AND t.permission_id = v_pid
                                                   AND t.param = v_parts.param)) THEN
        po_data := util.result_error('membership:invalid',
            format('%s is retired: a role that holds it keeps it, and no role can be given it again', v_name));
        RETURN;
    END IF;

    FOR v_role IN SELECT r.id, r.name FROM rolebyte.tenant_role r
                   WHERE r.tenant_id = v_tenant ORDER BY r.id COLLATE "C" LOOP
        v_holds := EXISTS (SELECT 1 FROM rolebyte.tenant_role_permission t
                            WHERE t.tenant_role_id = v_role.id AND t.permission_id = v_pid
                              AND t.param = v_parts.param);
        IF v_role.id = ANY (v_want) AND NOT v_holds THEN
            INSERT INTO rolebyte.tenant_role_permission (tenant_role_id, permission_id, param)
            VALUES (v_role.id, v_pid, v_parts.param);
            INSERT INTO rolebyte.event (id, actor, tenant_id, kind, payload)
            VALUES (util.generate_ulid(), v_actor, v_tenant, 'tenantRoleReconfigured',
                    jsonb_build_object('roleId', v_role.id, 'name', v_role.name,
                                       'added', jsonb_build_array(v_name), 'removed', '[]'::jsonb));
            v_changed := true;
        ELSIF NOT (v_role.id = ANY (v_want)) AND v_holds THEN
            DELETE FROM rolebyte.tenant_role_permission t
             WHERE t.tenant_role_id = v_role.id AND t.permission_id = v_pid AND t.param = v_parts.param;
            INSERT INTO rolebyte.event (id, actor, tenant_id, kind, payload)
            VALUES (util.generate_ulid(), v_actor, v_tenant, 'tenantRoleReconfigured',
                    jsonb_build_object('roleId', v_role.id, 'name', v_role.name,
                                       'added', '[]'::jsonb, 'removed', jsonb_build_array(v_name)));
            v_changed := true;
        END IF;
    END LOOP;

    SELECT COALESCE(jsonb_agg(t.tenant_role_id ORDER BY t.tenant_role_id COLLATE "C"), '[]'::jsonb)
      INTO v_held
      FROM rolebyte.tenant_role_permission t
      JOIN rolebyte.tenant_role r ON r.id = t.tenant_role_id
     WHERE r.tenant_id = v_tenant AND t.permission_id = v_pid AND t.param = v_parts.param;

    po_data := util.result_success(jsonb_build_object(
        'permission', v_name,
        'roleIds',    v_held,
        'changed',    v_changed
    ));
EXCEPTION
    WHEN sqlstate 'P0001' THEN
        RAISE;
    WHEN OTHERS THEN
        RAISE EXCEPTION '%', util.result_error('membership:error', sqlerrm) USING errcode = 'P0001';
END;
$$;

REVOKE ALL ON PROCEDURE rolebyte.field_permission_roles_set(jsonb, jsonb) FROM PUBLIC;
GRANT EXECUTE ON PROCEDURE rolebyte.field_permission_roles_set(jsonb, jsonb) TO rolebyte_public;

-- tenant_role_delete — remove a role nobody holds. A role the tenant was opened
-- with (one with a seed) is never deleted, only renamed or reticked. A role held by any member
-- whose access has not been revoked, or placed by a member service on its own
-- objects, is refused with the counts: deleting it would take access away from
-- people with no way back. The role's ticks and its
-- ended grants go with it; the history keeps all of them. Emits
-- `tenantRoleDeleted` carrying what the role held.
CREATE OR REPLACE PROCEDURE rolebyte.tenant_role_delete(IN pi_data jsonb, INOUT po_data jsonb)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = rolebyte, util, pg_temp
AS $$
DECLARE
    v_actor  text;
    v_tenant text;
    v_role   text;
    v_row    rolebyte.tenant_role%ROWTYPE;
    v_held   int;
    v_placed bigint;
    v_by     text;
    v_perms  jsonb;
BEGIN
    v_actor  := NULLIF(trim(pi_data->>'actor'), '');
    v_tenant := NULLIF(trim(pi_data->>'tenantId'), '');
    v_role   := NULLIF(trim(pi_data->>'roleId'), '');
    IF v_actor IS NULL OR v_tenant IS NULL OR v_role IS NULL THEN
        po_data := util.result_error('membership:invalid', 'actor, tenantId and roleId are required');
        RETURN;
    END IF;

    -- The lock also holds off a grant of this role, and a report of it placed,
    -- until the delete has decided.
    SELECT * INTO v_row
      FROM rolebyte.tenant_role
     WHERE id = v_role AND tenant_id = v_tenant
       FOR UPDATE;
    IF NOT FOUND THEN
        po_data := util.result_error('membership:not_found', 'role does not exist');
        RETURN;
    END IF;
    -- A role the tenant was opened with stays: services pick their defaults by
    -- it, such as the role a newcomer or a project's creator receives. It may be
    -- renamed and its ticks changed.
    IF v_row.seed <> '' THEN
        po_data := util.result_error('membership:conflict',
            'this role came with the workspace and is not deleted; rename it or change what it holds');
        RETURN;
    END IF;

    SELECT count(*) INTO v_held
      FROM rolebyte.tenant_role_assignment a
      JOIN rolebyte.user_account u ON u.id = a.user_id
     WHERE a.tenant_role_id = v_row.id
       AND a.state = 'granted'
       AND u.status <> 'revoked';

    -- Placed elsewhere counts as in use, as long as the service that placed it
    -- is still a member here; a retired service's count no longer holds a role.
    SELECT COALESCE(sum(p.placements), 0),
           string_agg(DISTINCT u.display_name, ', ' ORDER BY u.display_name)
      INTO v_placed, v_by
      FROM rolebyte.tenant_role_placement p
      JOIN rolebyte.user_account u ON u.id = p.reporter_id
     WHERE p.tenant_role_id = v_row.id
       AND u.status = 'active';

    IF v_held > 0 AND v_placed > 0 THEN
        po_data := util.result_error('membership:conflict',
            format('this role is held by %s %s and placed %s %s by %s; revoke it and move those placements first',
                   v_held, CASE WHEN v_held = 1 THEN 'person' ELSE 'people' END,
                   v_placed, CASE WHEN v_placed = 1 THEN 'time' ELSE 'times' END, v_by));
        RETURN;
    ELSIF v_held > 0 THEN
        po_data := util.result_error('membership:conflict',
            format('this role is held by %s %s; revoke it from them first',
                   v_held, CASE WHEN v_held = 1 THEN 'person' ELSE 'people' END));
        RETURN;
    ELSIF v_placed > 0 THEN
        po_data := util.result_error('membership:conflict',
            format('this role is placed %s %s by %s; move those placements to another role first',
                   v_placed, CASE WHEN v_placed = 1 THEN 'time' ELSE 'times' END, v_by));
        RETURN;
    END IF;

    v_perms := rolebyte.tenant_role_permission_names(v_row.id);

    -- What is left is a retired service's count, which goes with the role.
    DELETE FROM rolebyte.tenant_role_placement WHERE tenant_role_id = v_row.id;
    DELETE FROM rolebyte.tenant_role_assignment WHERE tenant_role_id = v_row.id;
    DELETE FROM rolebyte.tenant_role_permission WHERE tenant_role_id = v_row.id;
    DELETE FROM rolebyte.tenant_role WHERE id = v_row.id;

    INSERT INTO rolebyte.event (id, actor, tenant_id, kind, payload)
    VALUES (util.generate_ulid(), v_actor, v_tenant, 'tenantRoleDeleted',
            jsonb_build_object('roleId', v_row.id, 'name', v_row.name, 'permissions', v_perms));

    po_data := util.result_success(jsonb_build_object('deleted', true));
EXCEPTION
    WHEN sqlstate 'P0001' THEN
        RAISE;
    WHEN OTHERS THEN
        RAISE EXCEPTION '%', util.result_error('membership:error', sqlerrm) USING errcode = 'P0001';
END;
$$;

REVOKE ALL ON PROCEDURE rolebyte.tenant_role_delete(jsonb, jsonb) FROM PUBLIC;
GRANT EXECUTE ON PROCEDURE rolebyte.tenant_role_delete(jsonb, jsonb) TO rolebyte_public;

-- tenant_role_grant — give a member of the tenant one of the tenant's roles, by
-- the role's id. Re-granting a revoked role flips it back; granting one already
-- held changes nothing. A role that is not this tenant's is unknown, exactly
-- like one that never existed. Emits `tenantRoleGranted`.
CREATE OR REPLACE PROCEDURE rolebyte.tenant_role_grant(IN pi_data jsonb, INOUT po_data jsonb)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = rolebyte, util, pg_temp
AS $$
DECLARE
    v_actor   text;
    v_tenant  text;
    v_user_id text;
    v_role    text;
    v_row     rolebyte.tenant_role%ROWTYPE;
    v_changed boolean := false;
BEGIN
    v_actor   := NULLIF(trim(pi_data->>'actor'), '');
    v_tenant  := NULLIF(trim(pi_data->>'tenantId'), '');
    v_user_id := NULLIF(trim(pi_data->>'userId'), '');
    v_role    := NULLIF(trim(pi_data->>'roleId'), '');
    IF v_actor IS NULL OR v_tenant IS NULL OR v_user_id IS NULL OR v_role IS NULL THEN
        po_data := util.result_error('membership:invalid', 'actor, tenantId, userId and roleId are required');
        RETURN;
    END IF;

    -- Tenant-scoped user lookup: a foreign tenant's user answers not_found.
    IF NOT EXISTS (SELECT 1 FROM rolebyte.user_account
                   WHERE id = v_user_id AND tenant_id = v_tenant AND status <> 'revoked') THEN
        po_data := util.result_error('membership:not_found', 'user does not exist');
        RETURN;
    END IF;

    -- A delete of this role in flight holds it; once that commits, the role is
    -- simply not found here.
    SELECT * INTO v_row
      FROM rolebyte.tenant_role
     WHERE id = v_role AND tenant_id = v_tenant
       FOR KEY SHARE;
    IF NOT FOUND THEN
        po_data := util.result_error('membership:unknown_role', 'no such role');
        RETURN;
    END IF;

    INSERT INTO rolebyte.tenant_role_assignment (id, tenant_id, user_id, tenant_role_id)
    VALUES (util.generate_ulid(), v_tenant, v_user_id, v_row.id)
    ON CONFLICT (user_id, tenant_role_id)
        DO UPDATE SET state = 'granted', granted_at = now(), revoked_at = NULL
        WHERE rolebyte.tenant_role_assignment.state = 'revoked';
    v_changed := FOUND;

    IF v_changed THEN
        INSERT INTO rolebyte.event (id, actor, tenant_id, user_id, kind, payload)
        VALUES (util.generate_ulid(), v_actor, v_tenant, v_user_id, 'tenantRoleGranted',
                jsonb_build_object('roleId', v_row.id, 'name', v_row.name));
    END IF;

    po_data := util.result_success(jsonb_build_object('changed', v_changed));
EXCEPTION
    WHEN sqlstate 'P0001' THEN
        RAISE;
    WHEN OTHERS THEN
        RAISE EXCEPTION '%', util.result_error('membership:error', sqlerrm) USING errcode = 'P0001';
END;
$$;

REVOKE ALL ON PROCEDURE rolebyte.tenant_role_grant(jsonb, jsonb) FROM PUBLIC;
GRANT EXECUTE ON PROCEDURE rolebyte.tenant_role_grant(jsonb, jsonb) TO rolebyte_public;

-- tenant_role_revoke — take one of the tenant's roles back from a member, by
-- the role's id. Revoking a role the member does not hold changes nothing.
-- Emits `tenantRoleRevoked`.
CREATE OR REPLACE PROCEDURE rolebyte.tenant_role_revoke(IN pi_data jsonb, INOUT po_data jsonb)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = rolebyte, util, pg_temp
AS $$
DECLARE
    v_actor   text;
    v_tenant  text;
    v_user_id text;
    v_role    text;
    v_row     rolebyte.tenant_role%ROWTYPE;
    v_changed boolean := false;
BEGIN
    v_actor   := NULLIF(trim(pi_data->>'actor'), '');
    v_tenant  := NULLIF(trim(pi_data->>'tenantId'), '');
    v_user_id := NULLIF(trim(pi_data->>'userId'), '');
    v_role    := NULLIF(trim(pi_data->>'roleId'), '');
    IF v_actor IS NULL OR v_tenant IS NULL OR v_user_id IS NULL OR v_role IS NULL THEN
        po_data := util.result_error('membership:invalid', 'actor, tenantId, userId and roleId are required');
        RETURN;
    END IF;

    IF NOT EXISTS (SELECT 1 FROM rolebyte.user_account
                   WHERE id = v_user_id AND tenant_id = v_tenant) THEN
        po_data := util.result_error('membership:not_found', 'user does not exist');
        RETURN;
    END IF;

    SELECT * INTO v_row
      FROM rolebyte.tenant_role
     WHERE id = v_role AND tenant_id = v_tenant;
    IF NOT FOUND THEN
        po_data := util.result_error('membership:unknown_role', 'no such role');
        RETURN;
    END IF;

    UPDATE rolebyte.tenant_role_assignment
       SET state = 'revoked', revoked_at = now()
     WHERE user_id = v_user_id AND tenant_role_id = v_row.id AND state = 'granted';
    v_changed := FOUND;

    IF v_changed THEN
        INSERT INTO rolebyte.event (id, actor, tenant_id, user_id, kind, payload)
        VALUES (util.generate_ulid(), v_actor, v_tenant, v_user_id, 'tenantRoleRevoked',
                jsonb_build_object('roleId', v_row.id, 'name', v_row.name));
    END IF;

    po_data := util.result_success(jsonb_build_object('changed', v_changed));
EXCEPTION
    WHEN sqlstate 'P0001' THEN
        RAISE;
    WHEN OTHERS THEN
        RAISE EXCEPTION '%', util.result_error('membership:error', sqlerrm) USING errcode = 'P0001';
END;
$$;

REVOKE ALL ON PROCEDURE rolebyte.tenant_role_revoke(jsonb, jsonb) FROM PUBLIC;
GRANT EXECUTE ON PROCEDURE rolebyte.tenant_role_revoke(jsonb, jsonb) TO rolebyte_public;

-- ---------------------------------------------------------------------------
-- Placement elsewhere. A service that owns its own objects places the tenant's
-- roles on them and keeps those placements itself. It copies what each role
-- carries, so that checking a person on one of its objects is a local read, and
-- asks again to learn of a change. In return it reports how many placements of
-- each role it holds, so a role in use is not deleted from under its people.
-- ---------------------------------------------------------------------------

-- tenant_role_definitions — the tenant's roles as a service that places them
-- needs them: each role's id, its name and description, its names in the app's
-- other languages (`labels`), and the permissions it carries in this tenant. Those are its ticks narrowed to what the tenant has, the same filter
-- resolve applies to a person granted the role across the tenant, so a role
-- placed on one object never carries more than the same role granted everywhere.
-- For the same reason a tick of a permission that changes the tenant's own setup,
-- stored before a role could no longer carry one, is left out.
-- One field of a per-field family travels here, and only here, as
-- `<family>@<key>.<generation>`: resolve never puts it on a token, so the
-- services that place roles learn it from this copy.
-- Roles in id order, permissions in byte order, so the same state always reads
-- the same whatever the database's collation. Names no person.
CREATE OR REPLACE PROCEDURE rolebyte.tenant_role_definitions(IN pi_data jsonb, INOUT po_data jsonb)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = rolebyte, util, pg_temp
AS $$
DECLARE
    v_tenant text;
    v_roles  jsonb;
BEGIN
    v_tenant := NULLIF(trim(pi_data->>'tenantId'), '');
    IF v_tenant IS NULL THEN
        po_data := util.result_error('membership:invalid', 'tenantId is required');
        RETURN;
    END IF;

    IF NOT EXISTS (SELECT 1 FROM rolebyte.tenant WHERE id = v_tenant) THEN
        po_data := util.result_error('tenant:not_found', 'tenant does not exist');
        RETURN;
    END IF;

    SELECT COALESCE(jsonb_agg(jsonb_build_object(
               'id',          r.id,
               'seed',        r.seed,
               'name',        r.name,
               'labels',      r.labels,
               'description', r.description,
               'permissions', COALESCE((
                   SELECT jsonb_agg(p.name ORDER BY p.name COLLATE "C")
                     FROM (
                         SELECT sp.service_key || '/' || sp.feature_key || ':' || sp.act
                                || COALESCE('@' || tp.param, '') AS name
                           FROM rolebyte.tenant_role_permission tp
                           JOIN rolebyte.service_permission sp ON sp.id = tp.permission_id
                          WHERE tp.tenant_role_id = r.id
                            AND ((sp.class = 'ordinary' AND tp.param IS NULL)
                                 OR (sp.class = 'perField' AND tp.param IS NOT NULL))
                            AND EXISTS (
                                SELECT 1 FROM rolebyte.tenant_entitlement e
                                 WHERE e.tenant_id = r.tenant_id
                                   AND e.service_key = sp.service_key
                                   AND e.state = 'entitled'
                                   AND (e.feature_key = ''
                                        OR sp.feature_key = e.feature_key
                                        OR starts_with(sp.feature_key, e.feature_key || '/')))
                     ) p
               ), '[]'::jsonb)
           ) ORDER BY r.id COLLATE "C"), '[]'::jsonb)
      INTO v_roles
      FROM rolebyte.tenant_role r
     WHERE r.tenant_id = v_tenant;

    po_data := util.result_success(jsonb_build_object('tenantId', v_tenant, 'roles', v_roles));
EXCEPTION
    WHEN sqlstate 'P0001' THEN
        RAISE;
    WHEN OTHERS THEN
        RAISE EXCEPTION '%', util.result_error('membership:error', sqlerrm) USING errcode = 'P0001';
END;
$$;

REVOKE ALL ON PROCEDURE rolebyte.tenant_role_definitions(jsonb, jsonb) FROM PUBLIC;
GRANT EXECUTE ON PROCEDURE rolebyte.tenant_role_definitions(jsonb, jsonb) TO rolebyte_public;

-- tenant_role_placements_set — a service reports how many times it has placed
-- each of the tenant's roles, as one whole set that replaces its last report; a
-- role left out counts zero. The reporter is the service's own member row in the
-- tenant, which the caller takes from the verified token and never from what the
-- service sent. Every count is checked before anything is written.
--
-- An id that is not one of this tenant's roles is never stored. It is answered
-- back under `unknown`, which is how a service learns that it placed a role
-- deleted a moment before. The roles named are locked against a delete until the
-- report commits, so a report and a delete of the same role never both win: the
-- one that goes second sees the other.
CREATE OR REPLACE PROCEDURE rolebyte.tenant_role_placements_set(IN pi_data jsonb, INOUT po_data jsonb)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = rolebyte, util, pg_temp
AS $$
DECLARE
    v_tenant   text;
    v_reporter text;
    v_set      jsonb;
    v_entry    record;
    v_known    text[];
    v_unknown  jsonb;
BEGIN
    v_tenant   := NULLIF(trim(pi_data->>'tenantId'), '');
    v_reporter := NULLIF(trim(pi_data->>'reporterId'), '');
    v_set      := pi_data->'placements';
    IF v_tenant IS NULL OR v_reporter IS NULL THEN
        po_data := util.result_error('membership:invalid', 'tenantId and reporterId are required');
        RETURN;
    END IF;
    IF v_set IS NULL OR jsonb_typeof(v_set) <> 'object' THEN
        po_data := util.result_error('membership:invalid', 'placements must map role ids to counts');
        RETURN;
    END IF;

    FOR v_entry IN SELECT key, value FROM jsonb_each(v_set) LOOP
        IF jsonb_typeof(v_entry.value) <> 'number'
           OR (v_entry.value #>> '{}')::numeric < 0
           OR (v_entry.value #>> '{}')::numeric <> trunc((v_entry.value #>> '{}')::numeric)
           OR (v_entry.value #>> '{}')::numeric > 2147483647 THEN
            po_data := util.result_error('membership:invalid',
                format('the count for %s must be a whole number, zero or more', left(v_entry.key, 64)));
            RETURN;
        END IF;
    END LOOP;

    -- The second layer under the caller's own check: only an active member of
    -- this tenant reports for it.
    IF NOT EXISTS (SELECT 1 FROM rolebyte.user_account u
                    WHERE u.id = v_reporter AND u.tenant_id = v_tenant AND u.status = 'active') THEN
        po_data := util.result_error('membership:notMember', 'the reporter is not a member of this tenant');
        RETURN;
    END IF;

    SELECT COALESCE(array_agg(r.id), '{}')
      INTO v_known
      FROM (SELECT r.id
              FROM rolebyte.tenant_role r
             WHERE r.tenant_id = v_tenant
               AND r.id IN (SELECT jsonb_object_keys(v_set))
               FOR KEY SHARE) r;

    SELECT COALESCE(jsonb_agg(k ORDER BY k COLLATE "C"), '[]'::jsonb)
      INTO v_unknown
      FROM jsonb_object_keys(v_set) k
     WHERE k <> ALL (v_known);

    DELETE FROM rolebyte.tenant_role_placement
     WHERE tenant_id = v_tenant AND reporter_id = v_reporter;

    INSERT INTO rolebyte.tenant_role_placement (tenant_id, tenant_role_id, reporter_id, placements)
    SELECT v_tenant, e.key, v_reporter, (e.value #>> '{}')::integer
      FROM jsonb_each(v_set) e
     WHERE e.key = ANY (v_known)
       AND (e.value #>> '{}')::integer > 0;

    po_data := util.result_success(jsonb_build_object('unknown', v_unknown));
EXCEPTION
    WHEN sqlstate 'P0001' THEN
        RAISE;
    WHEN OTHERS THEN
        RAISE EXCEPTION '%', util.result_error('membership:error', sqlerrm) USING errcode = 'P0001';
END;
$$;

REVOKE ALL ON PROCEDURE rolebyte.tenant_role_placements_set(jsonb, jsonb) FROM PUBLIC;
GRANT EXECUTE ON PROCEDURE rolebyte.tenant_role_placements_set(jsonb, jsonb) TO rolebyte_public;

-- ---------------------------------------------------------------------------
-- Configuration transport. The section `rolebyte-config/1` carries the
-- deployment's list of services, with their role definitions and the
-- permissions they declare, so an export says what the tenant's configuration
-- was made against. An import never writes that list: it is the deployment's,
-- shared by every tenant on it, and only whoever runs the deployment adds to it.
-- Each entry of a document is reported `unchanged` where the list already says
-- the same, and `skipped` where it does not, naming why. The workspace's own
-- name and corporate login never travel: an export leaves them out, and an
-- import never changes them, whatever a file holds. People and their
-- assignments never travel at all.
--
-- The section's version is a hash of the section's own bytes, salted with the
-- tenant, computed when asked; nothing stores it and no writer maintains it, so
-- no writer can leave it lying. An apply names the version its preview
-- answered, and is refused when the section has moved since.
--
-- A preview and an apply are one pass: the document is compared item by item
-- through the same registering procedures every other caller uses, and the
-- pass is always undone again, so what the list already holds is read exactly
-- as a registration would read it. The two cannot disagree about a document,
-- because they are the same run.
-- ---------------------------------------------------------------------------

-- config_section — the tenant's section as it travels; NULL for no such
-- tenant. A pure function of the configuration — keys, never identifiers; no
-- timestamps; every list in one stable order — so the same configuration always
-- renders the same bytes.
CREATE OR REPLACE FUNCTION rolebyte.config_section(p_tenant text) RETURNS jsonb
LANGUAGE sql
STABLE
SET search_path = rolebyte, pg_temp
AS $$
    SELECT jsonb_build_object(
        'schema', 'rolebyte-config/1',
        'services', COALESCE((
            SELECT jsonb_agg(jsonb_build_object(
                       'key',         s.key,
                       'displayName', s.display_name,
                       'roles', COALESCE((
                           SELECT jsonb_agg(jsonb_build_object(
                                      'group',       d.role_group,
                                      'level',       d.role_level,
                                      'description', d.description)
                                      ORDER BY d.role_group COLLATE "C", d.role_level COLLATE "C")
                             FROM rolebyte.role_definition d
                            WHERE d.service_key = s.key), '[]'::jsonb),
                       -- The roles a new tenant starts with holding a permission
                       -- travel with it, so a document read back writes nothing.
                       'permissions', COALESCE((
                           SELECT jsonb_agg(jsonb_build_object(
                                      'feature',     p.feature_key,
                                      'act',         p.act,
                                      'description', p.description,
                                      'class',       p.class,
                                      'plane',       p.plane,
                                      'labels',      p.labels,
                                      'retired',     p.retired_at IS NOT NULL)
                                      || CASE WHEN cardinality(p.seeds) > 0
                                              THEN jsonb_build_object('seeds', to_jsonb(p.seeds))
                                              ELSE '{}'::jsonb END
                                      ORDER BY p.feature_key COLLATE "C", p.act COLLATE "C")
                             FROM rolebyte.service_permission p
                            WHERE p.service_key = s.key), '[]'::jsonb))
                   ORDER BY s.key COLLATE "C")
              FROM rolebyte.service s), '[]'::jsonb))
      FROM rolebyte.tenant t
     WHERE t.id = p_tenant;
$$;

REVOKE ALL ON FUNCTION rolebyte.config_section(text) FROM PUBLIC;

-- config_get — the section as it travels and the version computed from exactly
-- those bytes, from one snapshot.
CREATE OR REPLACE PROCEDURE rolebyte.config_get(IN pi_data jsonb, INOUT po_data jsonb)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = rolebyte, util, pg_temp
AS $$
DECLARE
    v_tenant  text := NULLIF(trim(pi_data->>'tenantId'), '');
    v_section jsonb;
BEGIN
    IF v_tenant IS NULL THEN
        po_data := util.result_error('membership:invalid', 'tenantId is required');
        RETURN;
    END IF;

    v_section := rolebyte.config_section(v_tenant);
    IF v_section IS NULL THEN
        po_data := util.result_error('membership:not_found', 'no such tenant');
        RETURN;
    END IF;

    po_data := util.result_success(jsonb_build_object(
        'section', v_section,
        'version', util.config_token('rolebyte-config/1', v_tenant, v_section)));
EXCEPTION
    WHEN sqlstate 'P0001' THEN RAISE;
    WHEN OTHERS THEN
        RAISE EXCEPTION '%', util.result_error('membership:error', sqlerrm) USING errcode = 'P0001';
END;
$$;

REVOKE ALL ON PROCEDURE rolebyte.config_get(jsonb, jsonb) FROM PUBLIC;
GRANT EXECUTE ON PROCEDURE rolebyte.config_get(jsonb, jsonb) TO rolebyte_public;

-- config_version — the version alone.
CREATE OR REPLACE PROCEDURE rolebyte.config_version(IN pi_data jsonb, INOUT po_data jsonb)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = rolebyte, util, pg_temp
AS $$
DECLARE
    v_tenant  text := NULLIF(trim(pi_data->>'tenantId'), '');
    v_section jsonb;
BEGIN
    IF v_tenant IS NULL THEN
        po_data := util.result_error('membership:invalid', 'tenantId is required');
        RETURN;
    END IF;

    v_section := rolebyte.config_section(v_tenant);
    IF v_section IS NULL THEN
        po_data := util.result_error('membership:not_found', 'no such tenant');
        RETURN;
    END IF;

    po_data := util.result_success(jsonb_build_object(
        'version', util.config_token('rolebyte-config/1', v_tenant, v_section)));
EXCEPTION
    WHEN sqlstate 'P0001' THEN RAISE;
    WHEN OTHERS THEN
        RAISE EXCEPTION '%', util.result_error('membership:error', sqlerrm) USING errcode = 'P0001';
END;
$$;

REVOKE ALL ON PROCEDURE rolebyte.config_version(jsonb, jsonb) FROM PUBLIC;
GRANT EXECUTE ON PROCEDURE rolebyte.config_version(jsonb, jsonb) TO rolebyte_public;

-- config_item — one line of a report: the item by key, what happened to it,
-- and for a refusal the reason and why, for a change the members that change.
CREATE OR REPLACE FUNCTION rolebyte.config_item(
    p_key text, p_status text, p_reason text DEFAULT NULL, p_detail text DEFAULT NULL) RETURNS jsonb
LANGUAGE sql
IMMUTABLE
SET search_path = pg_temp
AS $$
    SELECT jsonb_build_object('key', COALESCE(p_key, ''), 'status', p_status)
        || jsonb_strip_nulls(jsonb_build_object('reason', p_reason, 'detail', NULLIF(p_detail, '')));
$$;

REVOKE ALL ON FUNCTION rolebyte.config_item(text, text, text, text) FROM PUBLIC;

-- config_vocabulary — define what a document's services list names, item by
-- item: each service, its role definitions and its permissions, through the
-- registering procedures every other caller uses, so the events land
-- identically. A refused entry is a line of the report, never an error, and
-- the caller decides whether anything stands. Nothing is ever removed.
CREATE OR REPLACE FUNCTION rolebyte.config_vocabulary(p_actor text, p_services jsonb) RETURNS jsonb
LANGUAGE plpgsql
SET search_path = rolebyte, util, pg_temp
AS $$
DECLARE
    v_svc      jsonb;
    v_role     jsonb;
    v_perm     jsonb;
    v_out      jsonb;
    v_key      text;
    v_name     text;
    v_services jsonb := '[]'::jsonb;
    v_roles    jsonb := '[]'::jsonb;
    v_perms    jsonb := '[]'::jsonb;
BEGIN
    FOR v_svc IN SELECT * FROM jsonb_array_elements(COALESCE(p_services, '[]'::jsonb)) LOOP
        v_key := CASE WHEN jsonb_typeof(v_svc->'key') = 'string' THEN NULLIF(trim(v_svc->>'key'), '') END;
        IF jsonb_typeof(v_svc) IS DISTINCT FROM 'object' OR v_key IS NULL THEN
            v_services := v_services || rolebyte.config_item('', 'refused', 'config_bad_document',
                'a service entry is missing its key');
            CONTINUE;
        END IF;
        IF (v_svc ? 'roles' AND jsonb_typeof(v_svc->'roles') IS DISTINCT FROM 'array')
           OR (v_svc ? 'permissions' AND jsonb_typeof(v_svc->'permissions') IS DISTINCT FROM 'array') THEN
            v_services := v_services || rolebyte.config_item(v_key, 'refused', 'config_bad_document',
                format('the roles and the permissions of service %s are lists', v_key));
            CONTINUE;
        END IF;

        v_out := NULL;
        CALL rolebyte.service_register(jsonb_build_object(
            'actor',       p_actor,
            'service',     v_key,
            'displayName', v_svc->>'displayName'), v_out);
        IF v_out->>'result' IS DISTINCT FROM 'success' THEN
            v_services := v_services || rolebyte.config_item(v_key, 'refused', 'config_bad_document', v_out->>'message');
            CONTINUE;
        END IF;
        v_services := v_services || rolebyte.config_item(v_key,
            CASE WHEN (v_out->'data'->>'created')::boolean THEN 'added' ELSE 'unchanged' END);

        FOR v_role IN SELECT * FROM jsonb_array_elements(COALESCE(v_svc->'roles', '[]'::jsonb)) LOOP
            v_name := CASE WHEN NULLIF(trim(v_role->>'group'), '') IS NOT NULL AND NULLIF(trim(v_role->>'level'), '') IS NOT NULL
                           THEN v_key || ' ' || trim(v_role->>'group') || ':' || trim(v_role->>'level')
                           ELSE v_key END;
            v_out := NULL;
            CALL rolebyte.role_define(jsonb_build_object(
                'actor',       p_actor,
                'service',     v_key,
                'group',       v_role->>'group',
                'level',       v_role->>'level',
                'description', v_role->>'description'), v_out);
            IF v_out->>'result' IS DISTINCT FROM 'success' THEN
                v_roles := v_roles || rolebyte.config_item(v_name, 'refused', 'config_bad_document', v_out->>'message');
            ELSE
                v_roles := v_roles || rolebyte.config_item(v_name,
                    CASE WHEN (v_out->'data'->>'created')::boolean THEN 'added' ELSE 'unchanged' END);
            END IF;
        END LOOP;

        FOR v_perm IN SELECT * FROM jsonb_array_elements(COALESCE(v_svc->'permissions', '[]'::jsonb)) LOOP
            v_name := CASE WHEN jsonb_typeof(v_perm->'feature') = 'string' AND jsonb_typeof(v_perm->'act') = 'string'
                           THEN v_key || '/' || (v_perm->>'feature') || ':' || (v_perm->>'act')
                           ELSE v_key END;
            v_out := NULL;
            CALL rolebyte.permission_declare(jsonb_build_object(
                'actor',      p_actor,
                'service',    v_key,
                'permission', v_perm), v_out);
            IF v_out->>'result' IS DISTINCT FROM 'success' THEN
                -- A class or a plane that is not the one declared is a key that
                -- already means something else; anything else is a malformed entry.
                v_perms := v_perms || rolebyte.config_item(v_name, 'refused',
                    CASE WHEN v_out->>'code' = 'membership:conflict' THEN 'config_key_conflict' ELSE 'config_bad_document' END,
                    v_out->>'message');
            ELSE
                v_perms := v_perms || rolebyte.config_item(v_out->'data'->>'permission', v_out->'data'->>'status', NULL,
                    (SELECT string_agg(c, ', ') FROM jsonb_array_elements_text(COALESCE(v_out->'data'->'changes', '[]'::jsonb)) c));
            END IF;
        END LOOP;
    END LOOP;

    RETURN jsonb_build_object('services', v_services, 'roles', v_roles, 'permissions', v_perms);
END;
$$;

REVOKE ALL ON FUNCTION rolebyte.config_vocabulary(text, jsonb) FROM PUBLIC;

-- config_apply — preview or apply one section. `dryRun` answers the report and
-- writes nothing. An apply writes one thing, the `configApplied` line in the
-- tenant's history, naming the counts, the part's hash and the document it
-- arrived in: the list of services is the deployment's, so every entry is
-- compared and none is written — `unchanged` where the list already says the
-- same, `skipped` where it does not (`config_deployment_owned`). An entry that
-- cannot be read is `refused` (`config_bad_document`), and a document with one
-- writes nothing at all. A file that still names the workspace's name or its
-- corporate login gets a `workspace` list saying neither is taken
-- (`config_workspace_owned`).
CREATE OR REPLACE PROCEDURE rolebyte.config_apply(IN pi_data jsonb, INOUT po_data jsonb)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = rolebyte, util, pg_temp
AS $$
DECLARE
    v_tenant    text := NULLIF(trim(pi_data->>'tenantId'), '');
    v_actor     text := NULLIF(trim(pi_data->>'actor'), '');
    v_section   jsonb := pi_data->'section';
    v_expected  text := NULLIF(trim(pi_data->>'expectedVersion'), '');
    v_part_hash text := NULLIF(trim(pi_data->>'partHash'), '');
    v_document  text := NULLIF(trim(pi_data->>'documentHash'), '');
    v_dry       boolean;
    v_pass      jsonb;
    v_report    jsonb := '{}'::jsonb;
    v_items     jsonb;
    v_item      jsonb;
    v_workspace jsonb := '[]'::jsonb;
    v_part      text;
    v_refused   boolean := false;
    v_counts    jsonb := '{}'::jsonb;
BEGIN
    IF v_tenant IS NULL OR v_actor IS NULL THEN
        po_data := util.result_error('membership:invalid', 'tenantId and actor are required');
        RETURN;
    END IF;
    IF pi_data ? 'dryRun' AND jsonb_typeof(pi_data->'dryRun') NOT IN ('boolean', 'null')
       AND NOT (jsonb_typeof(pi_data->'dryRun') = 'string' AND (pi_data->>'dryRun') IN ('true', 'false')) THEN
        po_data := util.result_error('membership:invalid', 'dryRun is on or off');
        RETURN;
    END IF;
    v_dry := COALESCE((pi_data->>'dryRun')::boolean, false);
    IF v_section IS NULL OR jsonb_typeof(v_section) <> 'object' THEN
        po_data := util.result_error('membership:config_bad_document', 'the section must be an object');
        RETURN;
    END IF;
    IF v_section->>'schema' IS DISTINCT FROM 'rolebyte-config/1' THEN
        po_data := util.result_error('membership:config_bad_document',
            'the section is not rolebyte-config/1' ||
            CASE WHEN v_section ? 'schema' THEN ' (it says ' || COALESCE(v_section->>'schema', 'null') || ')' ELSE '' END);
        RETURN;
    END IF;
    -- The part's hash and the document's, as the service hands them over, are
    -- recorded on the import's line; one out of shape is refused, never stored.
    IF (v_part_hash IS NOT NULL AND v_part_hash !~ '^sha256:[0-9a-f]{64}$')
       OR (v_document IS NOT NULL AND v_document !~ '^sha256:[0-9a-f]{64}$') THEN
        po_data := util.result_error('membership:config_bad_document',
            'a part hash and a document hash are sha256: and 64 lower-case hex digits');
        RETURN;
    END IF;
    IF v_section ? 'services' AND jsonb_typeof(v_section->'services') IS DISTINCT FROM 'array' THEN
        po_data := util.result_error('membership:config_bad_document', 'services must be a list');
        RETURN;
    END IF;

    IF NOT EXISTS (SELECT 1 FROM rolebyte.tenant WHERE id = v_tenant) THEN
        po_data := util.result_error('membership:not_found', 'no such tenant');
        RETURN;
    END IF;

    -- A writing apply names the version its preview answered: without it,
    -- nothing says the document is being applied to the configuration the
    -- person looked at. The list is shared by every tenant and the deployment
    -- may be registering a service at this moment, so the version is compared
    -- under the lock the registration takes.
    IF NOT v_dry THEN
        IF v_expected IS NULL THEN
            po_data := util.result_error('membership:config_version_required',
                'an apply names the configuration version its preview answered; preview the document first');
            RETURN;
        END IF;
        PERFORM pg_advisory_xact_lock(hashtextextended('rolebyte.config', 0));
        IF util.config_token('rolebyte-config/1', v_tenant, rolebyte.config_section(v_tenant))
                IS DISTINCT FROM v_expected THEN
            po_data := util.result_error('membership:config_version_moved',
                'the configuration changed after the document was previewed; preview it again');
            RETURN;
        END IF;
    END IF;

    -- The pass: each entry run through the registering procedures, which say
    -- what a registration would do, and then always undone. What it found
    -- stands.
    BEGIN
        v_pass := rolebyte.config_vocabulary(v_actor, v_section->'services');
        RAISE EXCEPTION 'rolebyte.config_apply: the pass is undone' USING ERRCODE = 'RB001';
    EXCEPTION
        WHEN sqlstate 'RB001' THEN
            NULL;
    END;

    -- An entry the list already holds as the document says is unchanged. One
    -- it does not hold, or holds otherwise, is skipped: only the deployment
    -- changes its list. One that cannot be read is refused.
    FOREACH v_part IN ARRAY ARRAY['services', 'roles', 'permissions'] LOOP
        v_items := '[]'::jsonb;
        FOR v_item IN SELECT * FROM jsonb_array_elements(COALESCE(v_pass->v_part, '[]'::jsonb)) LOOP
            v_items := v_items || CASE
                WHEN v_item->>'status' = 'unchanged' THEN v_item
                WHEN v_item->>'status' = 'added' THEN rolebyte.config_item(v_item->>'key', 'skipped',
                    'config_deployment_owned',
                    'not on this deployment''s list; only whoever runs the deployment adds to it')
                WHEN v_item->>'status' = 'changed' THEN rolebyte.config_item(v_item->>'key', 'skipped',
                    'config_deployment_owned',
                    'this deployment''s list says otherwise (' || COALESCE(v_item->>'detail', '') ||
                    '); only whoever runs the deployment changes it')
                WHEN v_item->>'reason' = 'config_key_conflict' THEN rolebyte.config_item(v_item->>'key', 'skipped',
                    'config_deployment_owned',
                    'this deployment''s list holds it otherwise (' || COALESCE(v_item->>'detail', '') ||
                    '); only whoever runs the deployment changes it')
                ELSE v_item
            END;
        END LOOP;
        v_report := v_report || jsonb_build_object(v_part, v_items);
        v_refused := v_refused OR EXISTS (
            SELECT 1 FROM jsonb_array_elements(v_items) e WHERE e->>'status' = 'refused');
    END LOOP;

    -- The workspace's name and corporate login are its own. A file that still
    -- names them is told so, item by item; nothing is read from it.
    IF jsonb_typeof(v_section->'tenant') = 'object' THEN
        IF jsonb_typeof(v_section->'tenant'->'displayName') = 'string'
           AND NULLIF(trim(v_section->'tenant'->>'displayName'), '') IS NOT NULL THEN
            v_workspace := v_workspace || rolebyte.config_item('displayName', 'skipped', 'config_workspace_owned',
                'a workspace keeps its own name; a file never changes it');
        END IF;
        IF jsonb_typeof(v_section->'tenant'->'directory') = 'object'
           AND NULLIF(trim(v_section->'tenant'->'directory'->>'issuer'), '') IS NOT NULL THEN
            v_workspace := v_workspace || rolebyte.config_item('directory', 'skipped', 'config_workspace_owned',
                'a workspace keeps its own corporate login; a file never changes it');
        END IF;
    END IF;
    IF jsonb_array_length(v_workspace) > 0 THEN
        v_report := v_report || jsonb_build_object('workspace', v_workspace);
    END IF;

    IF NOT v_dry AND NOT v_refused THEN
        FOREACH v_part IN ARRAY ARRAY['services', 'roles', 'permissions'] LOOP
            v_counts := v_counts || jsonb_build_object(v_part, jsonb_build_object(
                'added',     0,
                'changed',   0,
                'unchanged', (SELECT count(*) FROM jsonb_array_elements(v_report->v_part) e WHERE e->>'status' = 'unchanged'),
                'skipped',   (SELECT count(*) FROM jsonb_array_elements(v_report->v_part) e WHERE e->>'status' = 'skipped'),
                'refused',   0));
        END LOOP;
        INSERT INTO rolebyte.event (id, actor, tenant_id, kind, payload)
        VALUES (util.generate_ulid(), v_actor, v_tenant, 'configApplied',
                v_counts || jsonb_strip_nulls(jsonb_build_object('partHash', v_part_hash, 'documentHash', v_document)));
    END IF;

    po_data := util.result_success(v_report || jsonb_build_object(
        'schema',  'rolebyte-config/1',
        'dryRun',  v_dry,
        'applied', NOT v_dry AND NOT v_refused,
        'refused', v_refused,
        'version', util.config_token('rolebyte-config/1', v_tenant, rolebyte.config_section(v_tenant))));
EXCEPTION
    WHEN sqlstate 'P0001' THEN
        RAISE;
    WHEN OTHERS THEN
        RAISE EXCEPTION '%', util.result_error('membership:error', sqlerrm) USING errcode = 'P0001';
END;
$$;

REVOKE ALL ON PROCEDURE rolebyte.config_apply(jsonb, jsonb) FROM PUBLIC;
GRANT EXECUTE ON PROCEDURE rolebyte.config_apply(jsonb, jsonb) TO rolebyte_public;

-- config_exported — record that the section was taken out as part of an
-- export: who took it, and the hash of the part they received, so the history
-- names the file. The service writes it before it answers the read, so an
-- export is never made unrecorded.
CREATE OR REPLACE PROCEDURE rolebyte.config_exported(IN pi_data jsonb, INOUT po_data jsonb)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = rolebyte, util, pg_temp
AS $$
DECLARE
    v_tenant    text := NULLIF(trim(pi_data->>'tenantId'), '');
    v_actor     text := NULLIF(trim(pi_data->>'actor'), '');
    v_part_hash text := NULLIF(trim(pi_data->>'partHash'), '');
BEGIN
    IF v_tenant IS NULL OR v_actor IS NULL THEN
        po_data := util.result_error('membership:invalid', 'tenantId and actor are required');
        RETURN;
    END IF;
    IF v_part_hash IS NULL OR v_part_hash !~ '^sha256:[0-9a-f]{64}$' THEN
        po_data := util.result_error('membership:invalid', 'partHash is sha256: and 64 lower-case hex digits');
        RETURN;
    END IF;
    IF NOT EXISTS (SELECT 1 FROM rolebyte.tenant WHERE id = v_tenant) THEN
        po_data := util.result_error('membership:not_found', 'no such tenant');
        RETURN;
    END IF;

    INSERT INTO rolebyte.event (id, actor, tenant_id, kind, payload)
    VALUES (util.generate_ulid(), v_actor, v_tenant, 'configExported',
            jsonb_build_object('partHash', v_part_hash));
    po_data := util.result_success(jsonb_build_object('recorded', true));
EXCEPTION
    WHEN sqlstate 'P0001' THEN RAISE;
    WHEN OTHERS THEN
        RAISE EXCEPTION '%', util.result_error('membership:error', sqlerrm) USING errcode = 'P0001';
END;
$$;

REVOKE ALL ON PROCEDURE rolebyte.config_exported(jsonb, jsonb) FROM PUBLIC;
GRANT EXECUTE ON PROCEDURE rolebyte.config_exported(jsonb, jsonb) TO rolebyte_public;

-- tenant_get — what a workspace is, for any of its members: its name, and the
-- products it has (each entitlement in force: a whole service as an empty
-- feature, or one feature of it), in a stable order. Who may ask is the
-- service's check — a member of this tenant — as for the list of its people;
-- nothing here is a secret from them.
CREATE OR REPLACE PROCEDURE rolebyte.tenant_get(IN pi_data jsonb, INOUT po_data jsonb)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = rolebyte, util, pg_temp
AS $$
DECLARE
    v_tenant text := NULLIF(trim(pi_data->>'tenantId'), '');
    v_name   text;
BEGIN
    IF v_tenant IS NULL THEN
        po_data := util.result_error('membership:invalid', 'tenantId is required');
        RETURN;
    END IF;
    SELECT name INTO v_name FROM rolebyte.tenant WHERE id = v_tenant;
    IF NOT FOUND THEN
        po_data := util.result_error('membership:not_found', 'no such tenant');
        RETURN;
    END IF;

    po_data := util.result_success(jsonb_build_object(
        'id',   v_tenant,
        'name', v_name,
        'entitlements', COALESCE((
            SELECT jsonb_agg(jsonb_build_object('service', e.service_key, 'feature', e.feature_key)
                             ORDER BY e.service_key COLLATE "C", e.feature_key COLLATE "C")
              FROM rolebyte.tenant_entitlement e
             WHERE e.tenant_id = v_tenant AND e.state = 'entitled'), '[]'::jsonb)));
EXCEPTION
    WHEN sqlstate 'P0001' THEN
        RAISE;
    WHEN OTHERS THEN
        RAISE EXCEPTION '%', util.result_error('membership:error', sqlerrm) USING errcode = 'P0001';
END;
$$;

REVOKE ALL ON PROCEDURE rolebyte.tenant_get(jsonb, jsonb) FROM PUBLIC;
GRANT EXECUTE ON PROCEDURE rolebyte.tenant_get(jsonb, jsonb) TO rolebyte_public;

-- permissions_register — the deployment registers what each service enforces:
-- the services' permission lists, as each service prints them, added to the
-- vocabulary every tenant shares. It is the deployment's act, not a person's
-- import, so it names no tenant, needs no version and writes no line in any
-- tenant's history. Additive and idempotent: a second run reports every
-- permission unchanged. One refused entry writes nothing, and the error names
-- it. Granted to nobody: the deployment calls it as the location's owner. A
-- service's own declaration is a different act, rolebyte.service_declare below.
CREATE OR REPLACE PROCEDURE rolebyte.permissions_register(IN pi_data jsonb, INOUT po_data jsonb)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = rolebyte, util, pg_temp
AS $$
DECLARE
    v_actor   text := NULLIF(trim(pi_data->>'actor'), '');
    v_section jsonb := pi_data->'section';
    v_report  jsonb;
    v_line    jsonb;
BEGIN
    IF v_actor IS NULL THEN
        po_data := util.result_error('membership:invalid', 'actor is required');
        RETURN;
    END IF;
    IF jsonb_typeof(v_section) IS DISTINCT FROM 'object'
       OR jsonb_typeof(v_section->'services') IS DISTINCT FROM 'array' THEN
        po_data := util.result_error('membership:config_bad_document', 'the section is an object carrying a services list');
        RETURN;
    END IF;

    PERFORM pg_advisory_xact_lock(hashtextextended('rolebyte.config', 0));
    v_report := rolebyte.config_vocabulary(v_actor, v_section->'services');

    SELECT e INTO v_line
      FROM jsonb_array_elements((v_report->'services') || (v_report->'roles') || (v_report->'permissions')) e
     WHERE e->>'status' = 'refused'
     LIMIT 1;
    IF v_line IS NOT NULL THEN
        RAISE EXCEPTION '%', util.result_error('membership:' || (v_line->>'reason'),
            COALESCE(NULLIF(v_line->>'key', ''), 'an entry') || ': ' || COALESCE(v_line->>'detail', 'refused'))
            USING errcode = 'P0001';
    END IF;

    po_data := util.result_success(v_report);
EXCEPTION
    WHEN sqlstate 'P0001' THEN
        RAISE;
    WHEN OTHERS THEN
        RAISE EXCEPTION '%', util.result_error('membership:error', sqlerrm) USING errcode = 'P0001';
END;
$$;

REVOKE ALL ON PROCEDURE rolebyte.permissions_register(jsonb, jsonb) FROM PUBLIC;

-- service_declare — a service declares itself: its key, its levels and the
-- permissions it enforces, in the document shape permissions_register reads,
-- written through the same vocabulary function under the same lock, so every
-- line reads and every event lands as it does there. The caller is a backend
-- service acting as itself: `actor` is its service subject (`svc:<client id>`),
-- and `allowed` is the list of service keys the caller was granted outside this
-- procedure; a key in the document that is not in it is refused, before
-- anything is written. The document is read strictly: a member this register
-- does not know, in the section, a service entry or a role entry, refuses it.
-- Every shape and limit is judged before anything is written: a service key, a
-- group and a level are each one lower-case word, texts have a length limit,
-- and a group belongs to one service key. The checks that read nothing from the
-- register's tables come first; the lock every registration shares is then
-- taken, and the checks against what is already registered (a group's service
-- key) are made under it, so two declarations made at once cannot both pass
-- them. Every refusal is returned before any write. All or nothing: one refused line raises and nothing of the document stands,
-- and the answer names the line. Nothing is inferred from an absence: a
-- permission a later document leaves out stays as it was; it is retired by its
-- own `retired` mark. The one write besides the vocabulary is a row per
-- service key and declaring client (service_declaration) holding when it was
-- first and last declared; that write makes no history event.
--
-- This is deliberately granted to the register's own role: it is the one
-- registration a service's own request may reach. Every other act that writes
-- the deployment's list stays the deployment's own.
CREATE OR REPLACE PROCEDURE rolebyte.service_declare(IN pi_data jsonb, INOUT po_data jsonb)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = rolebyte, util, pg_temp
AS $$
DECLARE
    v_actor   text := NULLIF(trim(pi_data->>'actor'), '');
    v_allowed jsonb := pi_data->'allowed';
    v_section jsonb := pi_data->'section';
    v_member  text;
    v_svc     jsonb;
    v_role    jsonb;
    v_key     text;
    v_report  jsonb;
    v_line    jsonb;
    v_perm    jsonb;
    v_groups  jsonb := '{}'::jsonb;
    v_group   text;
    v_prev    text;
    -- A name that is a service key, a group or a level: one lower-case word.
    c_word    constant text := '^[a-z][a-z0-9-]{0,63}$';
BEGIN
    IF v_actor IS NULL OR left(v_actor, 4) <> 'svc:' OR length(v_actor) = 4 THEN
        po_data := util.result_error('membership:invalid', 'actor is a service subject, svc:<client id>');
        RETURN;
    END IF;
    IF jsonb_typeof(v_allowed) IS DISTINCT FROM 'array'
       OR EXISTS (SELECT 1 FROM jsonb_array_elements(v_allowed) a WHERE jsonb_typeof(a) IS DISTINCT FROM 'string') THEN
        po_data := util.result_error('membership:invalid', 'allowed is a list of service keys');
        RETURN;
    END IF;
    IF jsonb_typeof(v_section) IS DISTINCT FROM 'object'
       OR jsonb_typeof(v_section->'services') IS DISTINCT FROM 'array' THEN
        po_data := util.result_error('membership:config_bad_document', 'the section is an object carrying a services list');
        RETURN;
    END IF;

    -- Strict reading: only the members this register knows.
    SELECT k INTO v_member FROM jsonb_object_keys(v_section) k WHERE k <> 'services' LIMIT 1;
    IF v_member IS NOT NULL THEN
        po_data := util.result_error('membership:config_bad_document',
            format('the document carries a member this register does not know: %s', left(v_member, 100)));
        RETURN;
    END IF;

    -- What one call may cost: at most 50 services and 256 KiB of document.
    IF jsonb_array_length(v_section->'services') > 50 THEN
        po_data := util.result_error('membership:config_bad_document', 'a document declares at most 50 services');
        RETURN;
    END IF;
    IF octet_length(v_section::text) > 262144 THEN
        po_data := util.result_error('membership:config_bad_document', 'a document is at most 262144 bytes');
        RETURN;
    END IF;

    -- Every check above reads nothing from the register's tables, so a malformed
    -- or oversized document never waits for the lock. Every check below does, and
    -- is made with the lock held: two declarations made at the same moment take
    -- the lock one after the other, so the second sees what the first wrote and
    -- both cannot pass a check against what is already registered. The lock every
    -- registration shares is waited for at most five seconds, so a registration
    -- stuck behind another does not hold a connection for ever; the caller is told
    -- to try again (below). The setting is this transaction's only, and the
    -- transaction's earlier value is put back once the lock is held.
    v_prev := current_setting('lock_timeout');
    PERFORM set_config('lock_timeout', '5s', true);
    PERFORM pg_advisory_xact_lock(hashtextextended('rolebyte.config', 0));
    PERFORM set_config('lock_timeout', v_prev, true);

    FOR v_svc IN SELECT * FROM jsonb_array_elements(v_section->'services') LOOP
        IF jsonb_typeof(v_svc) IS DISTINCT FROM 'object' THEN
            po_data := util.result_error('membership:config_bad_document', 'a service entry is an object');
            RETURN;
        END IF;
        SELECT k INTO v_member FROM jsonb_object_keys(v_svc) k
         WHERE k NOT IN ('key', 'displayName', 'roles', 'permissions') LIMIT 1;
        IF v_member IS NOT NULL THEN
            po_data := util.result_error('membership:config_bad_document',
                format('a service entry carries a member this register does not know: %s', left(v_member, 100)));
            RETURN;
        END IF;
        IF jsonb_typeof(v_svc->'key') IS DISTINCT FROM 'string' OR NULLIF(trim(v_svc->>'key'), '') IS NULL THEN
            po_data := util.result_error('membership:config_bad_document', 'a service entry is missing its key');
            RETURN;
        END IF;
        -- A key that is not a key by shape is never repeated in the answer.
        IF v_svc->>'key' !~ c_word THEN
            po_data := util.result_error('membership:config_bad_document',
                'a service entry has a key that is not a lower-case word of letters, digits and hyphens, at most 64 characters long');
            RETURN;
        END IF;
        v_key := v_svc->>'key';
        -- The service key `deployment` is the register's own: a permission under it
        -- would read as a scope of the group of the same name.
        IF v_key = 'deployment' THEN
            po_data := util.result_error('membership:config_key_conflict',
                'the service key deployment is the register''s own and is not a service');
            RETURN;
        END IF;
        IF v_svc ? 'displayName' AND jsonb_typeof(v_svc->'displayName') NOT IN ('string', 'null') THEN
            po_data := util.result_error('membership:config_bad_document',
                format('the display name of service %s is text', v_key));
            RETURN;
        END IF;
        IF jsonb_typeof(v_svc->'displayName') = 'string' AND char_length(v_svc->>'displayName') > 256 THEN
            po_data := util.result_error('membership:config_bad_document',
                format('the display name of service %s is at most 256 characters', v_key));
            RETURN;
        END IF;
        IF v_svc ? 'roles' AND jsonb_typeof(v_svc->'roles') IS DISTINCT FROM 'array' THEN
            po_data := util.result_error('membership:config_bad_document',
                format('the roles of service %s are a list', v_key));
            RETURN;
        END IF;
        IF v_svc ? 'permissions' AND jsonb_typeof(v_svc->'permissions') IS DISTINCT FROM 'array' THEN
            po_data := util.result_error('membership:config_bad_document',
                format('the permissions of service %s are a list', v_key));
            RETURN;
        END IF;
        IF jsonb_array_length(COALESCE(v_svc->'roles', '[]'::jsonb)) > 50 THEN
            po_data := util.result_error('membership:config_bad_document',
                format('service %s declares at most 50 roles', v_key));
            RETURN;
        END IF;
        IF jsonb_array_length(COALESCE(v_svc->'permissions', '[]'::jsonb)) > 500 THEN
            po_data := util.result_error('membership:config_bad_document',
                format('service %s declares at most 500 permissions', v_key));
            RETURN;
        END IF;

        FOR v_role IN SELECT * FROM jsonb_array_elements(COALESCE(v_svc->'roles', '[]'::jsonb)) LOOP
            IF jsonb_typeof(v_role) IS DISTINCT FROM 'object' THEN
                po_data := util.result_error('membership:config_bad_document',
                    format('a role of service %s is an object', v_key));
                RETURN;
            END IF;
            SELECT k INTO v_member FROM jsonb_object_keys(v_role) k
             WHERE k NOT IN ('group', 'level', 'description') LIMIT 1;
            IF v_member IS NOT NULL THEN
                po_data := util.result_error('membership:config_bad_document',
                    format('a role of service %s carries a member this register does not know: %s',
                           v_key, left(v_member, 100)));
                RETURN;
            END IF;
            -- A level is rendered into a token as group:level, and a token's scopes are
            -- separated by spaces: a level holding a space, a tab, a colon or a slash
            -- would put a second scope into the token of whoever holds it. So a group
            -- and a level are each one lower-case word, and are never echoed.
            IF jsonb_typeof(v_role->'group') IS DISTINCT FROM 'string' OR v_role->>'group' !~ c_word THEN
                po_data := util.result_error('membership:config_bad_document',
                    format('a role of service %s has a group that is not a lower-case word of letters, digits and hyphens, at most 64 characters long', v_key));
                RETURN;
            END IF;
            IF jsonb_typeof(v_role->'level') IS DISTINCT FROM 'string' OR v_role->>'level' !~ c_word THEN
                po_data := util.result_error('membership:config_bad_document',
                    format('a role of service %s has a level that is not a lower-case word of letters, digits and hyphens, at most 64 characters long', v_key));
                RETURN;
            END IF;
            IF v_role ? 'description' AND jsonb_typeof(v_role->'description') NOT IN ('string', 'null') THEN
                po_data := util.result_error('membership:config_bad_document',
                    format('a role of service %s has a description that is not text', v_key));
                RETURN;
            END IF;
            IF jsonb_typeof(v_role->'description') = 'string' AND char_length(v_role->>'description') > 256 THEN
                po_data := util.result_error('membership:config_bad_document',
                    format('a role of service %s has a description of more than 256 characters', v_key));
                RETURN;
            END IF;

            -- A level reaches a token without its service key, and who administers a
            -- tenant is decided by the group and the level alone, so a group must mean
            -- one service's ladder: it is the register's own for `membership`
            -- (declarable only under the key `rolebyte`) and for `deployment` (under
            -- no key), and otherwise belongs to the first service that defined it.
            v_group := v_role->>'group';
            -- The group `deployment` is the register's own, under any service key.
            IF v_group = 'deployment' THEN
                po_data := util.result_error('membership:config_key_conflict',
                    format('service %s may not declare group deployment: the group is the register''s own and not a level anything may define', v_key));
                RETURN;
            END IF;
            IF (v_group = 'membership' AND v_key <> 'rolebyte')
               OR EXISTS (SELECT 1 FROM rolebyte.role_definition rd WHERE rd.role_group = v_group AND rd.service_key <> v_key)
               OR (v_groups ? v_group AND v_groups->>v_group <> v_key) THEN
                po_data := util.result_error('membership:config_key_conflict',
                    format('service %s may not declare group %s: a group belongs to one service', v_key, v_group));
                RETURN;
            END IF;
            v_groups := v_groups || jsonb_build_object(v_group, v_key);
        END LOOP;

        FOR v_perm IN SELECT * FROM jsonb_array_elements(COALESCE(v_svc->'permissions', '[]'::jsonb)) LOOP
            IF jsonb_typeof(v_perm) = 'object' THEN
                IF jsonb_typeof(v_perm->'description') = 'string' AND char_length(v_perm->>'description') > 256 THEN
                    po_data := util.result_error('membership:config_bad_document',
                        format('a permission of service %s has a description of more than 256 characters', v_key));
                    RETURN;
                END IF;
                IF jsonb_typeof(v_perm->'labels') = 'object'
                   AND EXISTS (SELECT 1 FROM jsonb_each(v_perm->'labels') l
                                WHERE jsonb_typeof(l.value) = 'string' AND char_length(l.value #>> '{}') > 256) THEN
                    po_data := util.result_error('membership:config_bad_document',
                        format('a permission of service %s has a label of more than 256 characters', v_key));
                    RETURN;
                END IF;
            END IF;
        END LOOP;
    END LOOP;

    -- Only the keys the caller was granted, checked before anything is written.
    SELECT trim(s->>'key') INTO v_key
      FROM jsonb_array_elements(v_section->'services') s
     WHERE NOT (v_allowed @> to_jsonb(trim(s->>'key')))
     LIMIT 1;
    IF v_key IS NOT NULL THEN
        po_data := util.result_error('membership:forbidden',
            format('the caller may not declare service %s', left(v_key, 100)));
        RETURN;
    END IF;

    v_report := rolebyte.config_vocabulary(v_actor, v_section->'services');

    SELECT e INTO v_line
      FROM jsonb_array_elements((v_report->'services') || (v_report->'roles') || (v_report->'permissions')) e
     WHERE e->>'status' = 'refused'
     LIMIT 1;
    IF v_line IS NOT NULL THEN
        RAISE EXCEPTION '%', util.result_error('membership:' || (v_line->>'reason'),
            COALESCE(NULLIF(v_line->>'key', ''), 'an entry') || ': ' || COALESCE(v_line->>'detail', 'refused'))
            USING errcode = 'P0001';
    END IF;

    INSERT INTO rolebyte.service_declaration (service_key, declared_by, first_declared_at, last_declared_at)
    SELECT DISTINCT trim(s->>'key'), v_actor, clock_timestamp(), clock_timestamp()
      FROM jsonb_array_elements(v_section->'services') s
    ON CONFLICT (service_key, declared_by) DO UPDATE SET last_declared_at = EXCLUDED.last_declared_at;

    po_data := util.result_success(v_report);
EXCEPTION
    WHEN sqlstate 'P0001' THEN
        RAISE;
    -- The lock (or a row another registration holds) was not had in time: an outage
    -- of the moment, not a decision about the document, so it is raised as an error
    -- the caller can tell apart from a refusal and try again.
    WHEN lock_not_available THEN
        RAISE EXCEPTION '%', util.result_error('membership:busy', 'the registration lock is busy, try again')
            USING errcode = 'P0001';
    WHEN OTHERS THEN
        RAISE EXCEPTION '%', util.result_error('membership:error', sqlerrm) USING errcode = 'P0001';
END;
$$;

REVOKE ALL ON PROCEDURE rolebyte.service_declare(jsonb, jsonb) FROM PUBLIC;
GRANT EXECUTE ON PROCEDURE rolebyte.service_declare(jsonb, jsonb) TO rolebyte_public;

-- ===========================================================================
-- The deployment's own company, and the people who administer the deployment.
--
-- One tenant is the company that runs the deployment (rolebyte.deployment, at
-- most one row). A short list (rolebyte.deployment_admin) names the people, each
-- as their account in that company, who administer the whole deployment. The
-- right is answered by `resolve` as the member `highScopes` of that company's
-- membership only, so a person removed from the company stops having it at the
-- next answer with no change to the list. The procedures below that write share
-- one lock, so two calls made at once cannot both mark a company, and `user_revoke`
-- takes the same lock before it touches an account, so the list and the accounts
-- are always locked in the same order.
-- ===========================================================================

-- The deployment's own company is marked in two ways. The register marks one by
-- itself only when there is no choice to make: exactly one company exists.
-- With several companies the choice belongs to whoever runs the deployment, who
-- makes it with `deployment_company_set`, which the register's own role is
-- refused.
--
-- deployment_company_mark (the register's own, at its start) — marks the only
-- company, and takes no tenant: an input carrying `tenantId` is refused
-- (`membership:invalid`). Never an error otherwise. Nothing is marked and no
-- company exists: {company: null, changed: false, companies: 0}. Exactly one
-- company exists and none is marked: it is marked, with one history line in it
-- (`deploymentCompanyMarked`), and the answer is {company: {id, name},
-- changed: true, companies: 1}. A company is already marked, however many exist:
-- the answer is that company, changed false. Several companies and none marked:
-- nothing is written, {company: null, changed: false, companies: n}.
CREATE OR REPLACE PROCEDURE rolebyte.deployment_company_mark(IN pi_data jsonb, INOUT po_data jsonb)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = rolebyte, util, pg_temp
AS $$
DECLARE
    v_actor   text := NULLIF(trim(pi_data->>'actor'), '');
    v_current text;
    v_only    text;
    v_count   integer;
    v_name    text;
BEGIN
    IF v_actor IS NULL THEN
        po_data := util.result_error('membership:invalid', 'actor is required');
        RETURN;
    END IF;
    IF pi_data ? 'tenantId' THEN
        po_data := util.result_error('membership:invalid', 'this act names no company');
        RETURN;
    END IF;

    PERFORM pg_advisory_xact_lock(hashtextextended('rolebyte.deployment', 0));

    -- One statement, so the number and the only company come from the same
    -- snapshot: a company opened a moment later cannot turn a count of one into a
    -- choice already made.
    SELECT count(*), min(id), min(name) INTO v_count, v_only, v_name FROM rolebyte.tenant;

    SELECT company_tenant_id INTO v_current FROM rolebyte.deployment;
    IF v_current IS NOT NULL THEN
        SELECT name INTO v_name FROM rolebyte.tenant WHERE id = v_current;
        po_data := util.result_success(jsonb_build_object(
            'company', jsonb_build_object('id', v_current, 'name', v_name),
            'changed', false,
            'companies', v_count));
        RETURN;
    END IF;

    -- No choice to make only when there is exactly one company; any other number
    -- leaves the deployment without a company of its own.
    IF v_count <> 1 THEN
        po_data := util.result_success(jsonb_build_object(
            'company', NULL,
            'changed', false,
            'companies', v_count));
        RETURN;
    END IF;

    INSERT INTO rolebyte.deployment (company_tenant_id) VALUES (v_only);
    INSERT INTO rolebyte.event (id, actor, tenant_id, kind, payload)
    VALUES (util.generate_ulid(), v_actor, v_only, 'deploymentCompanyMarked', '{}'::jsonb);

    po_data := util.result_success(jsonb_build_object(
        'company', jsonb_build_object('id', v_only, 'name', v_name),
        'changed', true,
        'companies', 1));
EXCEPTION
    WHEN sqlstate 'P0001' THEN
        RAISE;
    WHEN OTHERS THEN
        RAISE EXCEPTION '%', util.result_error('membership:error', sqlerrm) USING errcode = 'P0001';
END;
$$;

REVOKE ALL ON PROCEDURE rolebyte.deployment_company_mark(jsonb, jsonb) FROM PUBLIC;
GRANT EXECUTE ON PROCEDURE rolebyte.deployment_company_mark(jsonb, jsonb) TO rolebyte_public;

-- deployment_company_set — the deliberate act of whoever runs the deployment:
-- names the tenant `tenantId` (required) as the deployment's own company. Granted
-- to nobody: the deployment calls it as the location's owner, and the register's
-- own role is refused it, so no request a tenant can make chooses the company.
-- An unknown tenant is refused `membership:not_found`; with nothing marked the
-- tenant is marked, with one history line in it (`deploymentCompanyMarked`); the
-- tenant already marked changes nothing; a different one already marked is
-- refused `membership:conflict`. Answers {company: {id, name}, changed}.
CREATE OR REPLACE PROCEDURE rolebyte.deployment_company_set(IN pi_data jsonb, INOUT po_data jsonb)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = rolebyte, util, pg_temp
AS $$
DECLARE
    v_actor   text := NULLIF(trim(pi_data->>'actor'), '');
    v_tenant  text := NULLIF(trim(pi_data->>'tenantId'), '');
    v_current text;
    v_name    text;
BEGIN
    IF v_actor IS NULL OR v_tenant IS NULL THEN
        po_data := util.result_error('membership:invalid', 'actor and tenantId are required');
        RETURN;
    END IF;

    PERFORM pg_advisory_xact_lock(hashtextextended('rolebyte.deployment', 0));

    SELECT name INTO v_name FROM rolebyte.tenant WHERE id = v_tenant;
    IF NOT FOUND THEN
        po_data := util.result_error('membership:not_found', 'no such tenant');
        RETURN;
    END IF;

    SELECT company_tenant_id INTO v_current FROM rolebyte.deployment;
    IF v_current IS NOT NULL THEN
        IF v_current <> v_tenant THEN
            po_data := util.result_error('membership:conflict', 'the deployment already has a company of its own');
            RETURN;
        END IF;
        po_data := util.result_success(jsonb_build_object(
            'company', jsonb_build_object('id', v_tenant, 'name', v_name),
            'changed', false));
        RETURN;
    END IF;

    INSERT INTO rolebyte.deployment (company_tenant_id) VALUES (v_tenant);
    INSERT INTO rolebyte.event (id, actor, tenant_id, kind, payload)
    VALUES (util.generate_ulid(), v_actor, v_tenant, 'deploymentCompanyMarked', '{}'::jsonb);

    po_data := util.result_success(jsonb_build_object(
        'company', jsonb_build_object('id', v_tenant, 'name', v_name),
        'changed', true));
EXCEPTION
    WHEN sqlstate 'P0001' THEN
        RAISE;
    WHEN OTHERS THEN
        RAISE EXCEPTION '%', util.result_error('membership:error', sqlerrm) USING errcode = 'P0001';
END;
$$;

REVOKE ALL ON PROCEDURE rolebyte.deployment_company_set(jsonb, jsonb) FROM PUBLIC;
REVOKE EXECUTE ON PROCEDURE rolebyte.deployment_company_set(jsonb, jsonb) FROM rolebyte_public;

-- deployment_get — the deployment's own company, for a member of it: answers
-- {company: {id, name}} when `subjectKey` is a person's key (`sub:`) whose account
-- in that company is active and the company itself is active, as `resolve` answers
-- a membership; and {company: null} otherwise: no company marked, a suspended
-- company, a member of another company only, a service's key, an unknown or an
-- absent subject. Never an error for the subject; nothing here is a secret from a member.
CREATE OR REPLACE PROCEDURE rolebyte.deployment_get(IN pi_data jsonb, INOUT po_data jsonb)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = rolebyte, util, pg_temp
AS $$
DECLARE
    v_subject text := NULLIF(trim(pi_data->>'subjectKey'), '');
    v_company jsonb;
BEGIN
    IF v_subject IS NOT NULL AND left(v_subject, 4) = 'sub:' THEN
        SELECT jsonb_build_object('id', t.id, 'name', t.name) INTO v_company
          FROM rolebyte.deployment d
          JOIN rolebyte.tenant t ON t.id = d.company_tenant_id
          JOIN rolebyte.user_account u ON u.tenant_id = t.id
         WHERE u.subject_key = v_subject
           AND u.status = 'active'
           AND t.status = 'active';
    END IF;

    po_data := util.result_success(jsonb_build_object('company', v_company));
EXCEPTION
    WHEN sqlstate 'P0001' THEN
        RAISE;
    WHEN OTHERS THEN
        RAISE EXCEPTION '%', util.result_error('membership:error', sqlerrm) USING errcode = 'P0001';
END;
$$;

REVOKE ALL ON PROCEDURE rolebyte.deployment_get(jsonb, jsonb) FROM PUBLIC;
GRANT EXECUTE ON PROCEDURE rolebyte.deployment_get(jsonb, jsonb) TO rolebyte_public;

-- deployment_admin_add — makes a person's account in the deployment's own company
-- one of the deployment's administrators. `addedFrom` is `settings` or `screen`.
-- Refused before any write: no company marked (`membership:conflict`), an
-- `addedFrom` that is neither (`membership:invalid`), a subject that is not a
-- person's key, so never a service's account (`membership:invalid`), no account
-- of that subject in the deployment's own company, including a person who is a
-- member of other companies only (`membership:not_found`), and a revoked account
-- (`membership:conflict`). An invited account is accepted; the right is answered
-- once the account is active. An account already on the list changes nothing.
-- A new entry writes one history line in the company (`deploymentAdminAdded`).
-- Answers {userId, changed}.
CREATE OR REPLACE PROCEDURE rolebyte.deployment_admin_add(IN pi_data jsonb, INOUT po_data jsonb)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = rolebyte, util, pg_temp
AS $$
DECLARE
    v_actor   text := NULLIF(trim(pi_data->>'actor'), '');
    v_subject text := NULLIF(trim(pi_data->>'subjectKey'), '');
    v_from    text := NULLIF(trim(pi_data->>'addedFrom'), '');
    v_company text;
    v_user_id text;
    v_status  text;
BEGIN
    IF v_actor IS NULL THEN
        po_data := util.result_error('membership:invalid', 'actor is required');
        RETURN;
    END IF;

    PERFORM pg_advisory_xact_lock(hashtextextended('rolebyte.deployment', 0));

    SELECT company_tenant_id INTO v_company FROM rolebyte.deployment;
    IF v_company IS NULL THEN
        po_data := util.result_error('membership:conflict', 'the deployment has no company of its own yet');
        RETURN;
    END IF;
    IF v_from IS NULL OR v_from NOT IN ('settings', 'screen') THEN
        po_data := util.result_error('membership:invalid', 'addedFrom is settings or screen');
        RETURN;
    END IF;
    IF v_subject IS NULL OR left(v_subject, 4) <> 'sub:' OR length(v_subject) = 4 THEN
        po_data := util.result_error('membership:invalid', 'subjectKey is a person''s key, sub:<person id>');
        RETURN;
    END IF;

    SELECT id, status INTO v_user_id, v_status
      FROM rolebyte.user_account
     WHERE tenant_id = v_company AND subject_key = v_subject
       FOR SHARE;
    IF v_user_id IS NULL THEN
        po_data := util.result_error('membership:not_found', 'the person has no account in the deployment''s company');
        RETURN;
    END IF;
    IF v_status = 'revoked' THEN
        po_data := util.result_error('membership:conflict', 'the person''s account in the deployment''s company is revoked');
        RETURN;
    END IF;

    INSERT INTO rolebyte.deployment_admin (user_id, added_by, added_from)
    VALUES (v_user_id, v_actor, v_from)
    ON CONFLICT (user_id) DO NOTHING;
    IF NOT FOUND THEN
        po_data := util.result_success(jsonb_build_object('userId', v_user_id, 'changed', false));
        RETURN;
    END IF;

    INSERT INTO rolebyte.event (id, actor, tenant_id, user_id, kind, payload)
    VALUES (util.generate_ulid(), v_actor, v_company, v_user_id, 'deploymentAdminAdded',
            jsonb_build_object('addedFrom', v_from));

    po_data := util.result_success(jsonb_build_object('userId', v_user_id, 'changed', true));
EXCEPTION
    WHEN sqlstate 'P0001' THEN
        RAISE;
    WHEN OTHERS THEN
        RAISE EXCEPTION '%', util.result_error('membership:error', sqlerrm) USING errcode = 'P0001';
END;
$$;

REVOKE ALL ON PROCEDURE rolebyte.deployment_admin_add(jsonb, jsonb) FROM PUBLIC;
GRANT EXECUTE ON PROCEDURE rolebyte.deployment_admin_add(jsonb, jsonb) TO rolebyte_public;

-- deployment_admin_remove — takes an account off the list of the deployment's
-- administrators. An account that is not on it is refused `membership:not_found`.
-- Otherwise the entry is deleted and one history line written in the company
-- (`deploymentAdminRemoved`). Answers {userId, subjectKey, changed: true}.
CREATE OR REPLACE PROCEDURE rolebyte.deployment_admin_remove(IN pi_data jsonb, INOUT po_data jsonb)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = rolebyte, util, pg_temp
AS $$
DECLARE
    v_actor   text := NULLIF(trim(pi_data->>'actor'), '');
    v_user_id text := NULLIF(trim(pi_data->>'userId'), '');
    v_company text;
    v_key     text;
BEGIN
    IF v_actor IS NULL OR v_user_id IS NULL THEN
        po_data := util.result_error('membership:invalid', 'actor and userId are required');
        RETURN;
    END IF;

    PERFORM pg_advisory_xact_lock(hashtextextended('rolebyte.deployment', 0));

    DELETE FROM rolebyte.deployment_admin WHERE user_id = v_user_id;
    IF NOT FOUND THEN
        po_data := util.result_error('membership:not_found', 'the account is not a deployment administrator');
        RETURN;
    END IF;

    SELECT COALESCE(d.company_tenant_id, u.tenant_id), u.subject_key INTO v_company, v_key
      FROM rolebyte.user_account u
      LEFT JOIN rolebyte.deployment d ON true
     WHERE u.id = v_user_id;

    INSERT INTO rolebyte.event (id, actor, tenant_id, user_id, kind, payload)
    VALUES (util.generate_ulid(), v_actor, v_company, v_user_id, 'deploymentAdminRemoved', '{}'::jsonb);

    po_data := util.result_success(jsonb_build_object('userId', v_user_id, 'subjectKey', v_key, 'changed', true));
EXCEPTION
    WHEN sqlstate 'P0001' THEN
        RAISE;
    WHEN OTHERS THEN
        RAISE EXCEPTION '%', util.result_error('membership:error', sqlerrm) USING errcode = 'P0001';
END;
$$;

REVOKE ALL ON PROCEDURE rolebyte.deployment_admin_remove(jsonb, jsonb) FROM PUBLIC;
GRANT EXECUTE ON PROCEDURE rolebyte.deployment_admin_remove(jsonb, jsonb) TO rolebyte_public;

-- deployment_admin_list — the deployment's administrators whose account is not
-- revoked, by display name then account id: {admins: [{userId, subjectKey,
-- displayName, status, lastSignedInOn, addedBy, addedFrom, addedAt}]}. An empty
-- list when no company is marked or nobody is on it. An entry whose account was
-- revoked stays in the table but is not listed, and never carries the right.
CREATE OR REPLACE PROCEDURE rolebyte.deployment_admin_list(IN pi_data jsonb, INOUT po_data jsonb)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = rolebyte, util, pg_temp
AS $$
BEGIN
    po_data := util.result_success(jsonb_build_object('admins', COALESCE((
        SELECT jsonb_agg(jsonb_build_object(
                   'userId',         u.id,
                   'subjectKey',     u.subject_key,
                   'displayName',    u.display_name,
                   'status',         u.status,
                   'lastSignedInOn', u.last_signed_in_on,
                   'addedBy',        da.added_by,
                   'addedFrom',      da.added_from,
                   'addedAt',        da.added_at)
               ORDER BY u.display_name COLLATE "C", u.id COLLATE "C")
          FROM rolebyte.deployment_admin da
          JOIN rolebyte.user_account u ON u.id = da.user_id
          JOIN rolebyte.deployment d ON d.company_tenant_id = u.tenant_id
         WHERE u.status <> 'revoked'), '[]'::jsonb)));
EXCEPTION
    WHEN sqlstate 'P0001' THEN
        RAISE;
    WHEN OTHERS THEN
        RAISE EXCEPTION '%', util.result_error('membership:error', sqlerrm) USING errcode = 'P0001';
END;
$$;

REVOKE ALL ON PROCEDURE rolebyte.deployment_admin_list(jsonb, jsonb) FROM PUBLIC;
GRANT EXECUTE ON PROCEDURE rolebyte.deployment_admin_list(jsonb, jsonb) TO rolebyte_public;

-- deployment_admin_apply — applies the person the deployment's settings name, once
-- per value. The register's own role runs it at start.
--
-- Input: `actor` (required); `mode`, exactly `saas` or `local`; `subjectKey`, a
-- person's key (`sub:` and a 26-character id; a service's key is refused);
-- `displayName` (optional; blank is absent). Refused `membership:invalid`, writing
-- nothing, for no actor, any other mode and a key that is not a person's; no
-- message repeats the key. Otherwise it always answers success with {outcome,
-- companyId, userId, companyMade, memberAdded, companyMarked, listAdded,
-- rungGranted}; companyId and userId are null where there is none. The three last
-- are true only for what this call did: marked a company as the deployment's own
-- (whatever the outcome that follows), put a new row on the deployment
-- administrators' list, newly granted the company administrator's rung. The outcome
-- is one of:
--   applied        the value was new and has been applied and remembered; a value
--                  is the person's key together with the mode, so the same person
--                  in the other mode is new;
--   unchanged      an account of the person exists and this value, key and mode, is
--                  the one last applied: nothing is written, so an entry taken off
--                  the list by hand is not put back;
--   removedMember  the person's account in the company is revoked: one history line
--                  (`deploymentAdminRefused`, from settings, reason revoked) and
--                  nothing else, whatever the value, and the value is not remembered;
--   nameNeeded     the person has no account and no `displayName` was given: nothing
--                  is written (a company that had to be marked first stays marked);
--   noCompany      none is marked and several exist: nothing is written.
--
-- The deployment's lock is taken first, then, when no company is marked, the lock
-- `bootstrap_state` takes (so that the one-time bootstrap door and this procedure
-- cannot both make a first company), then the company's administrators' lock, then
-- the account's row, the order `user_revoke` documents. `bootstrap_state` takes its
-- lock and nothing after it, so no procedure takes the two in the other order. The
-- deployment's own
-- company is the marked one; with none marked and exactly one company, that one is
-- marked as `deployment_company_mark` marks it. With no company at all (a fresh
-- deployment) and a name, one transaction makes a company with an empty name (its
-- `tenantCreated` line) and no starting roles, which are made when the company's
-- details are entered; marks it (`deploymentCompanyMarked`); makes the person its
-- administrator, invited, with the name given; on `saas` puts them on the list; and
-- remembers the value. `companyMade` and `memberAdded` are then true.
--
-- With a company: a person with no account and a name is added invited (on `saas`
-- holding no role, on `local` holding the administrator's rung); a person with an
-- account and a new value gains the rung on `local` and nothing about the account on
-- `saas`. On `saas` the account is then put on the deployment's list as added from
-- the settings (`deploymentAdminAdded` only for a new entry); on `local` the list is
-- never written. Remembering the value sets the deployment's three columns and writes
-- one history line (`deploymentAdminSettingApplied`, {mode}). A suspended company is
-- treated like any other.
CREATE OR REPLACE PROCEDURE rolebyte.deployment_admin_apply(IN pi_data jsonb, INOUT po_data jsonb)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = rolebyte, util, pg_temp
AS $$
DECLARE
    v_actor    text := NULLIF(trim(pi_data->>'actor'), '');
    v_mode     text := pi_data->>'mode';
    v_subject  text := NULLIF(trim(pi_data->>'subjectKey'), '');
    v_display  text := NULLIF(trim(pi_data->>'displayName'), '');
    v_company  text;
    v_last     text;
    v_last_mode text;
    v_count    integer;
    v_made_co  boolean := false;
    v_added    boolean := false;
    v_marked   boolean := false;
    v_listed   boolean := false;
    v_rung     boolean := false;
    v_user     rolebyte.user_account%ROWTYPE;
    v_found    boolean;
    v_res      jsonb;
BEGIN
    IF v_actor IS NULL THEN
        po_data := util.result_error('membership:invalid', 'actor is required');
        RETURN;
    END IF;
    IF v_mode IS NULL OR v_mode NOT IN ('saas', 'local') THEN
        po_data := util.result_error('membership:invalid', 'mode is saas or local');
        RETURN;
    END IF;
    IF v_subject IS NULL OR left(v_subject, 4) <> 'sub:' OR NOT rolebyte.is_typed_subject_key(v_subject) THEN
        po_data := util.result_error('membership:invalid', 'subjectKey must be a person''s key, sub:<person id>');
        RETURN;
    END IF;

    PERFORM pg_advisory_xact_lock(hashtextextended('rolebyte.deployment', 0));

    SELECT company_tenant_id, admin_setting_subject_key, admin_setting_mode
      INTO v_company, v_last, v_last_mode
      FROM rolebyte.deployment;

    IF v_company IS NULL THEN
        -- The one-time bootstrap door's lock, so the door and this procedure cannot
        -- both make a first company.
        PERFORM pg_advisory_xact_lock(hashtext('rolebyte.bootstrap'));

        SELECT count(*), min(id) INTO v_count, v_company FROM rolebyte.tenant;
        IF v_count > 1 THEN
            po_data := util.result_success(jsonb_build_object(
                'outcome', 'noCompany', 'companyId', NULL, 'userId', NULL,
                'companyMade', false, 'memberAdded', false,
                'companyMarked', false, 'listAdded', false, 'rungGranted', false));
            RETURN;
        END IF;
        IF v_count = 1 THEN
            INSERT INTO rolebyte.deployment (company_tenant_id) VALUES (v_company);
            INSERT INTO rolebyte.event (id, actor, tenant_id, kind, payload)
            VALUES (util.generate_ulid(), v_actor, v_company, 'deploymentCompanyMarked', '{}'::jsonb);
            v_marked := true;
        ELSE
            -- A fresh deployment: the company is made here, with an empty name.
            IF v_display IS NULL THEN
                po_data := util.result_success(jsonb_build_object(
                    'outcome', 'nameNeeded', 'companyId', NULL, 'userId', NULL,
                    'companyMade', false, 'memberAdded', false,
                    'companyMarked', false, 'listAdded', false, 'rungGranted', false));
                RETURN;
            END IF;
            v_company := util.generate_ulid();
            INSERT INTO rolebyte.tenant (id, name) VALUES (v_company, '');
            INSERT INTO rolebyte.event (id, actor, tenant_id, kind, payload)
            VALUES (util.generate_ulid(), v_actor, v_company, 'tenantCreated',
                    jsonb_build_object('name', ''));
            INSERT INTO rolebyte.deployment (company_tenant_id) VALUES (v_company);
            INSERT INTO rolebyte.event (id, actor, tenant_id, kind, payload)
            VALUES (util.generate_ulid(), v_actor, v_company, 'deploymentCompanyMarked', '{}'::jsonb);
            v_made_co := true;
            v_marked := true;
        END IF;
    END IF;

    PERFORM rolebyte.administrator_lock(v_company);

    SELECT * INTO v_user
      FROM rolebyte.user_account
     WHERE tenant_id = v_company AND subject_key = v_subject
       FOR UPDATE;
    v_found := FOUND;

    IF v_found AND v_user.status = 'revoked' THEN
        INSERT INTO rolebyte.event (id, actor, tenant_id, user_id, kind, payload)
        VALUES (util.generate_ulid(), v_actor, v_company, v_user.id, 'deploymentAdminRefused',
                jsonb_build_object('from', 'settings', 'reason', 'revoked'));
        po_data := util.result_success(jsonb_build_object(
            'outcome', 'removedMember', 'companyId', v_company, 'userId', v_user.id,
            'companyMade', false, 'memberAdded', false,
            'companyMarked', v_marked, 'listAdded', false, 'rungGranted', false));
        RETURN;
    END IF;

    IF v_found AND v_last IS NOT DISTINCT FROM v_subject AND v_last_mode IS NOT DISTINCT FROM v_mode THEN
        po_data := util.result_success(jsonb_build_object(
            'outcome', 'unchanged', 'companyId', v_company, 'userId', v_user.id,
            'companyMade', false, 'memberAdded', false,
            'companyMarked', v_marked, 'listAdded', false, 'rungGranted', false));
        RETURN;
    END IF;

    IF NOT v_found AND v_display IS NULL THEN
        po_data := util.result_success(jsonb_build_object(
            'outcome', 'nameNeeded', 'companyId', v_company, 'userId', NULL,
            'companyMade', false, 'memberAdded', false,
            'companyMarked', v_marked, 'listAdded', false, 'rungGranted', false));
        RETURN;
    END IF;

    IF v_mode = 'local' OR v_made_co THEN
        -- The person becomes an administrator of the company: added when not a
        -- member, the rung granted where it is lacking.
        v_res := rolebyte.administrator_make(v_actor, v_company, v_subject, v_display);
        IF v_res->>'result' IS DISTINCT FROM 'success' THEN
            RAISE EXCEPTION '%', v_res USING errcode = 'P0001';
        END IF;
        v_user.id := v_res->'data'->>'userId';
        v_added := (v_res->'data'->>'invited')::boolean;
        v_rung := (v_res->'data'->>'changed')::boolean;
    ELSIF NOT v_found THEN
        -- On saas a new member holds no role: the right comes from the list.
        v_user := rolebyte.invited_member_add(v_actor, v_company, v_subject, v_display);
        v_added := true;
    END IF;

    IF v_mode = 'saas' THEN
        INSERT INTO rolebyte.deployment_admin (user_id, added_by, added_from)
        VALUES (v_user.id, v_actor, 'settings')
        ON CONFLICT (user_id) DO NOTHING;
        IF FOUND THEN
            v_listed := true;
            INSERT INTO rolebyte.event (id, actor, tenant_id, user_id, kind, payload)
            VALUES (util.generate_ulid(), v_actor, v_company, v_user.id, 'deploymentAdminAdded',
                    jsonb_build_object('addedFrom', 'settings'));
        END IF;
    END IF;

    UPDATE rolebyte.deployment
       SET admin_setting_subject_key = v_subject, admin_setting_applied_at = now(),
           admin_setting_mode = v_mode;
    INSERT INTO rolebyte.event (id, actor, tenant_id, user_id, kind, payload)
    VALUES (util.generate_ulid(), v_actor, v_company, v_user.id, 'deploymentAdminSettingApplied',
            jsonb_build_object('mode', v_mode));

    po_data := util.result_success(jsonb_build_object(
        'outcome', 'applied', 'companyId', v_company, 'userId', v_user.id,
        'companyMade', v_made_co, 'memberAdded', v_added,
        'companyMarked', v_marked, 'listAdded', v_listed, 'rungGranted', v_rung));
EXCEPTION
    WHEN sqlstate 'P0001' THEN
        RAISE;
    WHEN OTHERS THEN
        RAISE EXCEPTION '%', util.result_error('membership:error', sqlerrm) USING errcode = 'P0001';
END;
$$;

REVOKE ALL ON PROCEDURE rolebyte.deployment_admin_apply(jsonb, jsonb) FROM PUBLIC;
GRANT EXECUTE ON PROCEDURE rolebyte.deployment_admin_apply(jsonb, jsonb) TO rolebyte_public;

-- ===========================================================================
-- Entitlement: what a tenant has, read by resolve. Written only by the
-- deployment's operator — none of these is granted to the register's own role,
-- so no request a tenant can make, through any route, reaches them. The
-- operator calls them as the location's owner, the way a deployment creates a
-- tenant and registers what its services declare.
--
-- A write reaches the next token within the resolve cache's lifetime: the
-- service's cache is not told, because the service is not the one writing.
-- ===========================================================================

-- entitlement_refusal — the one check an entitlement write makes before it
-- names anything: the tenant exists, the service is registered, and the feature
-- is empty (the whole service) or one that a permission of the service carries,
-- itself or nested under it. A typo is refused rather than stored as an
-- entitlement to nothing. NULL when everything holds.
CREATE OR REPLACE FUNCTION rolebyte.entitlement_refusal(p_tenant text, p_service text, p_feature text)
RETURNS jsonb
LANGUAGE plpgsql
STABLE
SET search_path = rolebyte, util, pg_temp
AS $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM rolebyte.tenant WHERE id = p_tenant) THEN
        RETURN util.result_error('membership:not_found', 'no such tenant');
    END IF;
    IF NOT EXISTS (SELECT 1 FROM rolebyte.service WHERE key = p_service) THEN
        RETURN util.result_error('membership:not_found', 'service is not registered');
    END IF;
    IF p_feature = '' THEN
        RETURN NULL;
    END IF;
    IF rolebyte.is_permission_feature(p_feature) IS NOT TRUE THEN
        RETURN util.result_error('membership:invalid',
            'feature must be empty or one or more lower-camel words joined by "/"');
    END IF;
    IF NOT EXISTS (SELECT 1 FROM rolebyte.service_permission
                    WHERE service_key = p_service
                      AND (feature_key = p_feature OR starts_with(feature_key, p_feature || '/'))) THEN
        RETURN util.result_error('membership:not_found', 'no permission of this service has this feature');
    END IF;
    RETURN NULL;
END;
$$;

REVOKE ALL ON FUNCTION rolebyte.entitlement_refusal(text, text, text) FROM PUBLIC;

-- entitlement_grant — give a tenant a whole service (`feature` absent or empty)
-- or one feature of it. Entitling again after a revoke flips it back; entitling
-- what the tenant already has changes nothing. Emits `tenantEntitled`.
CREATE OR REPLACE PROCEDURE rolebyte.entitlement_grant(IN pi_data jsonb, INOUT po_data jsonb)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = rolebyte, util, pg_temp
AS $$
DECLARE
    v_actor   text;
    v_tenant  text;
    v_service text;
    v_feature text;
    v_refusal jsonb;
    v_changed boolean := false;
BEGIN
    v_actor   := NULLIF(trim(pi_data->>'actor'), '');
    v_tenant  := NULLIF(trim(pi_data->>'tenantId'), '');
    v_service := NULLIF(trim(pi_data->>'service'), '');
    v_feature := COALESCE(trim(pi_data->>'feature'), '');
    IF v_actor IS NULL OR v_tenant IS NULL OR v_service IS NULL THEN
        po_data := util.result_error('membership:invalid', 'actor, tenantId and service are required');
        RETURN;
    END IF;

    v_refusal := rolebyte.entitlement_refusal(v_tenant, v_service, v_feature);
    IF v_refusal IS NOT NULL THEN
        po_data := v_refusal;
        RETURN;
    END IF;

    INSERT INTO rolebyte.tenant_entitlement (id, tenant_id, service_key, feature_key)
    VALUES (util.generate_ulid(), v_tenant, v_service, v_feature)
    ON CONFLICT (tenant_id, service_key, feature_key)
        DO UPDATE SET state = 'entitled', entitled_at = now(), revoked_at = NULL
        WHERE rolebyte.tenant_entitlement.state = 'revoked';
    v_changed := FOUND;

    IF v_changed THEN
        INSERT INTO rolebyte.event (id, actor, tenant_id, user_id, kind, payload)
        VALUES (util.generate_ulid(), v_actor, v_tenant, NULL, 'tenantEntitled',
                jsonb_build_object('service', v_service, 'feature', v_feature));
    END IF;

    po_data := util.result_success(jsonb_build_object('changed', v_changed));
EXCEPTION
    WHEN sqlstate 'P0001' THEN
        RAISE;
    WHEN OTHERS THEN
        RAISE EXCEPTION '%', util.result_error('membership:error', sqlerrm) USING errcode = 'P0001';
END;
$$;

REVOKE ALL ON PROCEDURE rolebyte.entitlement_grant(jsonb, jsonb) FROM PUBLIC;

-- entitlement_revoke — take an entitlement away. Nothing the tenant configured
-- is deleted: its roles keep their ticks, which stop reaching tokens. Revoking
-- what is already revoked changes nothing; revoking what the tenant was never
-- given is refused, so a mistyped name cannot look like a revoke that happened.
-- Emits `tenantEntitlementRevoked`.
CREATE OR REPLACE PROCEDURE rolebyte.entitlement_revoke(IN pi_data jsonb, INOUT po_data jsonb)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = rolebyte, util, pg_temp
AS $$
DECLARE
    v_actor   text;
    v_tenant  text;
    v_service text;
    v_feature text;
    v_changed boolean := false;
BEGIN
    v_actor   := NULLIF(trim(pi_data->>'actor'), '');
    v_tenant  := NULLIF(trim(pi_data->>'tenantId'), '');
    v_service := NULLIF(trim(pi_data->>'service'), '');
    v_feature := COALESCE(trim(pi_data->>'feature'), '');
    IF v_actor IS NULL OR v_tenant IS NULL OR v_service IS NULL THEN
        po_data := util.result_error('membership:invalid', 'actor, tenantId and service are required');
        RETURN;
    END IF;

    IF NOT EXISTS (SELECT 1 FROM rolebyte.tenant_entitlement
                    WHERE tenant_id = v_tenant AND service_key = v_service AND feature_key = v_feature) THEN
        po_data := util.result_error('membership:not_found', 'the tenant was never given this');
        RETURN;
    END IF;

    UPDATE rolebyte.tenant_entitlement
       SET state = 'revoked', revoked_at = now()
     WHERE tenant_id = v_tenant AND service_key = v_service AND feature_key = v_feature
       AND state = 'entitled';
    v_changed := FOUND;

    IF v_changed THEN
        INSERT INTO rolebyte.event (id, actor, tenant_id, user_id, kind, payload)
        VALUES (util.generate_ulid(), v_actor, v_tenant, NULL, 'tenantEntitlementRevoked',
                jsonb_build_object('service', v_service, 'feature', v_feature));
    END IF;

    po_data := util.result_success(jsonb_build_object('changed', v_changed));
EXCEPTION
    WHEN sqlstate 'P0001' THEN
        RAISE;
    WHEN OTHERS THEN
        RAISE EXCEPTION '%', util.result_error('membership:error', sqlerrm) USING errcode = 'P0001';
END;
$$;

REVOKE ALL ON PROCEDURE rolebyte.entitlement_revoke(jsonb, jsonb) FROM PUBLIC;

-- entitlement_list — what a tenant has now: each entitlement in force, a whole
-- service as an empty feature, in a stable order.
CREATE OR REPLACE PROCEDURE rolebyte.entitlement_list(IN pi_data jsonb, INOUT po_data jsonb)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = rolebyte, util, pg_temp
AS $$
DECLARE
    v_tenant text;
    v_items  jsonb;
BEGIN
    v_tenant := NULLIF(trim(pi_data->>'tenantId'), '');
    IF v_tenant IS NULL THEN
        po_data := util.result_error('membership:invalid', 'tenantId is required');
        RETURN;
    END IF;
    IF NOT EXISTS (SELECT 1 FROM rolebyte.tenant WHERE id = v_tenant) THEN
        po_data := util.result_error('membership:not_found', 'no such tenant');
        RETURN;
    END IF;

    SELECT COALESCE(jsonb_agg(jsonb_build_object(
        'service',    e.service_key,
        'feature',    e.feature_key,
        'entitledAt', e.entitled_at
    ) ORDER BY e.service_key, e.feature_key), '[]'::jsonb)
    INTO v_items
    FROM rolebyte.tenant_entitlement e
    WHERE e.tenant_id = v_tenant AND e.state = 'entitled';

    po_data := util.result_success(jsonb_build_object('entitlements', v_items));
EXCEPTION
    WHEN sqlstate 'P0001' THEN
        RAISE;
    WHEN OTHERS THEN
        RAISE EXCEPTION '%', util.result_error('membership:error', sqlerrm) USING errcode = 'P0001';
END;
$$;

REVOKE ALL ON PROCEDURE rolebyte.entitlement_list(jsonb, jsonb) FROM PUBLIC;

-- ===========================================================================
-- The operator's administrator acts: the way back for a tenant whose
-- administrators are gone. The deployment's operator opens a tenant with its
-- first administrator, sees every tenant with its administrators, and can make
-- someone an administrator or remove one. Like entitlement, none of these is
-- granted to the register's own role, so no request a tenant can make reaches
-- them; the operator calls them as the location's owner.
--
-- Each act that changes an administrator writes the ordinary events of what it
-- changed and one event of its own kind, so a later notice to the tenant can
-- select them by kind: `administratorSetByOperator`,
-- `administratorUnsetByOperator`, and the seed's `administratorSeeded`.
--
-- The one exception is the seed, which the service applies at start from its
-- own environment and therefore runs as the register's role.
-- ===========================================================================

-- tenant_open — a new tenant with its first administrator, invited until their
-- first sign-in, and the roles it starts with: Guest, Worker and Manager, holding
-- what the services declared for them, named in `language` (English unless
-- "lv"). The administrator is named by the subject key the identity store gave
-- them, as every invitation is. Emits `tenantCreated`, `userInvited`,
-- `roleGranted`, `administratorSetByOperator` and a `tenantRoleSeeded` per role.
CREATE OR REPLACE PROCEDURE rolebyte.tenant_open(IN pi_data jsonb, INOUT po_data jsonb)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = rolebyte, util, pg_temp
AS $$
DECLARE
    v_actor   text;
    v_name    text;
    v_admin   jsonb;
    v_subject text;
    v_display text;
    v_tenant  rolebyte.tenant%ROWTYPE;
    v_made    jsonb;
    v_roles   jsonb;
BEGIN
    v_actor := NULLIF(trim(pi_data->>'actor'), '');
    v_name  := NULLIF(trim(pi_data->>'name'), '');
    IF v_actor IS NULL OR v_name IS NULL THEN
        po_data := util.result_error('tenant:invalid', 'actor and name are required');
        RETURN;
    END IF;

    v_admin := pi_data->'administrator';
    IF jsonb_typeof(v_admin) IS DISTINCT FROM 'object' THEN
        po_data := util.result_error('membership:invalid',
            'administrator must be an object with subjectKey and displayName');
        RETURN;
    END IF;
    v_subject := NULLIF(trim(v_admin->>'subjectKey'), '');
    v_display := NULLIF(trim(v_admin->>'displayName'), '');
    IF v_subject IS NULL OR NOT rolebyte.is_typed_subject_key(v_subject) THEN
        po_data := util.result_error('membership:invalid',
            'subjectKey must be a typed key: sub:<person id> for a person, svc:<client id> for a service account');
        RETURN;
    END IF;
    IF v_display IS NULL THEN
        po_data := util.result_error('membership:invalid', 'displayName is required');
        RETURN;
    END IF;

    INSERT INTO rolebyte.tenant (id, name)
    VALUES (util.generate_ulid(), v_name)
    RETURNING * INTO v_tenant;

    INSERT INTO rolebyte.event (id, actor, tenant_id, kind, payload)
    VALUES (util.generate_ulid(), v_actor, v_tenant.id, 'tenantCreated',
            jsonb_build_object('name', v_tenant.name));

    PERFORM rolebyte.ensure_default_user_type(v_actor, v_tenant.id, NULLIF(btrim(pi_data->>'language'), ''));

    v_made := rolebyte.administrator_make(v_actor, v_tenant.id, v_subject, v_display);
    IF v_made->>'result' IS DISTINCT FROM 'success' THEN
        RAISE EXCEPTION '%', v_made USING errcode = 'P0001';
    END IF;

    INSERT INTO rolebyte.event (id, actor, tenant_id, user_id, kind, payload)
    VALUES (util.generate_ulid(), v_actor, v_tenant.id, v_made->'data'->>'userId',
            'administratorSetByOperator', '{}'::jsonb);

    v_roles := rolebyte.seed_roles(v_actor, v_tenant.id, NULLIF(btrim(pi_data->>'language'), ''));

    po_data := util.result_success(jsonb_build_object(
        'tenant', jsonb_build_object(
            'id',        v_tenant.id,
            'name',      v_tenant.name,
            'status',    v_tenant.status,
            'createdAt', v_tenant.created_at),
        'administrator', jsonb_build_object(
            'id',     v_made->'data'->>'userId',
            'status', v_made->'data'->>'status'),
        'roles', v_roles
    ));
EXCEPTION
    WHEN sqlstate 'P0001' THEN
        RAISE;
    WHEN OTHERS THEN
        RAISE EXCEPTION '%', util.result_error('membership:error', sqlerrm) USING errcode = 'P0001';
END;
$$;

REVOKE ALL ON PROCEDURE rolebyte.tenant_open(jsonb, jsonb) FROM PUBLIC;

-- administrator_set — the operator makes a person an administrator of a tenant,
-- whatever anyone else's state: the case where the only administrator is gone.
-- A member receives the rung; someone not yet a member is added, invited,
-- holding it. Making an administrator of someone who already is one changes
-- nothing and writes nothing. Emits `administratorSetByOperator` beside the
-- events of what it changed.
CREATE OR REPLACE PROCEDURE rolebyte.administrator_set(IN pi_data jsonb, INOUT po_data jsonb)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = rolebyte, util, pg_temp
AS $$
DECLARE
    v_actor  text;
    v_tenant text;
    v_made   jsonb;
BEGIN
    v_actor  := NULLIF(trim(pi_data->>'actor'), '');
    v_tenant := NULLIF(trim(pi_data->>'tenantId'), '');
    IF v_actor IS NULL OR v_tenant IS NULL THEN
        po_data := util.result_error('membership:invalid', 'actor and tenantId are required');
        RETURN;
    END IF;
    IF NOT EXISTS (SELECT 1 FROM rolebyte.tenant WHERE id = v_tenant) THEN
        po_data := util.result_error('tenant:not_found', 'tenant does not exist');
        RETURN;
    END IF;

    v_made := rolebyte.administrator_make(v_actor, v_tenant,
        NULLIF(trim(pi_data->>'subjectKey'), ''), NULLIF(trim(pi_data->>'displayName'), ''));
    IF v_made->>'result' IS DISTINCT FROM 'success' THEN
        po_data := v_made;
        RETURN;
    END IF;

    IF (v_made->'data'->>'changed')::boolean THEN
        INSERT INTO rolebyte.event (id, actor, tenant_id, user_id, kind, payload)
        VALUES (util.generate_ulid(), v_actor, v_tenant, v_made->'data'->>'userId',
                'administratorSetByOperator', '{}'::jsonb);
    END IF;

    po_data := util.result_success(jsonb_build_object(
        'tenantId', v_tenant,
        'userId',   v_made->'data'->>'userId',
        'invited',  (v_made->'data'->>'invited')::boolean,
        'changed',  (v_made->'data'->>'changed')::boolean
    ));
EXCEPTION
    WHEN sqlstate 'P0001' THEN
        RAISE;
    WHEN OTHERS THEN
        RAISE EXCEPTION '%', util.result_error('membership:error', sqlerrm) USING errcode = 'P0001';
END;
$$;

REVOKE ALL ON PROCEDURE rolebyte.administrator_set(jsonb, jsonb) FROM PUBLIC;

-- administrator_unset — the operator removes an administrator. The tenant still
-- keeps one: removing the last is refused, so this follows a set. The member
-- stays a member; only the rung goes. Removing it from someone who does not
-- hold it changes nothing and writes nothing. Emits `roleRevoked` and
-- `administratorUnsetByOperator`.
CREATE OR REPLACE PROCEDURE rolebyte.administrator_unset(IN pi_data jsonb, INOUT po_data jsonb)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = rolebyte, util, pg_temp
AS $$
DECLARE
    v_actor   text;
    v_tenant  text;
    v_user_id text;
    v_refusal jsonb;
    v_def     rolebyte.role_definition%ROWTYPE;
    v_changed boolean := false;
BEGIN
    v_actor   := NULLIF(trim(pi_data->>'actor'), '');
    v_tenant  := NULLIF(trim(pi_data->>'tenantId'), '');
    v_user_id := NULLIF(trim(pi_data->>'userId'), '');
    IF v_actor IS NULL OR v_tenant IS NULL OR v_user_id IS NULL THEN
        po_data := util.result_error('membership:invalid', 'actor, tenantId and userId are required');
        RETURN;
    END IF;
    IF NOT EXISTS (SELECT 1 FROM rolebyte.user_account WHERE id = v_user_id AND tenant_id = v_tenant) THEN
        po_data := util.result_error('membership:not_found', 'user does not exist');
        RETURN;
    END IF;

    v_refusal := rolebyte.administrator_removal_refusal(v_tenant, v_user_id);
    IF v_refusal IS NOT NULL THEN
        po_data := v_refusal;
        RETURN;
    END IF;

    FOR v_def IN
        UPDATE rolebyte.assignment a
           SET state = 'revoked', revoked_at = now()
          FROM rolebyte.role_definition rd
         WHERE rd.id = a.role_definition_id
           AND a.user_id = v_user_id
           AND a.state = 'granted'
           AND rolebyte.is_administrator_rung(rd.role_group, rd.role_level)
        RETURNING rd.*
    LOOP
        INSERT INTO rolebyte.event (id, actor, tenant_id, user_id, kind, payload)
        VALUES (util.generate_ulid(), v_actor, v_tenant, v_user_id, 'roleRevoked',
                jsonb_build_object('service', v_def.service_key, 'group', v_def.role_group, 'level', v_def.role_level));
        v_changed := true;
    END LOOP;

    IF v_changed THEN
        INSERT INTO rolebyte.event (id, actor, tenant_id, user_id, kind, payload)
        VALUES (util.generate_ulid(), v_actor, v_tenant, v_user_id, 'administratorUnsetByOperator', '{}'::jsonb);
    END IF;

    po_data := util.result_success(jsonb_build_object('changed', v_changed));
EXCEPTION
    WHEN sqlstate 'P0001' THEN
        RAISE;
    WHEN OTHERS THEN
        RAISE EXCEPTION '%', util.result_error('membership:error', sqlerrm) USING errcode = 'P0001';
END;
$$;

REVOKE ALL ON PROCEDURE rolebyte.administrator_unset(jsonb, jsonb) FROM PUBLIC;

-- tenant_overview — the operator's view of the deployment: every tenant with its
-- status, what it has, and who holds the administrator rung with the state of
-- their account, so a tenant whose only administrator was revoked is visible as
-- one. Tenants in the order they were created.
CREATE OR REPLACE PROCEDURE rolebyte.tenant_overview(IN pi_data jsonb, INOUT po_data jsonb)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = rolebyte, util, pg_temp
AS $$
DECLARE
    v_items jsonb;
BEGIN
    SELECT COALESCE(jsonb_agg(jsonb_build_object(
        'id',        t.id,
        'name',      t.name,
        'status',    t.status,
        'createdAt', t.created_at,
        'entitlements', COALESCE((
            SELECT jsonb_agg(jsonb_build_object('service', e.service_key, 'feature', e.feature_key)
                             ORDER BY e.service_key, e.feature_key)
              FROM rolebyte.tenant_entitlement e
             WHERE e.tenant_id = t.id AND e.state = 'entitled'), '[]'::jsonb),
        'administrators', COALESCE((
            SELECT jsonb_agg(jsonb_build_object(
                       'userId',      u.id,
                       'subjectKey',  u.subject_key,
                       'displayName', u.display_name,
                       'status',      u.status)
                   ORDER BY lower(u.display_name), u.id)
              FROM rolebyte.user_account u
             WHERE u.tenant_id = t.id
               AND EXISTS (SELECT 1 FROM rolebyte.assignment a
                             JOIN rolebyte.role_definition rd ON rd.id = a.role_definition_id
                            WHERE a.user_id = u.id AND a.state = 'granted'
                              AND rolebyte.is_administrator_rung(rd.role_group, rd.role_level))), '[]'::jsonb)
    ) ORDER BY t.created_at, t.id), '[]'::jsonb)
    INTO v_items
    FROM rolebyte.tenant t;

    po_data := util.result_success(jsonb_build_object('tenants', v_items));
EXCEPTION
    WHEN sqlstate 'P0001' THEN
        RAISE;
    WHEN OTHERS THEN
        RAISE EXCEPTION '%', util.result_error('membership:error', sqlerrm) USING errcode = 'P0001';
END;
$$;

REVOKE ALL ON PROCEDURE rolebyte.tenant_overview(jsonb, jsonb) FROM PUBLIC;

-- administrator_seed — the environment's way back, on a deployment the operator
-- runs on the customer's own machines: at start the service passes the subject
-- key its environment names, and that person becomes an administrator of the
-- tenant as administrator_set makes one.
--
-- Applied once per value. The last value applied to the tenant is remembered,
-- so a restart with the same value does nothing and writes nothing, and a new
-- value acts whatever anyone else's state. It never removes anyone: the new
-- administrator removes the old one. The tenant may be left out when the
-- deployment has exactly one. Emits `administratorSeeded` for each value
-- applied, beside the events of what it changed.
--
-- The register's own role runs this one: the value comes from the deployment's
-- own environment, which is the operator's. Every refusal is one the service
-- stops its start on, so a seed that did not apply is never mistaken for one
-- that did.
CREATE OR REPLACE PROCEDURE rolebyte.administrator_seed(IN pi_data jsonb, INOUT po_data jsonb)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = rolebyte, util, pg_temp
AS $$
DECLARE
    v_actor   text;
    v_tenant  text;
    v_subject text;
    v_count   integer;
    v_made    jsonb;
BEGIN
    v_actor   := NULLIF(trim(pi_data->>'actor'), '');
    v_tenant  := NULLIF(trim(pi_data->>'tenantId'), '');
    v_subject := NULLIF(trim(pi_data->>'subjectKey'), '');
    IF v_actor IS NULL THEN
        po_data := util.result_error('membership:invalid', 'actor is required');
        RETURN;
    END IF;
    IF v_subject IS NULL OR NOT rolebyte.is_typed_subject_key(v_subject) THEN
        po_data := util.result_error('membership:invalid',
            'subjectKey must be a typed key: sub:<person id> for a person, svc:<client id> for a service account');
        RETURN;
    END IF;

    IF v_tenant IS NULL THEN
        SELECT count(*) INTO v_count FROM rolebyte.tenant;
        IF v_count = 0 THEN
            po_data := util.result_error('tenant:not_found', 'the deployment has no tenant to seed an administrator into');
            RETURN;
        END IF;
        IF v_count > 1 THEN
            po_data := util.result_error('membership:invalid',
                format('the tenant must be named: the deployment has %s tenants', v_count));
            RETURN;
        END IF;
        SELECT id INTO v_tenant FROM rolebyte.tenant;
    ELSIF NOT EXISTS (SELECT 1 FROM rolebyte.tenant WHERE id = v_tenant) THEN
        po_data := util.result_error('tenant:not_found', 'tenant does not exist');
        RETURN;
    END IF;

    -- Two instances starting together with the same value apply it once.
    PERFORM rolebyte.administrator_lock(v_tenant);
    IF EXISTS (SELECT 1 FROM rolebyte.administrator_seed
                WHERE tenant_id = v_tenant AND subject_key = v_subject) THEN
        po_data := util.result_success(jsonb_build_object('tenantId', v_tenant, 'applied', false));
        RETURN;
    END IF;

    v_made := rolebyte.administrator_make(v_actor, v_tenant, v_subject, NULLIF(trim(pi_data->>'displayName'), ''));
    IF v_made->>'result' IS DISTINCT FROM 'success' THEN
        po_data := v_made;
        RETURN;
    END IF;

    INSERT INTO rolebyte.administrator_seed (tenant_id, subject_key)
    VALUES (v_tenant, v_subject)
    ON CONFLICT (tenant_id) DO UPDATE SET subject_key = EXCLUDED.subject_key, applied_at = now();

    INSERT INTO rolebyte.event (id, actor, tenant_id, user_id, kind, payload)
    VALUES (util.generate_ulid(), v_actor, v_tenant, v_made->'data'->>'userId', 'administratorSeeded',
            jsonb_build_object('subjectKey', v_subject));

    po_data := util.result_success(jsonb_build_object(
        'tenantId', v_tenant,
        'userId',   v_made->'data'->>'userId',
        'applied',  true,
        'changed',  (v_made->'data'->>'changed')::boolean
    ));
EXCEPTION
    WHEN sqlstate 'P0001' THEN
        RAISE;
    WHEN OTHERS THEN
        RAISE EXCEPTION '%', util.result_error('membership:error', sqlerrm) USING errcode = 'P0001';
END;
$$;

REVOKE ALL ON PROCEDURE rolebyte.administrator_seed(jsonb, jsonb) FROM PUBLIC;
GRANT EXECUTE ON PROCEDURE rolebyte.administrator_seed(jsonb, jsonb) TO rolebyte_public;

-- ---------------------------------------------------------------------------
-- A person's own language. Kept for the person, not for any membership: one
-- row per person keyed by their platform subject (`sub:<person id>`), the same
-- in every tenant they belong to, read and set by that person. NULL, or no row,
-- means they read the deployment's language. Each change is a line of the
-- register's history that belongs to no tenant and no membership (`tenant_id`
-- and `user_id` NULL), naming the person in its payload, so no tenant's history
-- shows it: it is a person's choice about their own screen, nobody else's data.
-- The row is part of the person: whatever erases a person takes it with them.
-- ---------------------------------------------------------------------------

-- person_language_get — the person's own language: {"language": "en"} or
-- {"language": null} when they have not chosen one. Answers for a person's key
-- only; a service account's key, or a key of any other kind, is refused.
CREATE OR REPLACE PROCEDURE rolebyte.person_language_get(IN pi_data jsonb, INOUT po_data jsonb)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = rolebyte, util, pg_temp
AS $$
DECLARE
    v_subject  text := NULLIF(btrim(pi_data->>'subjectKey'), '');
    v_language text;
BEGIN
    IF v_subject IS NULL
       OR (starts_with(v_subject, 'sub:') AND rolebyte.is_typed_subject_key(v_subject)) IS NOT TRUE THEN
        po_data := util.result_error('membership:invalid', 'subjectKey must be a person''s key, sub:<person id>');
        RETURN;
    END IF;

    SELECT s.language INTO v_language FROM rolebyte.person_setting s WHERE s.subject_key = v_subject;

    po_data := util.result_success(jsonb_build_object('language', v_language));
EXCEPTION
    WHEN sqlstate 'P0001' THEN
        RAISE;
    WHEN OTHERS THEN
        RAISE EXCEPTION '%', util.result_error('membership:error', sqlerrm) USING errcode = 'P0001';
END;
$$;

REVOKE ALL ON PROCEDURE rolebyte.person_language_get(jsonb, jsonb) FROM PUBLIC;
GRANT EXECUTE ON PROCEDURE rolebyte.person_language_get(jsonb, jsonb) TO rolebyte_public;

-- person_language_set — choose the person's own language, or clear it:
-- {actor, subjectKey, language} → {"language": …}. `language` must be sent: a
-- language the app speaks (util.app_languages, matched exactly) sets it, null
-- clears it, so the person reads the deployment's again; anything else, and a
-- call leaving it out, is refused rather than read as a clear. Only a person
-- who is an active member of at least one active tenant keeps one: anybody else
-- is refused `membership:notMember`. Every refusal writes nothing.
--
-- A set that moves the value writes one `personLanguageSet` line —
-- {subjectKey, language, from}, `language` and `from` each a language or null —
-- belonging to no tenant; a set that changes nothing writes nothing, and neither
-- does clearing a language that was never chosen.
--
-- Two sets of one person at the same moment take turns: each holds the person's
-- own lock to the end of its transaction, so the second waits for the first to
-- commit, then reads what it wrote, and its line starts `from` there. Different
-- people never wait for each other.
CREATE OR REPLACE PROCEDURE rolebyte.person_language_set(IN pi_data jsonb, INOUT po_data jsonb)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = rolebyte, util, pg_temp
AS $$
DECLARE
    v_actor    text := NULLIF(btrim(pi_data->>'actor'), '');
    v_subject  text := NULLIF(btrim(pi_data->>'subjectKey'), '');
    v_language text;
    v_before   text;
    v_why      text := 'language must be a language the app speaks ('
                       || array_to_string(util.app_languages(), ', ') || '), or null to read the deployment''s';
BEGIN
    IF v_actor IS NULL OR v_subject IS NULL THEN
        po_data := util.result_error('membership:invalid', 'actor and subjectKey are required');
        RETURN;
    END IF;
    IF (starts_with(v_subject, 'sub:') AND rolebyte.is_typed_subject_key(v_subject)) IS NOT TRUE THEN
        po_data := util.result_error('membership:invalid', 'subjectKey must be a person''s key, sub:<person id>');
        RETURN;
    END IF;

    -- Left out, `language` has no type at all, and is refused with every other
    -- shape that is neither a language nor null.
    CASE jsonb_typeof(pi_data->'language')
        WHEN 'string' THEN
            v_language := pi_data->>'language';
            IF NOT (v_language = ANY (util.app_languages())) THEN
                po_data := util.result_error('membership:invalid', v_why);
                RETURN;
            END IF;
        WHEN 'null' THEN
            v_language := NULL;
        ELSE
            po_data := util.result_error('membership:invalid', v_why);
            RETURN;
    END CASE;

    IF NOT EXISTS (
        SELECT 1
          FROM rolebyte.user_account u
          JOIN rolebyte.tenant t ON t.id = u.tenant_id
         WHERE u.subject_key = v_subject
           AND u.status = 'active'
           AND t.status = 'active') THEN
        po_data := util.result_error('membership:notMember',
            'only an active member of an active tenant keeps a language of their own');
        RETURN;
    END IF;

    PERFORM pg_advisory_xact_lock(hashtextextended('rolebyte.person_setting:' || v_subject, 0));

    SELECT s.language INTO v_before FROM rolebyte.person_setting s WHERE s.subject_key = v_subject;

    IF v_language IS DISTINCT FROM v_before THEN
        INSERT INTO rolebyte.event (id, actor, tenant_id, user_id, kind, payload)
        VALUES (util.generate_ulid(), v_actor, NULL, NULL, 'personLanguageSet',
                jsonb_build_object('subjectKey', v_subject, 'language', v_language, 'from', v_before));

        INSERT INTO rolebyte.person_setting (subject_key, language, changed_at)
        VALUES (v_subject, v_language, now())
        ON CONFLICT (subject_key) DO UPDATE
            SET language   = EXCLUDED.language,
                changed_at = EXCLUDED.changed_at;
    END IF;

    po_data := util.result_success(jsonb_build_object('language', v_language));
EXCEPTION
    WHEN sqlstate 'P0001' THEN
        RAISE;
    WHEN OTHERS THEN
        RAISE EXCEPTION '%', util.result_error('membership:error', sqlerrm) USING errcode = 'P0001';
END;
$$;

REVOKE ALL ON PROCEDURE rolebyte.person_language_set(jsonb, jsonb) FROM PUBLIC;
GRANT EXECUTE ON PROCEDURE rolebyte.person_language_set(jsonb, jsonb) TO rolebyte_public;

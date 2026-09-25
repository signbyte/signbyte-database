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
--      authenticated person", which is the identity provider's question.

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

-- tenant_create — register the paying organisation. Emits `tenantCreated`.
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

-- service_register — a consumer service registers itself (idempotent upsert).
-- Emits `serviceRegistered` only when the row is new.
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

REVOKE ALL ON PROCEDURE rolebyte.service_register(jsonb, jsonb) FROM PUBLIC;
GRANT EXECUTE ON PROCEDURE rolebyte.service_register(jsonb, jsonb) TO rolebyte_public;

-- role_define — a service defines one (group, level) role as data (idempotent
-- upsert). Emits `roleDefined` only when the row is new.
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

    -- `/` marks a permission; a role spelled like one would hand out an act
    -- nobody declared or ticked.
    IF position('/' IN v_group) > 0 THEN
        po_data := util.result_error('membership:invalid', 'a role group may not contain "/"');
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

REVOKE ALL ON PROCEDURE rolebyte.role_define(jsonb, jsonb) FROM PUBLIC;
GRANT EXECUTE ON PROCEDURE rolebyte.role_define(jsonb, jsonb) TO rolebyte_public;

-- permission_declare — a service declares one act it enforces on one of its
-- features. Additive: a new permission is created, an identical one reports
-- `unchanged`, and a changed description is updated and reports `changed`.
-- A permission's class never changes — re-classing would change who may hand
-- it out — so a declaration naming a different class is refused, naming the
-- permission. The declaration is read strictly: a property this register does
-- not know is refused rather than dropped, so a later property carrying a
-- requirement can never be stored without it. Emits `permissionDeclared` or
-- `permissionDescribed` when something changed, nothing otherwise.
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
    v_name    text;
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
    WHERE k NOT IN ('feature', 'act', 'description', 'class')
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
       OR (v_decl ? 'description' AND jsonb_typeof(v_decl->'description') IS DISTINCT FROM 'string') THEN
        po_data := util.result_error('membership:invalid',
            'feature, act and class are required strings, and description is a string');
        RETURN;
    END IF;

    v_feature := v_decl->>'feature';
    v_act     := v_decl->>'act';
    v_class   := v_decl->>'class';
    v_desc    := COALESCE(trim(v_decl->>'description'), '');

    IF NOT rolebyte.is_permission_feature(v_feature) THEN
        po_data := util.result_error('membership:invalid',
            'feature must be one or more lower-camel words joined by "/"');
        RETURN;
    END IF;
    IF NOT rolebyte.is_permission_act(v_act) THEN
        po_data := util.result_error('membership:invalid', 'act must be one lower-camel word');
        RETURN;
    END IF;
    IF v_class NOT IN ('ordinary', 'tenantConfiguration', 'roleManagement') THEN
        po_data := util.result_error('membership:invalid',
            'class must be ordinary, tenantConfiguration or roleManagement');
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
        INSERT INTO rolebyte.service_permission (id, service_key, feature_key, act, description, class)
        VALUES (util.generate_ulid(), v_service, v_feature, v_act, v_desc, v_class)
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
                    jsonb_build_object('service', v_service, 'permission', v_name, 'class', v_class));
            po_data := util.result_success(jsonb_build_object('permission', v_name, 'status', 'added'));
            RETURN;
        END IF;
    END IF;

    IF v_row.class <> v_class THEN
        po_data := util.result_error('membership:conflict',
            format('%s is declared as %s, and a permission''s class never changes', v_name, v_row.class));
        RETURN;
    END IF;

    IF v_row.description = v_desc THEN
        po_data := util.result_success(jsonb_build_object('permission', v_name, 'status', 'unchanged'));
        RETURN;
    END IF;

    UPDATE rolebyte.service_permission SET description = v_desc WHERE id = v_row.id;
    INSERT INTO rolebyte.event (id, actor, kind, payload)
    VALUES (util.generate_ulid(), v_actor, 'permissionDescribed',
            jsonb_build_object('service', v_service, 'permission', v_name,
                               'from', v_row.description, 'to', v_desc));
    po_data := util.result_success(jsonb_build_object('permission', v_name, 'status', 'changed'));
EXCEPTION
    WHEN sqlstate 'P0001' THEN
        RAISE;
    WHEN OTHERS THEN
        RAISE EXCEPTION '%', util.result_error('membership:error', sqlerrm) USING errcode = 'P0001';
END;
$$;

REVOKE ALL ON PROCEDURE rolebyte.permission_declare(jsonb, jsonb) FROM PUBLIC;
GRANT EXECUTE ON PROCEDURE rolebyte.permission_declare(jsonb, jsonb) TO rolebyte_public;

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

    INSERT INTO rolebyte.user_account (id, tenant_id, subject_key, display_name, status)
    VALUES (util.generate_ulid(), v_tenant, v_subject, v_display, 'invited')
    RETURNING * INTO v_user;

    INSERT INTO rolebyte.event (id, actor, tenant_id, user_id, kind, payload)
    VALUES (util.generate_ulid(), v_actor, v_tenant, v_user.id, 'userInvited',
            jsonb_build_object('subjectKey', v_subject, 'displayName', v_display));

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
-- member, not a role-holder, until an administrator gives them one. Emits
-- `directoryAdmitted`. Outcomes, all a success answer (refusing a login is the
-- caller's decision, and the caller's words):
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
        INSERT INTO rolebyte.user_account (id, tenant_id, subject_key, display_name, status)
        VALUES (util.generate_ulid(), v_tenant, v_subject, v_display, 'active')
        RETURNING * INTO v_user;

        INSERT INTO rolebyte.event (id, actor, tenant_id, user_id, kind, payload)
        VALUES (util.generate_ulid(), v_actor, v_tenant, v_user.id, 'directoryAdmitted',
                jsonb_build_object('subjectKey', v_subject, 'issuer', v_issuer, 'displayName', v_display));

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
CREATE OR REPLACE PROCEDURE rolebyte.user_revoke(IN pi_data jsonb, INOUT po_data jsonb)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = rolebyte, util, pg_temp
AS $$
DECLARE
    v_actor   text;
    v_tenant  text;
    v_user_id text;
BEGIN
    v_actor   := NULLIF(trim(pi_data->>'actor'), '');
    v_tenant  := NULLIF(trim(pi_data->>'tenantId'), '');
    v_user_id := NULLIF(trim(pi_data->>'userId'), '');
    IF v_actor IS NULL OR v_tenant IS NULL OR v_user_id IS NULL THEN
        po_data := util.result_error('membership:invalid', 'actor, tenantId and userId are required');
        RETURN;
    END IF;

    UPDATE rolebyte.user_account
    SET status = 'revoked'
    WHERE id = v_user_id AND tenant_id = v_tenant AND status <> 'revoked';

    IF NOT FOUND THEN
        po_data := util.result_error('membership:not_found', 'user does not exist');
        RETURN;
    END IF;

    INSERT INTO rolebyte.event (id, actor, tenant_id, user_id, kind, payload)
    VALUES (util.generate_ulid(), v_actor, v_tenant, v_user_id, 'userRevoked', '{}'::jsonb);

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
-- and each permission a tenant's own role ticks as `service/feature:act`. Reads
-- only; a stranger resolves to an empty list.
--
-- Both kinds feed ONE distinct aggregate, so a person who holds no tenant role
-- resolves exactly as before tenant roles existed, and a box ticked by two roles
-- appears once. The two kinds cannot collide: a permission always carries a `/`
-- and a role's group never does.
CREATE OR REPLACE PROCEDURE rolebyte.resolve(IN pi_data jsonb, INOUT po_data jsonb)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = rolebyte, util, pg_temp
AS $$
DECLARE
    v_subject     text;
    v_memberships jsonb;
BEGIN
    v_subject := NULLIF(trim(pi_data->>'subjectKey'), '');
    IF v_subject IS NULL THEN
        po_data := util.result_error('membership:invalid', 'subjectKey is required');
        RETURN;
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
                    UNION ALL
                    SELECT sp.service_key || '/' || sp.feature_key || ':' || sp.act
                    FROM rolebyte.tenant_role_assignment ta
                    JOIN rolebyte.tenant_role_permission tp ON tp.tenant_role_id = ta.tenant_role_id
                    JOIN rolebyte.service_permission sp ON sp.id = tp.permission_id
                    WHERE ta.user_id = u.id AND ta.tenant_id = u.tenant_id AND ta.state = 'granted'
                ) s
            ), '[]'::jsonb)
        ) AS m
        FROM rolebyte.user_account u
        JOIN rolebyte.tenant t ON t.id = u.tenant_id
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

-- history — the append-only promise made queryable: a tenant's membership
-- events in a time window, optionally narrowed to one service (the events
-- carry the service in their payload). The billing seat-count source.
CREATE OR REPLACE PROCEDURE rolebyte.history(IN pi_data jsonb, INOUT po_data jsonb)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = rolebyte, util, pg_temp
AS $$
DECLARE
    v_tenant  text;
    v_service text;
    v_from    timestamptz;
    v_to      timestamptz;
    v_events  jsonb;
BEGIN
    v_tenant := NULLIF(trim(pi_data->>'tenantId'), '');
    IF v_tenant IS NULL THEN
        po_data := util.result_error('membership:invalid', 'tenantId is required');
        RETURN;
    END IF;

    v_service := NULLIF(trim(pi_data->>'service'), '');
    v_from    := NULLIF(trim(pi_data->>'from'), '')::timestamptz;
    v_to      := NULLIF(trim(pi_data->>'to'), '')::timestamptz;

    SELECT COALESCE(jsonb_agg(jsonb_build_object(
        'id',      e.id,
        'at',      e.at,
        'actor',   e.actor,
        'userId',  COALESCE(e.user_id, ''),
        'kind',    e.kind,
        'payload', e.payload
    ) ORDER BY e.at, e.id), '[]'::jsonb)
    INTO v_events
    FROM (
        SELECT *
        FROM rolebyte.event
        WHERE tenant_id = v_tenant
          AND (v_from IS NULL OR at >= v_from)
          AND (v_to IS NULL OR at < v_to)
          AND (v_service IS NULL OR payload->>'service' = v_service)
        ORDER BY at, id
        LIMIT 1000
    ) e;

    po_data := util.result_success(jsonb_build_object('events', v_events));
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
-- travel (`<service>/<feature path>:<act>`), ordered by service, feature and act.
CREATE OR REPLACE FUNCTION rolebyte.tenant_role_permission_names(p_role_id text)
RETURNS jsonb
LANGUAGE sql
STABLE
SET search_path = rolebyte, pg_temp
AS $$
    SELECT COALESCE(jsonb_agg(sp.service_key || '/' || sp.feature_key || ':' || sp.act
                              ORDER BY sp.service_key, sp.feature_key, sp.act), '[]'::jsonb)
      FROM rolebyte.tenant_role_permission t
      JOIN rolebyte.service_permission sp ON sp.id = t.permission_id
     WHERE t.tenant_role_id = p_role_id;
$$;

REVOKE ALL ON FUNCTION rolebyte.tenant_role_permission_names(text) FROM PUBLIC;

-- tenant_role_list — the tenant's roles with what each holds, ordered by name.
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
               'name',        r.name,
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

-- tenant_role_define — the tenant makes a role: a name, an optional
-- description, and no permissions yet. A name another role of the tenant
-- already carries, in any letter case, is refused. Emits `tenantRoleDefined`.
CREATE OR REPLACE PROCEDURE rolebyte.tenant_role_define(IN pi_data jsonb, INOUT po_data jsonb)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = rolebyte, util, pg_temp
AS $$
DECLARE
    v_actor  text;
    v_tenant text;
    v_name   text;
    v_desc   text;
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

    IF NOT EXISTS (SELECT 1 FROM rolebyte.tenant WHERE id = v_tenant) THEN
        po_data := util.result_error('tenant:not_found', 'tenant does not exist');
        RETURN;
    END IF;

    IF EXISTS (SELECT 1 FROM rolebyte.tenant_role
               WHERE tenant_id = v_tenant AND lower(name) = lower(v_name)) THEN
        po_data := util.result_error('membership:conflict', 'a role with this name already exists in the tenant');
        RETURN;
    END IF;

    INSERT INTO rolebyte.tenant_role (id, tenant_id, name, description)
    VALUES (util.generate_ulid(), v_tenant, v_name, v_desc)
    RETURNING * INTO v_row;

    INSERT INTO rolebyte.event (id, actor, tenant_id, kind, payload)
    VALUES (util.generate_ulid(), v_actor, v_tenant, 'tenantRoleDefined',
            jsonb_build_object('roleId', v_row.id, 'name', v_row.name, 'description', v_row.description));

    po_data := util.result_success(jsonb_build_object(
        'id',          v_row.id,
        'name',        v_row.name,
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

-- tenant_role_update — rename a role and change its description. An absent
-- description keeps the one there; an empty one clears it. Changing nothing
-- records nothing. Emits `tenantRoleRenamed` for a new name and
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
    v_desc    text;
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

    SELECT * INTO v_row
      FROM rolebyte.tenant_role
     WHERE id = v_role AND tenant_id = v_tenant
       FOR UPDATE;
    IF NOT FOUND THEN
        po_data := util.result_error('membership:not_found', 'role does not exist');
        RETURN;
    END IF;

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

    IF v_name <> v_row.name OR v_desc <> v_row.description THEN
        UPDATE rolebyte.tenant_role SET name = v_name, description = v_desc WHERE id = v_row.id;
        v_changed := true;
    END IF;

    IF v_name <> v_row.name THEN
        INSERT INTO rolebyte.event (id, actor, tenant_id, kind, payload)
        VALUES (util.generate_ulid(), v_actor, v_tenant, 'tenantRoleRenamed',
                jsonb_build_object('roleId', v_row.id, 'from', v_row.name, 'to', v_name));
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

-- tenant_role_permissions_set — replace what a role holds with the given set of
-- permission names, and answer the difference. The whole list is checked before
-- anything is written: one name that is not a declared permission refuses the
-- call and the set stays as it was. A name given twice counts once; an empty
-- list clears the role. The same set again changes nothing and records nothing.
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
    v_slash   int;
    v_colon   int;
    v_service text;
    v_feature text;
    v_act     text;
    v_pid     text;
    v_ids     text[] := '{}'::text[];
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
        v_slash := position('/' IN v_perm);
        v_colon := position(':' IN v_perm);
        IF v_slash = 0 OR v_colon < v_slash THEN
            po_data := util.result_error('membership:unknown_permission', 'an entry is not a permission name');
            RETURN;
        END IF;
        v_service := left(v_perm, v_slash - 1);
        v_feature := substr(v_perm, v_slash + 1, v_colon - v_slash - 1);
        v_act     := substr(v_perm, v_colon + 1);
        IF rolebyte.is_permission_service(v_service) IS NOT TRUE
           OR rolebyte.is_permission_feature(v_feature) IS NOT TRUE
           OR rolebyte.is_permission_act(v_act) IS NOT TRUE THEN
            po_data := util.result_error('membership:unknown_permission', 'an entry is not a permission name');
            RETURN;
        END IF;

        SELECT id INTO v_pid
          FROM rolebyte.service_permission
         WHERE service_key = v_service AND feature_key = v_feature AND act = v_act;
        IF v_pid IS NULL THEN
            po_data := util.result_error('membership:unknown_permission',
                format('%s is not a declared permission', v_perm));
            RETURN;
        END IF;
        v_ids := array_append(v_ids, v_pid);
    END LOOP;

    SELECT COALESCE(jsonb_agg(sp.service_key || '/' || sp.feature_key || ':' || sp.act
                              ORDER BY sp.service_key, sp.feature_key, sp.act), '[]'::jsonb)
      INTO v_added
      FROM rolebyte.service_permission sp
     WHERE sp.id = ANY (v_ids)
       AND NOT EXISTS (SELECT 1 FROM rolebyte.tenant_role_permission t
                       WHERE t.tenant_role_id = v_row.id AND t.permission_id = sp.id);

    SELECT COALESCE(jsonb_agg(sp.service_key || '/' || sp.feature_key || ':' || sp.act
                              ORDER BY sp.service_key, sp.feature_key, sp.act), '[]'::jsonb)
      INTO v_removed
      FROM rolebyte.tenant_role_permission t
      JOIN rolebyte.service_permission sp ON sp.id = t.permission_id
     WHERE t.tenant_role_id = v_row.id
       AND NOT (t.permission_id = ANY (v_ids));

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

    DELETE FROM rolebyte.tenant_role_permission
     WHERE tenant_role_id = v_row.id
       AND NOT (permission_id = ANY (v_ids));

    INSERT INTO rolebyte.tenant_role_permission (tenant_role_id, permission_id)
    SELECT v_row.id, p FROM unnest(v_ids) AS p
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

-- tenant_role_delete — remove a role nobody holds. A role held by any member
-- whose access has not been revoked is refused with the count: deleting it
-- would take access away from people with no way back. The role's ticks and its
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
    v_perms  jsonb;
BEGIN
    v_actor  := NULLIF(trim(pi_data->>'actor'), '');
    v_tenant := NULLIF(trim(pi_data->>'tenantId'), '');
    v_role   := NULLIF(trim(pi_data->>'roleId'), '');
    IF v_actor IS NULL OR v_tenant IS NULL OR v_role IS NULL THEN
        po_data := util.result_error('membership:invalid', 'actor, tenantId and roleId are required');
        RETURN;
    END IF;

    -- The lock also holds off a grant of this role until the delete has decided.
    SELECT * INTO v_row
      FROM rolebyte.tenant_role
     WHERE id = v_role AND tenant_id = v_tenant
       FOR UPDATE;
    IF NOT FOUND THEN
        po_data := util.result_error('membership:not_found', 'role does not exist');
        RETURN;
    END IF;

    SELECT count(*) INTO v_held
      FROM rolebyte.tenant_role_assignment a
      JOIN rolebyte.user_account u ON u.id = a.user_id
     WHERE a.tenant_role_id = v_row.id
       AND a.state = 'granted'
       AND u.status <> 'revoked';
    IF v_held > 0 THEN
        po_data := util.result_error('membership:conflict',
            format('this role is held by %s %s; revoke it from them first',
                   v_held, CASE WHEN v_held = 1 THEN 'person' ELSE 'people' END));
        RETURN;
    END IF;

    v_perms := rolebyte.tenant_role_permission_names(v_row.id);

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
-- Configuration transport. The vocabulary (services with their role
-- definitions and the permissions they declare) and the tenant's display name
-- travel in a configuration document. The vocabulary is shared by every tenant on a deployment, so a
-- document only ever ADDS to it — defining what is missing, reporting what
-- is already present — and never removes: retiring a role people may hold
-- somewhere is an administration act performed in place, not a side effect
-- of importing a file. People and their assignments never travel at all.
-- ---------------------------------------------------------------------------

-- config_get — the vocabulary as it travels: every service with its role
-- definitions and its permissions, plus the asking tenant's display name.
CREATE OR REPLACE PROCEDURE rolebyte.config_get(IN pi_data jsonb, INOUT po_data jsonb)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = rolebyte, util, pg_temp
AS $$
DECLARE
    v_tenant   text := NULLIF(trim(pi_data->>'tenantId'), '');
    v_name     text;
    v_dir      text;
    v_services jsonb;
BEGIN
    IF v_tenant IS NULL THEN
        po_data := util.result_error('membership:invalid', 'tenantId is required');
        RETURN;
    END IF;

    SELECT name, directory_issuer INTO v_name, v_dir FROM rolebyte.tenant WHERE id = v_tenant;
    IF v_name IS NULL THEN
        po_data := util.result_error('membership:not_found', 'no such tenant');
        RETURN;
    END IF;

    SELECT COALESCE(jsonb_agg(jsonb_build_object(
               'key',         s.key,
               'displayName', s.display_name,
               'roles', (
                   SELECT COALESCE(jsonb_agg(jsonb_build_object(
                              'group',       d.role_group,
                              'level',       d.role_level,
                              'description', d.description)
                              ORDER BY d.role_group, d.role_level), '[]'::jsonb)
                   FROM rolebyte.role_definition d
                   WHERE d.service_key = s.key),
               'permissions', (
                   SELECT COALESCE(jsonb_agg(jsonb_build_object(
                              'feature',     p.feature_key,
                              'act',         p.act,
                              'description', p.description,
                              'class',       p.class)
                              ORDER BY p.feature_key, p.act), '[]'::jsonb)
                   FROM rolebyte.service_permission p
                   WHERE p.service_key = s.key))
               ORDER BY s.key), '[]'::jsonb)
    INTO v_services
    FROM rolebyte.service s;

    -- The tenant's attached directory travels with its display name: an address,
    -- not a secret, and part of what makes a tenant ready to use.
    po_data := util.result_success(jsonb_build_object(
        'tenant',   jsonb_build_object(
                        'displayName', v_name,
                        'directory',   CASE WHEN v_dir IS NULL THEN NULL::jsonb
                                            ELSE jsonb_build_object('issuer', v_dir) END),
        'services', v_services));
EXCEPTION
    WHEN sqlstate 'P0001' THEN RAISE;
    WHEN OTHERS THEN
        RAISE EXCEPTION '%', util.result_error('membership:error', sqlerrm) USING errcode = 'P0001';
END;
$$;

REVOKE ALL ON PROCEDURE rolebyte.config_get(jsonb, jsonb) FROM PUBLIC;
GRANT EXECUTE ON PROCEDURE rolebyte.config_get(jsonb, jsonb) TO rolebyte_public;

-- config_apply — apply one vocabulary section, additive and atomic: missing
-- services and role definitions are created (through the same registering
-- procedures every other caller uses, so the events land identically),
-- present ones are reported unchanged, and the tenant's display name is
-- updated when the document carries a different one.
CREATE OR REPLACE PROCEDURE rolebyte.config_apply(IN pi_data jsonb, INOUT po_data jsonb)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = rolebyte, util, pg_temp
AS $$
DECLARE
    v_tenant   text := NULLIF(trim(pi_data->>'tenantId'), '');
    v_actor    text := NULLIF(trim(pi_data->>'actor'), '');
    v_section  jsonb := pi_data->'section';
    v_svc      jsonb;
    v_role     jsonb;
    v_perm     jsonb;
    v_out      jsonb;
    v_key      text;
    v_name     text;
    v_new_name text;
    v_svc_r    jsonb := '[]'::jsonb;
    v_roles_r  jsonb := '[]'::jsonb;
    v_perms_r  jsonb := '[]'::jsonb;
    v_tenant_r jsonb := 'null'::jsonb;
    v_new_dir  text;
    v_dir_r    jsonb;
BEGIN
    IF v_tenant IS NULL OR v_actor IS NULL THEN
        po_data := util.result_error('membership:invalid', 'tenantId and actor are required');
        RETURN;
    END IF;
    IF jsonb_typeof(v_section) IS DISTINCT FROM 'object' THEN
        po_data := util.result_error('membership:config_bad_document', 'section must be an object');
        RETURN;
    END IF;

    SELECT name INTO v_name FROM rolebyte.tenant WHERE id = v_tenant;
    IF v_name IS NULL THEN
        po_data := util.result_error('membership:not_found', 'no such tenant');
        RETURN;
    END IF;

    IF v_section ? 'services' THEN
        IF jsonb_typeof(v_section->'services') IS DISTINCT FROM 'array' THEN
            po_data := util.result_error('membership:config_bad_document', 'services must be an array');
            RETURN;
        END IF;
        FOR v_svc IN SELECT * FROM jsonb_array_elements(v_section->'services') LOOP
            v_key := NULLIF(trim(v_svc->>'key'), '');
            IF v_key IS NULL THEN
                RAISE EXCEPTION '%', util.result_error('membership:config_bad_document', 'a service entry is missing its key') USING errcode = 'P0001';
            END IF;

            v_out := NULL;
            CALL rolebyte.service_register(jsonb_build_object(
                'actor',       v_actor,
                'service',     v_key,
                'displayName', v_svc->>'displayName'), v_out);
            IF v_out->>'result' IS DISTINCT FROM 'success' THEN
                RAISE EXCEPTION '%', v_out USING errcode = 'P0001';
            END IF;
            v_svc_r := v_svc_r || jsonb_build_object(
                'key',    v_key,
                'status', CASE WHEN (v_out->'data'->>'created')::boolean THEN 'added' ELSE 'unchanged' END);

            FOR v_role IN SELECT * FROM jsonb_array_elements(COALESCE(v_svc->'roles', '[]'::jsonb)) LOOP
                v_out := NULL;
                CALL rolebyte.role_define(jsonb_build_object(
                    'actor',       v_actor,
                    'service',     v_key,
                    'group',       v_role->>'group',
                    'level',       v_role->>'level',
                    'description', v_role->>'description'), v_out);
                IF v_out->>'result' IS DISTINCT FROM 'success' THEN
                    RAISE EXCEPTION '%', v_out USING errcode = 'P0001';
                END IF;
                v_roles_r := v_roles_r || jsonb_build_object(
                    'service', v_key,
                    'group',   v_role->>'group',
                    'level',   v_role->>'level',
                    'status',  CASE WHEN (v_out->'data'->>'created')::boolean THEN 'added' ELSE 'unchanged' END);
            END LOOP;

            -- The service's permissions, declared through the same procedure a
            -- direct declaration uses so the events land identically; one refused
            -- entry rolls the whole section back.
            IF v_svc ? 'permissions' AND jsonb_typeof(v_svc->'permissions') IS DISTINCT FROM 'array' THEN
                RAISE EXCEPTION '%', util.result_error('membership:config_bad_document',
                    format('the permissions of service %s must be an array', v_key)) USING errcode = 'P0001';
            END IF;
            FOR v_perm IN SELECT * FROM jsonb_array_elements(COALESCE(v_svc->'permissions', '[]'::jsonb)) LOOP
                v_out := NULL;
                CALL rolebyte.permission_declare(jsonb_build_object(
                    'actor',      v_actor,
                    'service',    v_key,
                    'permission', v_perm), v_out);
                IF v_out->>'result' IS DISTINCT FROM 'success' THEN
                    RAISE EXCEPTION '%', v_out USING errcode = 'P0001';
                END IF;
                v_perms_r := v_perms_r || jsonb_build_object(
                    'service',    v_key,
                    'permission', v_out->'data'->>'permission',
                    'status',     v_out->'data'->>'status');
            END LOOP;
        END LOOP;
    END IF;

    v_new_name := NULLIF(trim(v_section->'tenant'->>'displayName'), '');
    IF v_new_name IS NOT NULL THEN
        IF v_new_name = v_name THEN
            v_tenant_r := jsonb_build_object('status', 'unchanged');
        ELSE
            UPDATE rolebyte.tenant SET name = v_new_name WHERE id = v_tenant;
            INSERT INTO rolebyte.event (id, actor, tenant_id, kind, payload)
            VALUES (util.generate_ulid(), v_actor, v_tenant, 'tenantRenamed',
                    jsonb_build_object('from', v_name, 'to', v_new_name));
            v_tenant_r := jsonb_build_object('status', 'changed', 'from', v_name, 'to', v_new_name);
        END IF;
    END IF;

    -- The attached directory follows the document too, through the same
    -- administration procedure a direct attach uses, so the event lands
    -- identically. A document never detaches: an absent or empty directory
    -- leaves the tenant's as it is (removal is an in-place administration act).
    IF jsonb_typeof(v_section->'tenant'->'directory') = 'object' THEN
        v_new_dir := NULLIF(trim(v_section->'tenant'->'directory'->>'issuer'), '');
        IF v_new_dir IS NOT NULL THEN
            v_out := NULL;
            CALL rolebyte.directory_attach(jsonb_build_object(
                'actor', v_actor, 'tenantId', v_tenant, 'issuer', v_new_dir), v_out);
            IF v_out->>'result' IS DISTINCT FROM 'success' THEN
                RAISE EXCEPTION '%', v_out USING errcode = 'P0001';
            END IF;
            v_dir_r := jsonb_build_object(
                'status', CASE WHEN (v_out->'data'->>'changed')::boolean THEN 'changed' ELSE 'unchanged' END,
                'issuer', v_new_dir);
        END IF;
    END IF;
    IF v_dir_r IS NOT NULL THEN
        v_tenant_r := COALESCE(NULLIF(v_tenant_r, 'null'::jsonb), '{}'::jsonb)
                      || jsonb_build_object('directory', v_dir_r);
    END IF;

    po_data := util.result_success(jsonb_build_object(
        'services',    v_svc_r,
        'roles',       v_roles_r,
        'permissions', v_perms_r,
        'tenant',      v_tenant_r));
EXCEPTION
    WHEN sqlstate 'P0001' THEN
        RAISE;
    WHEN OTHERS THEN
        RAISE EXCEPTION '%', util.result_error('membership:error', sqlerrm) USING errcode = 'P0001';
END;
$$;

REVOKE ALL ON PROCEDURE rolebyte.config_apply(jsonb, jsonb) FROM PUBLIC;
GRANT EXECUTE ON PROCEDURE rolebyte.config_apply(jsonb, jsonb) TO rolebyte_public;

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

    v_subject := NULLIF(trim(pi_data->>'subjectKey'), '');
    IF v_subject IS NULL OR position(':' in v_subject) = 0 THEN
        po_data := util.result_error('membership:invalid', 'subjectKey is required and must be typed (e.g. pno:<code>)');
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
-- subject key answers the memberships it may act under, each with the
-- `group:level` scope set from currently granted assignments. Reads only;
-- a stranger resolves to an empty list.
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
-- Configuration transport. The role vocabulary (services and their role
-- definitions) and the tenant's display name travel in a configuration
-- document. The vocabulary is shared by every tenant on a deployment, so a
-- document only ever ADDS to it — defining what is missing, reporting what
-- is already present — and never removes: retiring a role people may hold
-- somewhere is an administration act performed in place, not a side effect
-- of importing a file. People and their assignments never travel at all.
-- ---------------------------------------------------------------------------

-- config_get — the vocabulary as it travels: every service with its role
-- definitions, plus the asking tenant's display name.
CREATE OR REPLACE PROCEDURE rolebyte.config_get(IN pi_data jsonb, INOUT po_data jsonb)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = rolebyte, util, pg_temp
AS $$
DECLARE
    v_tenant   text := NULLIF(trim(pi_data->>'tenantId'), '');
    v_name     text;
    v_services jsonb;
BEGIN
    IF v_tenant IS NULL THEN
        po_data := util.result_error('membership:invalid', 'tenantId is required');
        RETURN;
    END IF;

    SELECT name INTO v_name FROM rolebyte.tenant WHERE id = v_tenant;
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
                   WHERE d.service_key = s.key))
               ORDER BY s.key), '[]'::jsonb)
    INTO v_services
    FROM rolebyte.service s;

    po_data := util.result_success(jsonb_build_object(
        'tenant',   jsonb_build_object('displayName', v_name),
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
    v_out      jsonb;
    v_key      text;
    v_name     text;
    v_new_name text;
    v_svc_r    jsonb := '[]'::jsonb;
    v_roles_r  jsonb := '[]'::jsonb;
    v_tenant_r jsonb := 'null'::jsonb;
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

    po_data := util.result_success(jsonb_build_object(
        'services', v_svc_r,
        'roles',    v_roles_r,
        'tenant',   v_tenant_r));
EXCEPTION
    WHEN sqlstate 'P0001' THEN
        RAISE;
    WHEN OTHERS THEN
        RAISE EXCEPTION '%', util.result_error('membership:error', sqlerrm) USING errcode = 'P0001';
END;
$$;

REVOKE ALL ON PROCEDURE rolebyte.config_apply(jsonb, jsonb) FROM PUBLIC;
GRANT EXECUTE ON PROCEDURE rolebyte.config_apply(jsonb, jsonb) TO rolebyte_public;

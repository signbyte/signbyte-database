-- Assistants: named machine members, each one person's own, through which that
-- person connects an AI app.
--
-- An administrator adds an assistant for one person (the register mints its
-- key), chosen then and never changed after, names and renames it, and gives it
-- roles as a person's are given; a person may have several. The first assistant of a
-- tenant brings the shipped Assistant role, holding what the services declared
-- for the seed `assistant`, and every new assistant starts in it. The sign-in
-- service asks for a person's own assistants when the person connects an app,
-- and again at every refresh.
--
-- The file keeps the name it had when assistants were called helpers: Flyway
-- records every repeatable file it applied, and checks that each is still there.

-- ---------------------------------------------------------------------------
-- assistant_role — the tenant's Assistant role, made the first time a tenant
-- needs it, by the rule the shipped roles follow (seed_roles): a tenant keeps
-- what it has, so where one of its own roles already has the name, or reads so in
-- a language the app speaks, no role is made and the answer is NULL. Ticked with
-- every permission declared for the seed `assistant` and not retired. Emits
-- `tenantRoleSeeded`. A helper for assistant_create; no service may call it.
-- ---------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION rolebyte.assistant_role(p_actor text, p_tenant text)
RETURNS text
LANGUAGE plpgsql
SET search_path = rolebyte, util, pg_temp
AS $$
DECLARE
    v_id     text;
    v_name   text := 'Assistant';
    v_labels jsonb := '{}'::jsonb;
    v_desc   text := 'What an assistant starts with: sees projects and tasks, adds and edits tasks, moves its person''s own, comments.';
BEGIN
    SELECT id INTO v_id FROM rolebyte.tenant_role WHERE tenant_id = p_tenant AND seed = 'assistant';
    IF v_id IS NOT NULL THEN
        RETURN v_id;
    END IF;
    IF EXISTS (SELECT 1 FROM rolebyte.tenant_role r WHERE r.tenant_id = p_tenant AND lower(r.name) = lower(v_name))
       OR rolebyte.tenant_role_reads_alike(p_tenant, NULL, v_name, '{}'::jsonb) IS NOT NULL THEN
        RETURN NULL;
    END IF;
    IF 'lv' = ANY (util.app_languages()) THEN
        v_labels := jsonb_build_object('lv', 'Asistents');
        IF rolebyte.tenant_role_reads_alike(p_tenant, NULL, v_name, v_labels) IS NOT NULL THEN
            v_labels := '{}'::jsonb;
        END IF;
    END IF;

    v_id := util.generate_ulid();
    INSERT INTO rolebyte.tenant_role (id, tenant_id, name, labels, description, seed)
    VALUES (v_id, p_tenant, v_name, v_labels, v_desc, 'assistant');
    INSERT INTO rolebyte.tenant_role_permission (tenant_role_id, permission_id)
    SELECT v_id, sp.id
      FROM rolebyte.service_permission sp
     WHERE 'assistant' = ANY (sp.seeds) AND sp.retired_at IS NULL;
    INSERT INTO rolebyte.event (id, actor, tenant_id, kind, payload)
    VALUES (util.generate_ulid(), p_actor, p_tenant, 'tenantRoleSeeded',
            jsonb_build_object('roleId', v_id, 'seed', 'assistant', 'name', v_name, 'labels', v_labels,
                               'permissions', COALESCE((
                                   SELECT jsonb_agg(sp.service_key || '/' || sp.feature_key || ':' || sp.act
                                                    ORDER BY sp.service_key, sp.feature_key, sp.act)
                                     FROM rolebyte.tenant_role_permission t
                                     JOIN rolebyte.service_permission sp ON sp.id = t.permission_id
                                    WHERE t.tenant_role_id = v_id), '[]'::jsonb)));
    RETURN v_id;
END;
$$;

REVOKE ALL ON FUNCTION rolebyte.assistant_role(text, text) FROM PUBLIC;

-- assistant_json — an assistant as every answer names it.
CREATE OR REPLACE FUNCTION rolebyte.assistant_json(v rolebyte.user_account)
RETURNS jsonb
LANGUAGE sql
STABLE
SET search_path = rolebyte, pg_temp
AS $$
    SELECT jsonb_build_object('id', v.id, 'subjectKey', v.subject_key, 'name', v.display_name, 'status', v.status);
$$;

REVOKE ALL ON FUNCTION rolebyte.assistant_json(rolebyte.user_account) FROM PUBLIC;

-- assistant_person_json — an assistant's person as an answer names them, or
-- JSON null for an assistant that serves nobody.
CREATE OR REPLACE FUNCTION rolebyte.assistant_person_json(p_assistant text)
RETURNS jsonb
LANGUAGE sql
STABLE
SET search_path = rolebyte, pg_temp
AS $$
    SELECT COALESCE((SELECT jsonb_build_object('id', p.id, 'subjectKey', p.subject_key, 'displayName', p.display_name)
                       FROM rolebyte.assistant_person a JOIN rolebyte.user_account p ON p.id = a.user_id
                      WHERE a.assistant_id = p_assistant), 'null'::jsonb);
$$;

REVOKE ALL ON FUNCTION rolebyte.assistant_person_json(text) FROM PUBLIC;

-- assistant_name_taken — whether another assistant of the tenant, not removed,
-- has the name, ignoring case.
CREATE OR REPLACE FUNCTION rolebyte.assistant_name_taken(p_tenant text, p_name text, p_except text)
RETURNS boolean
LANGUAGE sql
STABLE
SET search_path = rolebyte, pg_temp
AS $$
    SELECT EXISTS (SELECT 1 FROM rolebyte.user_account u
                    WHERE u.tenant_id = p_tenant
                      AND u.subject_key LIKE 'svc:assistant-%'
                      AND u.status <> 'revoked'
                      AND lower(u.display_name) = lower(p_name)
                      AND u.id IS DISTINCT FROM p_except);
$$;

REVOKE ALL ON FUNCTION rolebyte.assistant_name_taken(text, text, text) FROM PUBLIC;

-- assistant_person_of — the member id an input names as an assistant's person
-- when it is an active person of the tenant, else NULL: one id, given as a
-- string; never a list, a machine, someone not yet or no longer active, or a
-- member of another tenant.
CREATE OR REPLACE FUNCTION rolebyte.assistant_person_of(p_tenant text, p_person jsonb)
RETURNS text
LANGUAGE sql
STABLE
SET search_path = rolebyte, pg_temp
AS $$
    SELECT u.id FROM rolebyte.user_account u
     WHERE jsonb_typeof(p_person) = 'string'
       AND u.id = p_person #>> '{}' AND u.tenant_id = p_tenant
       AND u.subject_key LIKE 'sub:%' AND u.status = 'active';
$$;

REVOKE ALL ON FUNCTION rolebyte.assistant_person_of(text, jsonb) FROM PUBLIC;

-- assistant_create — add an assistant to the tenant for one person: the
-- register mints its key, it is active at once, it has the tenant's default
-- user type as every member does, and it starts in the Assistant role (none
-- where the tenant keeps a role of its own by that name). Input {actor,
-- tenantId, name, personId}. Answers the assistant, its person and its starting
-- role, or `role: null`. Emits `assistantAdded`, and the role's own events.
CREATE OR REPLACE PROCEDURE rolebyte.assistant_create(IN pi_data jsonb, INOUT po_data jsonb)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = rolebyte, util, pg_temp
AS $$
DECLARE
    v_actor  text := NULLIF(btrim(pi_data->>'actor'), '');
    v_tenant text := NULLIF(btrim(pi_data->>'tenantId'), '');
    v_name   text := btrim(COALESCE(pi_data->>'name', ''));
    v_type   text;
    v_person text;
    v_row    rolebyte.user_account%ROWTYPE;
    v_role   text;
    v_in     jsonb;
    v_out    jsonb;
BEGIN
    IF v_actor IS NULL OR v_tenant IS NULL THEN
        po_data := util.result_error('membership:invalid', 'actor and tenantId are required');
        RETURN;
    END IF;
    IF NOT rolebyte.is_tenant_role_name(v_name) THEN
        po_data := util.result_error('membership:invalid', 'an assistant''s name is 1 to 100 characters on one line');
        RETURN;
    END IF;
    -- Held as every act naming the tenant's roles holds it, so two assistants
    -- added at once cannot both take a name, nor both make the Assistant role.
    SELECT default_user_type_id INTO v_type FROM rolebyte.tenant WHERE id = v_tenant AND status = 'active' FOR UPDATE;
    IF NOT FOUND THEN
        po_data := util.result_error('membership:not_found', 'tenant does not exist');
        RETURN;
    END IF;
    v_person := rolebyte.assistant_person_of(v_tenant, pi_data->'personId');
    IF v_person IS NULL THEN
        po_data := util.result_error('membership:invalid', 'an assistant is made for one active person of this tenant');
        RETURN;
    END IF;
    IF rolebyte.assistant_name_taken(v_tenant, v_name, NULL) THEN
        po_data := util.result_error('membership:conflict', format('another assistant here is named %s', v_name));
        RETURN;
    END IF;

    INSERT INTO rolebyte.user_account (id, tenant_id, subject_key, display_name, status, user_type_id, user_type_source)
    VALUES (util.generate_ulid(), v_tenant, 'svc:assistant-' || util.generate_ulid(), v_name, 'active', v_type,
            'workspaceDefault')
    RETURNING * INTO v_row;
    INSERT INTO rolebyte.assistant_person (tenant_id, assistant_id, user_id) VALUES (v_tenant, v_row.id, v_person);
    INSERT INTO rolebyte.event (id, actor, tenant_id, user_id, kind, payload)
    VALUES (util.generate_ulid(), v_actor, v_tenant, v_row.id, 'assistantAdded',
            jsonb_build_object('subjectKey', v_row.subject_key, 'name', v_name, 'personId', v_person));

    v_role := rolebyte.assistant_role(v_actor, v_tenant);
    IF v_role IS NOT NULL THEN
        v_in := jsonb_build_object('actor', v_actor, 'tenantId', v_tenant, 'userId', v_row.id, 'roleId', v_role);
        CALL rolebyte.tenant_role_grant(v_in, v_out);
        IF v_out->>'result' IS DISTINCT FROM 'success' THEN
            RAISE EXCEPTION '%', v_out::text USING errcode = 'P0001';
        END IF;
    END IF;

    po_data := util.result_success(rolebyte.assistant_json(v_row)
        || jsonb_build_object('person', rolebyte.assistant_person_json(v_row.id), 'role',
        (SELECT jsonb_build_object('id', r.id, 'name', r.name, 'seed', r.seed)
           FROM rolebyte.tenant_role r WHERE r.id = v_role)));
EXCEPTION
    WHEN sqlstate 'P0001' THEN RAISE;
    WHEN OTHERS THEN
        RAISE EXCEPTION '%', util.result_error('membership:error', sqlerrm) USING errcode = 'P0001';
END;
$$;

REVOKE ALL ON PROCEDURE rolebyte.assistant_create(jsonb, jsonb) FROM PUBLIC;
GRANT EXECUTE ON PROCEDURE rolebyte.assistant_create(jsonb, jsonb) TO rolebyte_public;

-- assistant_rename — give an assistant of the tenant, not removed, another name.
-- Its key, roles and person stay as they were; history names it by the new name,
-- since a line keeps the key. The same name again changes nothing and records
-- nothing. Input {actor, tenantId, userId, name}. Emits `assistantRenamed`
-- {from, to}.
CREATE OR REPLACE PROCEDURE rolebyte.assistant_rename(IN pi_data jsonb, INOUT po_data jsonb)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = rolebyte, util, pg_temp
AS $$
DECLARE
    v_actor  text := NULLIF(btrim(pi_data->>'actor'), '');
    v_tenant text := NULLIF(btrim(pi_data->>'tenantId'), '');
    v_user   text := NULLIF(btrim(pi_data->>'userId'), '');
    v_name   text := btrim(COALESCE(pi_data->>'name', ''));
    v_row    rolebyte.user_account%ROWTYPE;
    v_from   text;
BEGIN
    IF v_actor IS NULL OR v_tenant IS NULL OR v_user IS NULL THEN
        po_data := util.result_error('membership:invalid', 'actor, tenantId and userId are required');
        RETURN;
    END IF;
    IF NOT rolebyte.is_tenant_role_name(v_name) THEN
        po_data := util.result_error('membership:invalid', 'an assistant''s name is 1 to 100 characters on one line');
        RETURN;
    END IF;
    PERFORM 1 FROM rolebyte.tenant WHERE id = v_tenant FOR UPDATE;
    SELECT * INTO v_row FROM rolebyte.user_account
     WHERE id = v_user AND tenant_id = v_tenant AND subject_key LIKE 'svc:assistant-%' AND status <> 'revoked'
       FOR UPDATE;
    IF NOT FOUND THEN
        po_data := util.result_error('membership:not_found', 'assistant does not exist');
        RETURN;
    END IF;
    IF v_row.display_name = v_name THEN
        po_data := util.result_success(rolebyte.assistant_json(v_row) || jsonb_build_object('changed', false));
        RETURN;
    END IF;
    IF rolebyte.assistant_name_taken(v_tenant, v_name, v_row.id) THEN
        po_data := util.result_error('membership:conflict', format('another assistant here is named %s', v_name));
        RETURN;
    END IF;

    v_from := v_row.display_name;
    UPDATE rolebyte.user_account SET display_name = v_name WHERE id = v_row.id RETURNING * INTO v_row;
    INSERT INTO rolebyte.event (id, actor, tenant_id, user_id, kind, payload)
    VALUES (util.generate_ulid(), v_actor, v_tenant, v_row.id, 'assistantRenamed',
            jsonb_build_object('from', v_from, 'to', v_name));
    po_data := util.result_success(rolebyte.assistant_json(v_row) || jsonb_build_object('changed', true));
EXCEPTION
    WHEN sqlstate 'P0001' THEN RAISE;
    WHEN OTHERS THEN
        RAISE EXCEPTION '%', util.result_error('membership:error', sqlerrm) USING errcode = 'P0001';
END;
$$;

REVOKE ALL ON PROCEDURE rolebyte.assistant_rename(jsonb, jsonb) FROM PUBLIC;
GRANT EXECUTE ON PROCEDURE rolebyte.assistant_rename(jsonb, jsonb) TO rolebyte_public;

-- assistant_list — the tenant's assistants, every one ever added, removed ones
-- included, so history keeps naming them; by name. With `userId`, that one
-- assistant alone (not found otherwise); with `withPerson`, each whole, for the
-- administrator: its person, when it was added, and when it was removed (null
-- while it is not), read from its removal's own line in the register's history.
-- Input {tenantId, userId?, withPerson?}.
CREATE OR REPLACE PROCEDURE rolebyte.assistant_list(IN pi_data jsonb, INOUT po_data jsonb)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = rolebyte, util, pg_temp
AS $$
DECLARE
    v_tenant text := NULLIF(btrim(pi_data->>'tenantId'), '');
    v_user   text := NULLIF(btrim(pi_data->>'userId'), '');
    v_with   boolean := COALESCE((pi_data->>'withPerson')::boolean, false);
    v_items  jsonb;
BEGIN
    IF v_tenant IS NULL THEN
        po_data := util.result_error('membership:invalid', 'tenantId is required');
        RETURN;
    END IF;
    SELECT COALESCE(jsonb_agg(rolebyte.assistant_json(u)
               || CASE WHEN v_with THEN jsonb_build_object(
                      'person',    rolebyte.assistant_person_json(u.id),
                      'addedAt',   u.created_at,
                      'removedAt', CASE WHEN u.status = 'revoked' THEN
                                       (SELECT max(e.at) FROM rolebyte.event e
                                         WHERE e.user_id = u.id AND e.tenant_id = u.tenant_id AND e.kind = 'userRevoked')
                                   END)
                  ELSE '{}'::jsonb END
           ORDER BY lower(u.display_name), u.id), '[]'::jsonb)
      INTO v_items
      FROM rolebyte.user_account u
     WHERE u.tenant_id = v_tenant AND u.subject_key LIKE 'svc:assistant-%'
       AND (v_user IS NULL OR u.id = v_user);
    IF v_user IS NOT NULL AND jsonb_array_length(v_items) = 0 THEN
        po_data := util.result_error('membership:not_found', 'assistant does not exist');
        RETURN;
    END IF;
    po_data := util.result_success(jsonb_build_object('items', v_items));
EXCEPTION
    WHEN sqlstate 'P0001' THEN RAISE;
    WHEN OTHERS THEN
        RAISE EXCEPTION '%', util.result_error('membership:error', sqlerrm) USING errcode = 'P0001';
END;
$$;

REVOKE ALL ON PROCEDURE rolebyte.assistant_list(jsonb, jsonb) FROM PUBLIC;
GRANT EXECUTE ON PROCEDURE rolebyte.assistant_list(jsonb, jsonb) TO rolebyte_public;

-- assistants_of_person — a person's own assistants, for the sign-in service when
-- the person connects an app and at every refresh: each active assistant whose
-- person is the person's active membership of an active tenant, with the tenant,
-- the person's member id there, and the assistant by key and name. What the app
-- may do through each is the sign-in door's to work out from both members'
-- boxes. Input {subjectKey (the person's)}; none is an empty list.
CREATE OR REPLACE PROCEDURE rolebyte.assistants_of_person(IN pi_data jsonb, INOUT po_data jsonb)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = rolebyte, util, pg_temp
AS $$
DECLARE
    v_person text := NULLIF(btrim(pi_data->>'subjectKey'), '');
    v_items  jsonb;
BEGIN
    IF v_person IS NULL OR v_person NOT LIKE 'sub:_%' THEN
        po_data := util.result_error('membership:invalid', 'only a person has assistants');
        RETURN;
    END IF;
    SELECT COALESCE(jsonb_agg(jsonb_build_object('tenantId', t.id, 'tenantName', t.name, 'userId', p.id,
                                                 'assistantUserId', a.id, 'assistant', a.subject_key, 'name', a.display_name)
                              ORDER BY lower(t.name), t.id, lower(a.display_name), a.id), '[]'::jsonb)
      INTO v_items
      FROM rolebyte.user_account p
      JOIN rolebyte.tenant t            ON t.id = p.tenant_id AND t.status = 'active'
      JOIN rolebyte.assistant_person ap ON ap.user_id = p.id
      JOIN rolebyte.user_account a      ON a.id = ap.assistant_id AND a.tenant_id = p.tenant_id AND a.status = 'active'
     WHERE p.subject_key = v_person AND p.status = 'active';
    po_data := util.result_success(jsonb_build_object('items', v_items));
EXCEPTION
    WHEN sqlstate 'P0001' THEN RAISE;
    WHEN OTHERS THEN
        RAISE EXCEPTION '%', util.result_error('membership:error', sqlerrm) USING errcode = 'P0001';
END;
$$;

REVOKE ALL ON PROCEDURE rolebyte.assistants_of_person(jsonb, jsonb) FROM PUBLIC;
GRANT EXECUTE ON PROCEDURE rolebyte.assistants_of_person(jsonb, jsonb) TO rolebyte_public;

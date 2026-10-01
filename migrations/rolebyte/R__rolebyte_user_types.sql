-- The roles a new tenant starts with, and user types.

-- ---------------------------------------------------------------------------
-- seed_roles — the roles the register creates with a new tenant: Guest, who
-- holds nothing and is what a person has before anybody gives them a role;
-- Worker; and Manager. What each seeded role holds is what the services
-- declared beside their permissions (`seeds`), so the register names no
-- service's permission here, and a deployment whose services declare none
-- opens its tenants with no roles at all, as before. Named in the deployment's
-- language — English unless the call says Latvian — and changed or deleted by
-- the tenant like any other role afterwards. A helper for tenant_open; no
-- service may call it.
-- ---------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION rolebyte.seed_roles(p_actor text, p_tenant text, p_language text)
RETURNS jsonb
LANGUAGE plpgsql
SET search_path = rolebyte, util, pg_temp
AS $$
DECLARE
    v_seed  record;
    v_id    text;
    v_made  jsonb := '[]'::jsonb;
BEGIN
    IF NOT EXISTS (SELECT 1 FROM rolebyte.service_permission
                    WHERE seeds <> '{}'::text[] AND retired_at IS NULL) THEN
        RETURN v_made;
    END IF;

    FOR v_seed IN
        SELECT s.seed, s.name, s.description
          FROM (VALUES
            ('guest', 'en', 'Guest', 'Holds nothing. What a person has until somebody places them.'),
            ('worker', 'en', 'Worker', 'Adds tasks, moves the ones assigned to them, and sees only their own hours; in the Asset register only the equipment handed to them, in Workforce only their own record.'),
            ('manager', 'en', 'Manager', 'Everything where they are placed, including who is on it.'),
            ('guest', 'lv', 'Viesis', 'Nedod neko; tas ir cilvēkam, līdz kāds viņu kaut kur pievieno.'),
            ('worker', 'lv', 'Darbinieks', 'Pievieno uzdevumus, virza sev piešķirtos un redz tikai savas stundas; Iekārtu reģistrā tikai sev nodotās iekārtas, Darbaspēkā tikai savu ierakstu.'),
            ('manager', 'lv', 'Vadītājs', 'Visu tur, kur ir pievienots, arī to, kas tur ir.')
          ) AS s(seed, lang, name, description)
         WHERE s.lang = CASE WHEN p_language = 'lv' THEN 'lv' ELSE 'en' END
         ORDER BY CASE s.seed WHEN 'guest' THEN 1 WHEN 'worker' THEN 2 ELSE 3 END
    LOOP
        -- A tenant keeps what it has: a shipped role it already holds, or a name
        -- it already uses for a role of its own, is left alone.
        IF EXISTS (SELECT 1 FROM rolebyte.tenant_role r
                    WHERE r.tenant_id = p_tenant
                      AND (r.seed = v_seed.seed OR lower(r.name) = lower(v_seed.name))) THEN
            CONTINUE;
        END IF;

        v_id := util.generate_ulid();
        INSERT INTO rolebyte.tenant_role (id, tenant_id, name, description, seed)
        VALUES (v_id, p_tenant, v_seed.name, v_seed.description, v_seed.seed);

        INSERT INTO rolebyte.tenant_role_permission (tenant_role_id, permission_id)
        SELECT v_id, sp.id
          FROM rolebyte.service_permission sp
         WHERE v_seed.seed = ANY (sp.seeds) AND sp.retired_at IS NULL;

        -- The event carries what the role was given, so the history alone
        -- rebuilds it, exactly as a defined role and its reconfigurations do.
        INSERT INTO rolebyte.event (id, actor, tenant_id, kind, payload)
        VALUES (util.generate_ulid(), p_actor, p_tenant, 'tenantRoleSeeded',
                jsonb_build_object('roleId', v_id, 'seed', v_seed.seed, 'name', v_seed.name,
                                   'permissions', COALESCE((
                                       SELECT jsonb_agg(sp.service_key || '/' || sp.feature_key || ':' || sp.act
                                                        ORDER BY sp.service_key, sp.feature_key, sp.act)
                                         FROM rolebyte.tenant_role_permission t
                                         JOIN rolebyte.service_permission sp ON sp.id = t.permission_id
                                        WHERE t.tenant_role_id = v_id), '[]'::jsonb)));

        v_made := v_made || jsonb_build_object('id', v_id, 'seed', v_seed.seed, 'name', v_seed.name);
    END LOOP;

    RETURN v_made;
END;
$$;
REVOKE ALL ON FUNCTION rolebyte.seed_roles(text, text, text) FROM PUBLIC;

-- tenant_seed_roles — the operator gives an open tenant the shipped roles it does
-- not have yet, holding what the services declared for them now: for a tenant
-- opened before its services declared their permissions, as a deployment's
-- first tenant always is. A shipped role the tenant already holds, and a name it
-- already uses, are left alone, so running it again changes nothing. Answers the
-- roles created, the shipped roles it already held (`kept`), and those it still
-- lacks (`missing`: its own role has that name, or no service declared any yet).
-- Input {actor, tenantId, language?}. Emits `tenantRoleSeeded` per role created.
-- The operator's act: the register's own role cannot run it.
CREATE OR REPLACE PROCEDURE rolebyte.tenant_seed_roles(IN pi_data jsonb, INOUT po_data jsonb)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = rolebyte, util, pg_temp
AS $$
DECLARE
    v_actor  text := NULLIF(btrim(pi_data->>'actor'), '');
    v_tenant text := NULLIF(btrim(pi_data->>'tenantId'), '');
    v_made   jsonb;
    v_left   jsonb;
    v_miss   jsonb;
BEGIN
    IF v_actor IS NULL OR v_tenant IS NULL THEN
        po_data := util.result_error('membership:invalid', 'actor and tenantId are required');
        RETURN;
    END IF;
    IF NOT EXISTS (SELECT 1 FROM rolebyte.tenant WHERE id = v_tenant) THEN
        po_data := util.result_error('tenant:not_found', 'tenant does not exist');
        RETURN;
    END IF;

    v_made := rolebyte.seed_roles(v_actor, v_tenant, NULLIF(btrim(pi_data->>'language'), ''));
    SELECT COALESCE(jsonb_agg(jsonb_build_object('id', r.id, 'seed', r.seed, 'name', r.name) ORDER BY r.seed), '[]'::jsonb)
      INTO v_left
      FROM rolebyte.tenant_role r
     WHERE r.tenant_id = v_tenant AND r.seed <> ''
       AND NOT EXISTS (SELECT 1 FROM jsonb_array_elements(v_made) m WHERE m->>'id' = r.id);

    SELECT COALESCE(jsonb_agg(sd ORDER BY sd), '[]'::jsonb) INTO v_miss
      FROM unnest(ARRAY['guest', 'worker', 'manager']) sd
     WHERE NOT EXISTS (SELECT 1 FROM rolebyte.tenant_role r WHERE r.tenant_id = v_tenant AND r.seed = sd);

    po_data := util.result_success(jsonb_build_object('roles', v_made, 'kept', v_left, 'missing', v_miss));
EXCEPTION
    WHEN sqlstate 'P0001' THEN
        RAISE;
    WHEN OTHERS THEN
        RAISE EXCEPTION '%', util.result_error('membership:error', sqlerrm) USING errcode = 'P0001';
END;
$$;
REVOKE ALL ON PROCEDURE rolebyte.tenant_seed_roles(jsonb, jsonb) FROM PUBLIC;

-- ---------------------------------------------------------------------------
-- User types: a named set of the tenant's tenant-wide permissions, given to a
-- person across the tenant. Every act is the tenant administrator's.
-- ---------------------------------------------------------------------------

-- ensure_default_user_type — the tenant's default user type, made when it has
-- none: named Member (Dalībnieks in Latvian), holding nothing. Every member holds
-- a user type, so every arrival receives this one unless a lane names another. A
-- tenant that already has a type of that name adopts it as its default rather
-- than making a second. Answers the default's id. A helper for the procedures
-- that admit a member; no service may call it.
CREATE OR REPLACE FUNCTION rolebyte.ensure_default_user_type(p_actor text, p_tenant text, p_language text)
RETURNS text
LANGUAGE plpgsql
SET search_path = rolebyte, util, pg_temp
AS $$
DECLARE
    v_id   text;
    v_name text := CASE WHEN p_language = 'lv' THEN 'Dalībnieks' ELSE 'Member' END;
    v_desc text := CASE WHEN p_language = 'lv'
                        THEN 'Nedod neko. Tas ir katrs dalībnieks, līdz kāds viņam piešķir citu.'
                        ELSE 'Holds nothing. What every member is until somebody gives them another.' END;
BEGIN
    SELECT default_user_type_id INTO v_id FROM rolebyte.tenant WHERE id = p_tenant FOR UPDATE;
    IF v_id IS NOT NULL THEN
        RETURN v_id;
    END IF;

    SELECT id INTO v_id FROM rolebyte.user_type WHERE tenant_id = p_tenant AND lower(name) = lower(v_name);
    IF v_id IS NULL THEN
        v_id := util.generate_ulid();
        INSERT INTO rolebyte.user_type (id, tenant_id, name, description) VALUES (v_id, p_tenant, v_name, v_desc);
        INSERT INTO rolebyte.event (id, actor, tenant_id, kind, payload)
        VALUES (util.generate_ulid(), p_actor, p_tenant, 'userTypeDefined',
                jsonb_build_object('userTypeId', v_id, 'name', v_name, 'description', v_desc,
                                   'permissions', '[]'::jsonb));
    END IF;
    UPDATE rolebyte.tenant SET default_user_type_id = v_id WHERE id = p_tenant;
    INSERT INTO rolebyte.event (id, actor, tenant_id, kind, payload)
    VALUES (util.generate_ulid(), p_actor, p_tenant, 'defaultUserTypeSet',
            jsonb_build_object('userTypeId', v_id, 'from', ''));

    RETURN v_id;
END;
$$;
REVOKE ALL ON FUNCTION rolebyte.ensure_default_user_type(text, text, text) FROM PUBLIC;

-- effective_user_type — the user type that applies to a member now: the type of
-- the position they sit in when that position names one and the tenant is
-- entitled to the chart, and their own otherwise. A lapse of the entitlement,
-- or leaving the position, returns them to the type an administrator (or their
-- arrival) gave them; nothing is overwritten.
CREATE OR REPLACE FUNCTION rolebyte.effective_user_type(p_tenant text, p_user text)
RETURNS text
LANGUAGE sql
STABLE
SET search_path = rolebyte, pg_temp
AS $$
    SELECT COALESCE(
        (SELECT p.user_type_id
           FROM rolebyte.chart_holder h
           JOIN rolebyte.chart_position p ON p.tenant_id = h.tenant_id AND p.id = h.position_id
          WHERE h.tenant_id = p_tenant AND h.user_id = p_user
            AND p.user_type_id IS NOT NULL
            AND rolebyte.chart_entitled(p_tenant)),
        (SELECT u.user_type_id FROM rolebyte.user_account u WHERE u.tenant_id = p_tenant AND u.id = p_user));
$$;
REVOKE ALL ON FUNCTION rolebyte.effective_user_type(text, text) FROM PUBLIC;

-- user_type_permissions — the permission ids a list of names resolves to, or
-- NULL when one of them is not an ordinary tenant-wide permission this register
-- has declared: a user type never carries sight of anybody's work, nor setup.
CREATE OR REPLACE FUNCTION rolebyte.user_type_permissions(p_names jsonb)
RETURNS text[]
LANGUAGE plpgsql
STABLE
SET search_path = rolebyte, pg_temp
AS $$
DECLARE
    v_ids   text[];
    v_count int;
BEGIN
    IF p_names IS NULL THEN
        RETURN '{}'::text[];
    END IF;
    IF jsonb_typeof(p_names) <> 'array' THEN
        RETURN NULL;
    END IF;

    SELECT COALESCE(array_agg(DISTINCT sp.id) FILTER (WHERE sp.id IS NOT NULL), '{}'::text[]), count(DISTINCT n.value)
      INTO v_ids, v_count
      FROM jsonb_array_elements_text(p_names) n
      LEFT JOIN rolebyte.service_permission sp
        ON sp.service_key || '/' || sp.feature_key || ':' || sp.act = n.value
       AND sp.plane = 'tenant' AND sp.class = 'ordinary' AND sp.retired_at IS NULL;

    IF cardinality(v_ids) <> v_count THEN
        RETURN NULL;
    END IF;

    RETURN v_ids;
END;
$$;
REVOKE ALL ON FUNCTION rolebyte.user_type_permissions(jsonb) FROM PUBLIC;

-- user_type_json — one user type as it is read.
CREATE OR REPLACE FUNCTION rolebyte.user_type_json(p_id text)
RETURNS jsonb
LANGUAGE plpgsql
STABLE
SET search_path = rolebyte, pg_temp
AS $$
BEGIN
    RETURN (SELECT jsonb_build_object(
                'id', t.id, 'name', t.name, 'description', t.description,
                'permissions', COALESCE((
                    SELECT jsonb_agg(sp.service_key || '/' || sp.feature_key || ':' || sp.act
                                     ORDER BY sp.service_key || '/' || sp.feature_key || ':' || sp.act COLLATE "C")
                      FROM rolebyte.user_type_permission up
                      JOIN rolebyte.service_permission sp ON sp.id = up.permission_id
                     WHERE up.user_type_id = t.id), '[]'::jsonb),
                'members', (SELECT count(*) FROM rolebyte.user_account u WHERE u.user_type_id = t.id),
                'corporateLoginDefault', EXISTS (SELECT 1 FROM rolebyte.tenant n
                                                  WHERE n.id = t.tenant_id AND n.corporate_login_user_type_id = t.id),
                'workspaceDefault', EXISTS (SELECT 1 FROM rolebyte.tenant n
                                             WHERE n.id = t.tenant_id AND n.default_user_type_id = t.id))
              FROM rolebyte.user_type t WHERE t.id = p_id);
END;
$$;
REVOKE ALL ON FUNCTION rolebyte.user_type_json(text) FROM PUBLIC;

-- user_type_state — what a user type is after an act (its name, description and
-- whole set of permissions), carried by the act's event so the history alone
-- rebuilds it.
CREATE OR REPLACE FUNCTION rolebyte.user_type_state(p_id text)
RETURNS jsonb
LANGUAGE plpgsql
STABLE
SET search_path = rolebyte, pg_temp
AS $$
BEGIN
    RETURN rolebyte.user_type_json(p_id) - 'id' - 'members' - 'corporateLoginDefault' - 'workspaceDefault';
END;
$$;
REVOKE ALL ON FUNCTION rolebyte.user_type_state(text) FROM PUBLIC;

-- user_type_define — a new user type. Input {actor, tenantId, name,
-- description, permissions: ["<service>/<feature>:<act>", …]}.
CREATE OR REPLACE PROCEDURE rolebyte.user_type_define(IN pi_data jsonb, INOUT po_data jsonb)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = rolebyte, util, pg_temp
AS $$
DECLARE
    v_actor  text := NULLIF(btrim(pi_data->>'actor'), '');
    v_tenant text := NULLIF(btrim(pi_data->>'tenantId'), '');
    v_name   text := btrim(COALESCE(pi_data->>'name', ''));
    v_desc   text := btrim(COALESCE(pi_data->>'description', ''));
    v_perms  text[];
    v_id     text;
BEGIN
    IF v_actor IS NULL OR v_tenant IS NULL THEN
        po_data := util.result_error('membership:invalid', 'actor and tenantId are required');
        RETURN;
    END IF;
    IF NOT rolebyte.is_tenant_role_name(v_name) THEN
        po_data := util.result_error('membership:invalid', 'a user type needs a name of 1 to 100 characters on one line');
        RETURN;
    END IF;
    v_perms := rolebyte.user_type_permissions(pi_data->'permissions');
    IF v_perms IS NULL THEN
        po_data := util.result_error('membership:invalid',
            'a user type holds only permissions granted across the tenant, never one placed on a project nor the tenant''s setup');
        RETURN;
    END IF;
    IF NOT EXISTS (SELECT 1 FROM rolebyte.tenant WHERE id = v_tenant) THEN
        po_data := util.result_error('tenant:not_found', 'tenant does not exist');
        RETURN;
    END IF;
    IF EXISTS (SELECT 1 FROM rolebyte.user_type WHERE tenant_id = v_tenant AND lower(name) = lower(v_name)) THEN
        po_data := util.result_error('membership:conflict', 'the tenant already has a user type of that name');
        RETURN;
    END IF;

    v_id := util.generate_ulid();
    INSERT INTO rolebyte.user_type (id, tenant_id, name, description) VALUES (v_id, v_tenant, v_name, v_desc);
    INSERT INTO rolebyte.user_type_permission (user_type_id, permission_id) SELECT v_id, unnest(v_perms);
    INSERT INTO rolebyte.event (id, actor, tenant_id, kind, payload)
    VALUES (util.generate_ulid(), v_actor, v_tenant, 'userTypeDefined',
            jsonb_build_object('userTypeId', v_id) || rolebyte.user_type_state(v_id));

    po_data := util.result_success(rolebyte.user_type_json(v_id));
EXCEPTION
    WHEN sqlstate 'P0001' THEN
        RAISE;
    WHEN OTHERS THEN
        RAISE EXCEPTION '%', util.result_error('membership:error', sqlerrm) USING errcode = 'P0001';
END;
$$;
REVOKE ALL ON PROCEDURE rolebyte.user_type_define(jsonb, jsonb) FROM PUBLIC;
GRANT EXECUTE ON PROCEDURE rolebyte.user_type_define(jsonb, jsonb) TO rolebyte_public;

-- user_type_update — rename a user type, or give it a new whole set of
-- permissions. Input {actor, tenantId, userTypeId, name?, description?, permissions?}.
CREATE OR REPLACE PROCEDURE rolebyte.user_type_update(IN pi_data jsonb, INOUT po_data jsonb)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = rolebyte, util, pg_temp
AS $$
DECLARE
    v_actor  text := NULLIF(btrim(pi_data->>'actor'), '');
    v_tenant text := NULLIF(btrim(pi_data->>'tenantId'), '');
    v_id     text := NULLIF(btrim(pi_data->>'userTypeId'), '');
    v_row    rolebyte.user_type%ROWTYPE;
    v_name   text;
    v_perms  text[];
BEGIN
    IF v_actor IS NULL OR v_tenant IS NULL OR v_id IS NULL THEN
        po_data := util.result_error('membership:invalid', 'actor, tenantId and userTypeId are required');
        RETURN;
    END IF;
    SELECT * INTO v_row FROM rolebyte.user_type WHERE tenant_id = v_tenant AND id = v_id FOR UPDATE;
    IF NOT FOUND THEN
        po_data := util.result_error('membership:not_found', 'no such user type');
        RETURN;
    END IF;
    v_name := CASE WHEN pi_data ? 'name' THEN btrim(COALESCE(pi_data->>'name', '')) ELSE v_row.name END;
    IF NOT rolebyte.is_tenant_role_name(v_name) THEN
        po_data := util.result_error('membership:invalid', 'a user type needs a name of 1 to 100 characters on one line');
        RETURN;
    END IF;
    IF lower(v_name) <> lower(v_row.name)
       AND EXISTS (SELECT 1 FROM rolebyte.user_type WHERE tenant_id = v_tenant AND lower(name) = lower(v_name)) THEN
        po_data := util.result_error('membership:conflict', 'the tenant already has a user type of that name');
        RETURN;
    END IF;
    IF pi_data ? 'permissions' THEN
        v_perms := rolebyte.user_type_permissions(pi_data->'permissions');
        IF v_perms IS NULL THEN
            po_data := util.result_error('membership:invalid',
                'a user type holds only permissions granted across the tenant, never one placed on a project nor the tenant''s setup');
            RETURN;
        END IF;
    END IF;

    UPDATE rolebyte.user_type
       SET name = v_name,
           description = CASE WHEN pi_data ? 'description' THEN btrim(COALESCE(pi_data->>'description', '')) ELSE description END
     WHERE id = v_id;
    IF v_perms IS NOT NULL THEN
        DELETE FROM rolebyte.user_type_permission WHERE user_type_id = v_id;
        INSERT INTO rolebyte.user_type_permission (user_type_id, permission_id) SELECT v_id, unnest(v_perms);
    END IF;
    INSERT INTO rolebyte.event (id, actor, tenant_id, kind, payload)
    VALUES (util.generate_ulid(), v_actor, v_tenant, 'userTypeChanged',
            jsonb_build_object('userTypeId', v_id) || rolebyte.user_type_state(v_id));

    po_data := util.result_success(rolebyte.user_type_json(v_id));
EXCEPTION
    WHEN sqlstate 'P0001' THEN
        RAISE;
    WHEN OTHERS THEN
        RAISE EXCEPTION '%', util.result_error('membership:error', sqlerrm) USING errcode = 'P0001';
END;
$$;
REVOKE ALL ON PROCEDURE rolebyte.user_type_update(jsonb, jsonb) FROM PUBLIC;
GRANT EXECUTE ON PROCEDURE rolebyte.user_type_update(jsonb, jsonb) TO rolebyte_public;

-- user_type_delete — remove a user type nobody holds and the corporate login
-- does not give; a user type in use is refused with the count.
CREATE OR REPLACE PROCEDURE rolebyte.user_type_delete(IN pi_data jsonb, INOUT po_data jsonb)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = rolebyte, util, pg_temp
AS $$
DECLARE
    v_actor  text := NULLIF(btrim(pi_data->>'actor'), '');
    v_tenant text := NULLIF(btrim(pi_data->>'tenantId'), '');
    v_id     text := NULLIF(btrim(pi_data->>'userTypeId'), '');
    v_held   int;
BEGIN
    IF v_actor IS NULL OR v_tenant IS NULL OR v_id IS NULL THEN
        po_data := util.result_error('membership:invalid', 'actor, tenantId and userTypeId are required');
        RETURN;
    END IF;
    PERFORM 1 FROM rolebyte.user_type WHERE tenant_id = v_tenant AND id = v_id FOR UPDATE;
    IF NOT FOUND THEN
        po_data := util.result_error('membership:not_found', 'no such user type');
        RETURN;
    END IF;
    SELECT count(*) INTO v_held FROM rolebyte.user_account WHERE user_type_id = v_id;
    IF v_held > 0 THEN
        po_data := util.result_error('membership:conflict',
            format('%s member(s) hold this user type; give them another first', v_held));
        RETURN;
    END IF;
    IF EXISTS (SELECT 1 FROM rolebyte.tenant WHERE id = v_tenant AND corporate_login_user_type_id = v_id) THEN
        po_data := util.result_error('membership:conflict',
            'people arriving through the corporate login receive this user type; choose another first');
        RETURN;
    END IF;
    IF EXISTS (SELECT 1 FROM rolebyte.tenant WHERE id = v_tenant AND default_user_type_id = v_id) THEN
        po_data := util.result_error('membership:conflict',
            'this is the user type every new member receives; it cannot be deleted');
        RETURN;
    END IF;
    IF EXISTS (SELECT 1 FROM rolebyte.chart_position WHERE tenant_id = v_tenant AND user_type_id = v_id) THEN
        po_data := util.result_error('membership:conflict',
            'a position in the chart of authority sets this user type; choose another there first');
        RETURN;
    END IF;

    DELETE FROM rolebyte.user_type_permission WHERE user_type_id = v_id;
    DELETE FROM rolebyte.user_type WHERE id = v_id;
    INSERT INTO rolebyte.event (id, actor, tenant_id, kind, payload)
    VALUES (util.generate_ulid(), v_actor, v_tenant, 'userTypeDeleted', jsonb_build_object('userTypeId', v_id));

    po_data := util.result_success(jsonb_build_object('userTypeId', v_id));
EXCEPTION
    WHEN sqlstate 'P0001' THEN
        RAISE;
    WHEN OTHERS THEN
        RAISE EXCEPTION '%', util.result_error('membership:error', sqlerrm) USING errcode = 'P0001';
END;
$$;
REVOKE ALL ON PROCEDURE rolebyte.user_type_delete(jsonb, jsonb) FROM PUBLIC;
GRANT EXECUTE ON PROCEDURE rolebyte.user_type_delete(jsonb, jsonb) TO rolebyte_public;

-- user_type_list — the tenant's user types.
CREATE OR REPLACE PROCEDURE rolebyte.user_type_list(IN pi_data jsonb, INOUT po_data jsonb)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = rolebyte, util, pg_temp
AS $$
DECLARE
    v_tenant text := NULLIF(btrim(pi_data->>'tenantId'), '');
BEGIN
    IF v_tenant IS NULL THEN
        po_data := util.result_error('membership:invalid', 'tenantId is required');
        RETURN;
    END IF;
    po_data := util.result_success(jsonb_build_object('userTypes', COALESCE((
        SELECT jsonb_agg(rolebyte.user_type_json(t.id) ORDER BY lower(t.name))
          FROM rolebyte.user_type t WHERE t.tenant_id = v_tenant), '[]'::jsonb)));
EXCEPTION
    WHEN sqlstate 'P0001' THEN
        RAISE;
    WHEN OTHERS THEN
        RAISE EXCEPTION '%', util.result_error('membership:error', sqlerrm) USING errcode = 'P0001';
END;
$$;
REVOKE ALL ON PROCEDURE rolebyte.user_type_list(jsonb, jsonb) FROM PUBLIC;
GRANT EXECUTE ON PROCEDURE rolebyte.user_type_list(jsonb, jsonb) TO rolebyte_public;

-- user_type_assign — give a member a user type. Every member holds one, so it is
-- never taken away, only changed. Set by an administrator, and recorded as such.
CREATE OR REPLACE PROCEDURE rolebyte.user_type_assign(IN pi_data jsonb, INOUT po_data jsonb)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = rolebyte, util, pg_temp
AS $$
DECLARE
    v_actor  text := NULLIF(btrim(pi_data->>'actor'), '');
    v_tenant text := NULLIF(btrim(pi_data->>'tenantId'), '');
    v_user   text := NULLIF(btrim(pi_data->>'userId'), '');
    v_type   text := NULLIF(btrim(pi_data->>'userTypeId'), '');
    v_before text;
BEGIN
    IF v_actor IS NULL OR v_tenant IS NULL OR v_user IS NULL THEN
        po_data := util.result_error('membership:invalid', 'actor, tenantId and userId are required');
        RETURN;
    END IF;
    IF v_type IS NULL THEN
        po_data := util.result_error('membership:invalid', 'every member has a user type; choose one');
        RETURN;
    END IF;
    SELECT user_type_id INTO v_before FROM rolebyte.user_account WHERE tenant_id = v_tenant AND id = v_user FOR UPDATE;
    IF NOT FOUND THEN
        po_data := util.result_error('membership:not_found', 'no such member');
        RETURN;
    END IF;
    IF v_type IS NOT NULL AND NOT EXISTS (SELECT 1 FROM rolebyte.user_type WHERE tenant_id = v_tenant AND id = v_type) THEN
        po_data := util.result_error('membership:invalid', 'that is not one of the tenant''s user types');
        RETURN;
    END IF;

    UPDATE rolebyte.user_account
       SET user_type_id = v_type,
           user_type_source = 'administrator'
     WHERE id = v_user;
    IF v_type IS DISTINCT FROM v_before THEN
        INSERT INTO rolebyte.event (id, actor, tenant_id, user_id, kind, payload)
        VALUES (util.generate_ulid(), v_actor, v_tenant, v_user, 'userTypeAssigned',
                jsonb_build_object('userTypeId', COALESCE(v_type, ''), 'from', COALESCE(v_before, ''), 'source', 'administrator'));
    END IF;

    po_data := util.result_success(jsonb_build_object('userId', v_user, 'userTypeId', v_type, 'source', 'administrator'));
EXCEPTION
    WHEN sqlstate 'P0001' THEN
        RAISE;
    WHEN OTHERS THEN
        RAISE EXCEPTION '%', util.result_error('membership:error', sqlerrm) USING errcode = 'P0001';
END;
$$;
REVOKE ALL ON PROCEDURE rolebyte.user_type_assign(jsonb, jsonb) FROM PUBLIC;
GRANT EXECUTE ON PROCEDURE rolebyte.user_type_assign(jsonb, jsonb) TO rolebyte_public;

-- corporate_login_default_set — the user type people arriving through the
-- tenant's corporate login receive at their first sign-in; empty for none.
-- Changing it never touches anybody already in.
CREATE OR REPLACE PROCEDURE rolebyte.corporate_login_default_set(IN pi_data jsonb, INOUT po_data jsonb)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = rolebyte, util, pg_temp
AS $$
DECLARE
    v_actor  text := NULLIF(btrim(pi_data->>'actor'), '');
    v_tenant text := NULLIF(btrim(pi_data->>'tenantId'), '');
    v_type   text := NULLIF(btrim(pi_data->>'userTypeId'), '');
    v_before text;
BEGIN
    IF v_actor IS NULL OR v_tenant IS NULL THEN
        po_data := util.result_error('membership:invalid', 'actor and tenantId are required');
        RETURN;
    END IF;
    SELECT corporate_login_user_type_id INTO v_before FROM rolebyte.tenant WHERE id = v_tenant FOR UPDATE;
    IF NOT FOUND THEN
        po_data := util.result_error('tenant:not_found', 'tenant does not exist');
        RETURN;
    END IF;
    IF v_type IS NOT NULL AND NOT EXISTS (SELECT 1 FROM rolebyte.user_type WHERE tenant_id = v_tenant AND id = v_type) THEN
        po_data := util.result_error('membership:invalid', 'that is not one of the tenant''s user types');
        RETURN;
    END IF;

    UPDATE rolebyte.tenant SET corporate_login_user_type_id = v_type WHERE id = v_tenant;
    IF v_type IS DISTINCT FROM v_before THEN
        INSERT INTO rolebyte.event (id, actor, tenant_id, kind, payload)
        VALUES (util.generate_ulid(), v_actor, v_tenant, 'corporateLoginDefaultSet',
                jsonb_build_object('userTypeId', COALESCE(v_type, ''), 'from', COALESCE(v_before, '')));
    END IF;

    po_data := util.result_success(jsonb_build_object('userTypeId', COALESCE(v_type, '')));
EXCEPTION
    WHEN sqlstate 'P0001' THEN
        RAISE;
    WHEN OTHERS THEN
        RAISE EXCEPTION '%', util.result_error('membership:error', sqlerrm) USING errcode = 'P0001';
END;
$$;
REVOKE ALL ON PROCEDURE rolebyte.corporate_login_default_set(jsonb, jsonb) FROM PUBLIC;
GRANT EXECUTE ON PROCEDURE rolebyte.corporate_login_default_set(jsonb, jsonb) TO rolebyte_public;

-- corporate_login_default_get — which user type that is, empty for none.
CREATE OR REPLACE PROCEDURE rolebyte.corporate_login_default_get(IN pi_data jsonb, INOUT po_data jsonb)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = rolebyte, util, pg_temp
AS $$
DECLARE
    v_tenant text := NULLIF(btrim(pi_data->>'tenantId'), '');
    v_type   text;
BEGIN
    IF v_tenant IS NULL THEN
        po_data := util.result_error('membership:invalid', 'tenantId is required');
        RETURN;
    END IF;
    SELECT corporate_login_user_type_id INTO v_type FROM rolebyte.tenant WHERE id = v_tenant;
    IF NOT FOUND THEN
        po_data := util.result_error('tenant:not_found', 'tenant does not exist');
        RETURN;
    END IF;
    po_data := util.result_success(jsonb_build_object('userTypeId', COALESCE(v_type, '')));
EXCEPTION
    WHEN sqlstate 'P0001' THEN
        RAISE;
    WHEN OTHERS THEN
        RAISE EXCEPTION '%', util.result_error('membership:error', sqlerrm) USING errcode = 'P0001';
END;
$$;
REVOKE ALL ON PROCEDURE rolebyte.corporate_login_default_get(jsonb, jsonb) FROM PUBLIC;
GRANT EXECUTE ON PROCEDURE rolebyte.corporate_login_default_get(jsonb, jsonb) TO rolebyte_public;

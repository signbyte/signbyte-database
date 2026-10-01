-- The chart of authority: the tenant's own tree of positions, the people in
-- them, the boxes a position carries and the user type it may name.
--
-- Every write is the tenant administrator's and leaves an event naming who made
-- it. The chart is read for the editor (chart_get) and, as a flat answer for the
-- services that let a position see what the people below it see, by
-- chart_document. A tenant holds the chart only while it is entitled to the
-- service key `authority`: nothing is deleted when that lapses, the document
-- answers empty, and the positions' user types stop applying.

-- chart_entitled — whether the tenant is entitled to the chart, whole or in any
-- feature. The one place that asks; resolve, the editor and the document agree
-- because they all call it.
CREATE OR REPLACE FUNCTION rolebyte.chart_entitled(p_tenant text)
RETURNS boolean
LANGUAGE sql
STABLE
SET search_path = rolebyte, pg_temp
AS $$
    SELECT EXISTS (SELECT 1 FROM rolebyte.tenant_entitlement e
                    WHERE e.tenant_id = p_tenant AND e.service_key = 'authority' AND e.state = 'entitled');
$$;
REVOKE ALL ON FUNCTION rolebyte.chart_entitled(text) FROM PUBLIC;

-- chart_permission_ids — the permission ids a list of names resolves to, or
-- NULL when one is not a chart permission this register has declared and not
-- retired: a position carries chart boxes only, and no other list carries them.
CREATE OR REPLACE FUNCTION rolebyte.chart_permission_ids(p_names jsonb)
RETURNS text[]
LANGUAGE plpgsql
STABLE
SET search_path = rolebyte, pg_temp
AS $$
DECLARE
    v_ids   text[];
    v_count int;
BEGIN
    IF jsonb_typeof(p_names) IS DISTINCT FROM 'array'
       OR EXISTS (SELECT 1 FROM jsonb_array_elements(p_names) e WHERE jsonb_typeof(e) <> 'string') THEN
        RETURN NULL;
    END IF;

    SELECT COALESCE(array_agg(DISTINCT sp.id) FILTER (WHERE sp.id IS NOT NULL), '{}'::text[]),
           count(DISTINCT n.value)
      INTO v_ids, v_count
      FROM jsonb_array_elements_text(p_names) n
      LEFT JOIN rolebyte.service_permission sp
        ON sp.service_key || '/' || sp.feature_key || ':' || sp.act = n.value
       AND sp.plane = 'chart' AND sp.class = 'ordinary' AND sp.retired_at IS NULL;

    IF cardinality(v_ids) <> v_count THEN
        RETURN NULL;
    END IF;

    RETURN v_ids;
END;
$$;
REVOKE ALL ON FUNCTION rolebyte.chart_permission_ids(jsonb) FROM PUBLIC;

-- chart_position_json — one position as it is read: its place in the tree, the
-- user type it names, the boxes it carries and the people in it.
CREATE OR REPLACE FUNCTION rolebyte.chart_position_json(p_id text)
RETURNS jsonb
LANGUAGE plpgsql
STABLE
SET search_path = rolebyte, pg_temp
AS $$
BEGIN
    RETURN (SELECT jsonb_build_object(
                'id', p.id,
                'parentId', COALESCE(p.parent_id, ''),
                'name', p.name,
                'userTypeId', COALESCE(p.user_type_id, ''),
                'permissions', COALESCE((
                    SELECT jsonb_agg(sp.service_key || '/' || sp.feature_key || ':' || sp.act
                                     ORDER BY sp.service_key || '/' || sp.feature_key || ':' || sp.act COLLATE "C")
                      FROM rolebyte.chart_position_permission cp
                      JOIN rolebyte.service_permission sp ON sp.id = cp.permission_id
                     WHERE cp.position_id = p.id), '[]'::jsonb),
                'people', COALESCE((
                    SELECT jsonb_agg(jsonb_build_object('userId', u.id, 'displayName', u.display_name)
                                     ORDER BY lower(u.display_name), u.id)
                      FROM rolebyte.chart_holder h
                      JOIN rolebyte.user_account u ON u.tenant_id = h.tenant_id AND u.id = h.user_id
                     WHERE h.position_id = p.id), '[]'::jsonb))
              FROM rolebyte.chart_position p WHERE p.id = p_id);
END;
$$;
REVOKE ALL ON FUNCTION rolebyte.chart_position_json(text) FROM PUBLIC;

-- chart_get — the whole chart for the editor: whether the tenant has it, every
-- position, and the people who are in no position (the editor lists them so a
-- project nobody below the director runs is visible). Machine members are never
-- people of the chart. Input {tenantId}.
CREATE OR REPLACE PROCEDURE rolebyte.chart_get(IN pi_data jsonb, INOUT po_data jsonb)
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
    IF NOT EXISTS (SELECT 1 FROM rolebyte.tenant WHERE id = v_tenant) THEN
        po_data := util.result_error('tenant:not_found', 'tenant does not exist');
        RETURN;
    END IF;

    po_data := util.result_success(jsonb_build_object(
        'included', rolebyte.chart_entitled(v_tenant),
        'positions', COALESCE((
            SELECT jsonb_agg(rolebyte.chart_position_json(p.id) ORDER BY lower(p.name), p.id)
              FROM rolebyte.chart_position p WHERE p.tenant_id = v_tenant), '[]'::jsonb),
        'unplaced', COALESCE((
            SELECT jsonb_agg(jsonb_build_object('userId', u.id, 'displayName', u.display_name)
                             ORDER BY lower(u.display_name), u.id)
              FROM rolebyte.user_account u
             WHERE u.tenant_id = v_tenant AND u.status IN ('active', 'invited')
               AND u.subject_key LIKE 'sub:%'
               AND NOT EXISTS (SELECT 1 FROM rolebyte.chart_holder h
                                WHERE h.tenant_id = u.tenant_id AND h.user_id = u.id)), '[]'::jsonb)));
EXCEPTION
    WHEN sqlstate 'P0001' THEN
        RAISE;
    WHEN OTHERS THEN
        RAISE EXCEPTION '%', util.result_error('membership:error', sqlerrm) USING errcode = 'P0001';
END;
$$;
REVOKE ALL ON PROCEDURE rolebyte.chart_get(jsonb, jsonb) FROM PUBLIC;
GRANT EXECUTE ON PROCEDURE rolebyte.chart_get(jsonb, jsonb) TO rolebyte_public;

-- chart_document — who is below whom, for the services that read it: for each
-- person in a position, every person in every position under theirs, all the way
-- down, never the people in their own position. Subjects, not ids, because a
-- service knows its people by subject. Only active members count. A tenant that
-- does not hold the chart is answered an empty one. Input {tenantId}.
CREATE OR REPLACE PROCEDURE rolebyte.chart_document(IN pi_data jsonb, INOUT po_data jsonb)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = rolebyte, util, pg_temp
AS $$
DECLARE
    v_tenant text := NULLIF(btrim(pi_data->>'tenantId'), '');
    v_below  jsonb;
BEGIN
    IF v_tenant IS NULL THEN
        po_data := util.result_error('membership:invalid', 'tenantId is required');
        RETURN;
    END IF;
    IF NOT EXISTS (SELECT 1 FROM rolebyte.tenant WHERE id = v_tenant) THEN
        po_data := util.result_error('tenant:not_found', 'tenant does not exist');
        RETURN;
    END IF;

    IF NOT rolebyte.chart_entitled(v_tenant) THEN
        po_data := util.result_success(jsonb_build_object('below', '{}'::jsonb));
        RETURN;
    END IF;

    WITH RECURSIVE under(top_id, pos_id) AS (
        SELECT p.id, p.id FROM rolebyte.chart_position p WHERE p.tenant_id = v_tenant
        UNION ALL
        SELECT s.top_id, c.id
          FROM under s
          JOIN rolebyte.chart_position c ON c.tenant_id = v_tenant AND c.parent_id = s.pos_id
    ), pairs AS (
        SELECT up.subject_key AS above, dn.subject_key AS below
          FROM under s
          JOIN rolebyte.chart_holder hu ON hu.tenant_id = v_tenant AND hu.position_id = s.top_id
          JOIN rolebyte.user_account up ON up.tenant_id = v_tenant AND up.id = hu.user_id AND up.status = 'active'
          JOIN rolebyte.chart_holder hd ON hd.tenant_id = v_tenant AND hd.position_id = s.pos_id
          JOIN rolebyte.user_account dn ON dn.tenant_id = v_tenant AND dn.id = hd.user_id AND dn.status = 'active'
         WHERE s.pos_id <> s.top_id
    )
    SELECT COALESCE(jsonb_object_agg(g.above, g.list), '{}'::jsonb)
      INTO v_below
      FROM (SELECT above, jsonb_agg(DISTINCT below) AS list FROM pairs GROUP BY above) g;

    po_data := util.result_success(jsonb_build_object('below', v_below));
EXCEPTION
    WHEN sqlstate 'P0001' THEN
        RAISE;
    WHEN OTHERS THEN
        RAISE EXCEPTION '%', util.result_error('membership:error', sqlerrm) USING errcode = 'P0001';
END;
$$;
REVOKE ALL ON PROCEDURE rolebyte.chart_document(jsonb, jsonb) FROM PUBLIC;
GRANT EXECUTE ON PROCEDURE rolebyte.chart_document(jsonb, jsonb) TO rolebyte_public;

-- chart_position_add — a position under another, or the top when the tenant has
-- none yet. Input {actor, tenantId, name, parentId?}.
CREATE OR REPLACE PROCEDURE rolebyte.chart_position_add(IN pi_data jsonb, INOUT po_data jsonb)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = rolebyte, util, pg_temp
AS $$
DECLARE
    v_actor  text := NULLIF(btrim(pi_data->>'actor'), '');
    v_tenant text := NULLIF(btrim(pi_data->>'tenantId'), '');
    v_name   text := btrim(COALESCE(pi_data->>'name', ''));
    v_parent text := NULLIF(btrim(COALESCE(pi_data->>'parentId', '')), '');
    v_id     text;
BEGIN
    IF v_actor IS NULL OR v_tenant IS NULL THEN
        po_data := util.result_error('membership:invalid', 'actor and tenantId are required');
        RETURN;
    END IF;
    IF NOT rolebyte.is_tenant_role_name(v_name) THEN
        po_data := util.result_error('membership:invalid', 'a position needs a name of 1 to 100 characters on one line');
        RETURN;
    END IF;
    PERFORM 1 FROM rolebyte.tenant WHERE id = v_tenant FOR UPDATE;
    IF NOT FOUND THEN
        po_data := util.result_error('tenant:not_found', 'tenant does not exist');
        RETURN;
    END IF;
    IF NOT rolebyte.chart_entitled(v_tenant) THEN
        po_data := util.result_error('membership:conflict', 'the workspace does not include the chart of authority');
        RETURN;
    END IF;
    IF v_parent IS NULL THEN
        IF EXISTS (SELECT 1 FROM rolebyte.chart_position WHERE tenant_id = v_tenant) THEN
            po_data := util.result_error('membership:conflict',
                'the chart has one top position; place this one under another');
            RETURN;
        END IF;
    ELSIF NOT EXISTS (SELECT 1 FROM rolebyte.chart_position WHERE tenant_id = v_tenant AND id = v_parent) THEN
        po_data := util.result_error('membership:not_found', 'no such position to place it under');
        RETURN;
    END IF;

    v_id := util.generate_ulid();
    INSERT INTO rolebyte.chart_position (id, tenant_id, parent_id, name) VALUES (v_id, v_tenant, v_parent, v_name);
    INSERT INTO rolebyte.event (id, actor, tenant_id, kind, payload)
    VALUES (util.generate_ulid(), v_actor, v_tenant, 'chartPositionAdded',
            jsonb_build_object('positionId', v_id, 'parentId', COALESCE(v_parent, ''), 'name', v_name));

    po_data := util.result_success(rolebyte.chart_position_json(v_id));
EXCEPTION
    WHEN sqlstate 'P0001' THEN
        RAISE;
    WHEN OTHERS THEN
        RAISE EXCEPTION '%', util.result_error('membership:error', sqlerrm) USING errcode = 'P0001';
END;
$$;
REVOKE ALL ON PROCEDURE rolebyte.chart_position_add(jsonb, jsonb) FROM PUBLIC;
GRANT EXECUTE ON PROCEDURE rolebyte.chart_position_add(jsonb, jsonb) TO rolebyte_public;

-- chart_position_rename. Input {actor, tenantId, positionId, name}.
CREATE OR REPLACE PROCEDURE rolebyte.chart_position_rename(IN pi_data jsonb, INOUT po_data jsonb)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = rolebyte, util, pg_temp
AS $$
DECLARE
    v_actor  text := NULLIF(btrim(pi_data->>'actor'), '');
    v_tenant text := NULLIF(btrim(pi_data->>'tenantId'), '');
    v_id     text := NULLIF(btrim(pi_data->>'positionId'), '');
    v_name   text := btrim(COALESCE(pi_data->>'name', ''));
    v_before text;
BEGIN
    IF v_actor IS NULL OR v_tenant IS NULL OR v_id IS NULL THEN
        po_data := util.result_error('membership:invalid', 'actor, tenantId and positionId are required');
        RETURN;
    END IF;
    IF NOT rolebyte.is_tenant_role_name(v_name) THEN
        po_data := util.result_error('membership:invalid', 'a position needs a name of 1 to 100 characters on one line');
        RETURN;
    END IF;
    IF NOT rolebyte.chart_entitled(v_tenant) THEN
        po_data := util.result_error('membership:conflict', 'the workspace does not include the chart of authority');
        RETURN;
    END IF;
    SELECT name INTO v_before FROM rolebyte.chart_position WHERE tenant_id = v_tenant AND id = v_id FOR UPDATE;
    IF NOT FOUND THEN
        po_data := util.result_error('membership:not_found', 'no such position');
        RETURN;
    END IF;

    IF v_name <> v_before THEN
        UPDATE rolebyte.chart_position SET name = v_name WHERE id = v_id;
        INSERT INTO rolebyte.event (id, actor, tenant_id, kind, payload)
        VALUES (util.generate_ulid(), v_actor, v_tenant, 'chartPositionRenamed',
                jsonb_build_object('positionId', v_id, 'name', v_name, 'from', v_before));
    END IF;

    po_data := util.result_success(rolebyte.chart_position_json(v_id));
EXCEPTION
    WHEN sqlstate 'P0001' THEN
        RAISE;
    WHEN OTHERS THEN
        RAISE EXCEPTION '%', util.result_error('membership:error', sqlerrm) USING errcode = 'P0001';
END;
$$;
REVOKE ALL ON PROCEDURE rolebyte.chart_position_rename(jsonb, jsonb) FROM PUBLIC;
GRANT EXECUTE ON PROCEDURE rolebyte.chart_position_rename(jsonb, jsonb) TO rolebyte_public;

-- chart_position_move — a position, with everything under it, under another.
-- Never under itself or anything below it, and never the top. Input {actor,
-- tenantId, positionId, parentId}.
CREATE OR REPLACE PROCEDURE rolebyte.chart_position_move(IN pi_data jsonb, INOUT po_data jsonb)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = rolebyte, util, pg_temp
AS $$
DECLARE
    v_actor  text := NULLIF(btrim(pi_data->>'actor'), '');
    v_tenant text := NULLIF(btrim(pi_data->>'tenantId'), '');
    v_id     text := NULLIF(btrim(pi_data->>'positionId'), '');
    v_parent text := NULLIF(btrim(COALESCE(pi_data->>'parentId', '')), '');
    v_row    rolebyte.chart_position%ROWTYPE;
BEGIN
    IF v_actor IS NULL OR v_tenant IS NULL OR v_id IS NULL OR v_parent IS NULL THEN
        po_data := util.result_error('membership:invalid', 'actor, tenantId, positionId and parentId are required');
        RETURN;
    END IF;
    IF NOT rolebyte.chart_entitled(v_tenant) THEN
        po_data := util.result_error('membership:conflict', 'the workspace does not include the chart of authority');
        RETURN;
    END IF;
    -- One lock per tenant: two moves at once could each look safe and together make a loop.
    PERFORM 1 FROM rolebyte.tenant WHERE id = v_tenant FOR UPDATE;
    SELECT * INTO v_row FROM rolebyte.chart_position WHERE tenant_id = v_tenant AND id = v_id;
    IF NOT FOUND THEN
        po_data := util.result_error('membership:not_found', 'no such position');
        RETURN;
    END IF;
    IF NOT EXISTS (SELECT 1 FROM rolebyte.chart_position WHERE tenant_id = v_tenant AND id = v_parent) THEN
        po_data := util.result_error('membership:not_found', 'no such position to place it under');
        RETURN;
    END IF;
    IF v_row.parent_id IS NULL THEN
        po_data := util.result_error('membership:conflict', 'the top position cannot be moved');
        RETURN;
    END IF;
    IF v_parent = v_id OR EXISTS (
        WITH RECURSIVE under(id) AS (
            SELECT c.id FROM rolebyte.chart_position c WHERE c.tenant_id = v_tenant AND c.parent_id = v_id
            UNION ALL
            SELECT c.id FROM under u JOIN rolebyte.chart_position c ON c.tenant_id = v_tenant AND c.parent_id = u.id)
        SELECT 1 FROM under WHERE id = v_parent) THEN
        po_data := util.result_error('membership:conflict', 'a position cannot be placed under itself or under anything below it');
        RETURN;
    END IF;

    IF v_parent IS DISTINCT FROM v_row.parent_id THEN
        UPDATE rolebyte.chart_position SET parent_id = v_parent WHERE id = v_id;
        INSERT INTO rolebyte.event (id, actor, tenant_id, kind, payload)
        VALUES (util.generate_ulid(), v_actor, v_tenant, 'chartPositionMoved',
                jsonb_build_object('positionId', v_id, 'parentId', v_parent, 'from', v_row.parent_id));
    END IF;

    po_data := util.result_success(rolebyte.chart_position_json(v_id));
EXCEPTION
    WHEN sqlstate 'P0001' THEN
        RAISE;
    WHEN OTHERS THEN
        RAISE EXCEPTION '%', util.result_error('membership:error', sqlerrm) USING errcode = 'P0001';
END;
$$;
REVOKE ALL ON PROCEDURE rolebyte.chart_position_move(jsonb, jsonb) FROM PUBLIC;
GRANT EXECUTE ON PROCEDURE rolebyte.chart_position_move(jsonb, jsonb) TO rolebyte_public;

-- chart_position_remove — an empty position with nothing under it. A position
-- with people or positions in it is refused with the counts; moving them first
-- is the administrator's decision. Input {actor, tenantId, positionId}.
CREATE OR REPLACE PROCEDURE rolebyte.chart_position_remove(IN pi_data jsonb, INOUT po_data jsonb)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = rolebyte, util, pg_temp
AS $$
DECLARE
    v_actor  text := NULLIF(btrim(pi_data->>'actor'), '');
    v_tenant text := NULLIF(btrim(pi_data->>'tenantId'), '');
    v_id     text := NULLIF(btrim(pi_data->>'positionId'), '');
    v_kids   int;
    v_people int;
BEGIN
    IF v_actor IS NULL OR v_tenant IS NULL OR v_id IS NULL THEN
        po_data := util.result_error('membership:invalid', 'actor, tenantId and positionId are required');
        RETURN;
    END IF;
    IF NOT rolebyte.chart_entitled(v_tenant) THEN
        po_data := util.result_error('membership:conflict', 'the workspace does not include the chart of authority');
        RETURN;
    END IF;
    PERFORM 1 FROM rolebyte.chart_position WHERE tenant_id = v_tenant AND id = v_id FOR UPDATE;
    IF NOT FOUND THEN
        po_data := util.result_error('membership:not_found', 'no such position');
        RETURN;
    END IF;
    SELECT count(*) INTO v_kids FROM rolebyte.chart_position WHERE tenant_id = v_tenant AND parent_id = v_id;
    SELECT count(*) INTO v_people FROM rolebyte.chart_holder WHERE tenant_id = v_tenant AND position_id = v_id;
    IF v_kids > 0 OR v_people > 0 THEN
        po_data := util.result_error('membership:conflict',
            format('%s position(s) are under it and %s person(s) are in it; move them first', v_kids, v_people));
        RETURN;
    END IF;

    DELETE FROM rolebyte.chart_position_permission WHERE position_id = v_id;
    DELETE FROM rolebyte.chart_position WHERE id = v_id;
    INSERT INTO rolebyte.event (id, actor, tenant_id, kind, payload)
    VALUES (util.generate_ulid(), v_actor, v_tenant, 'chartPositionRemoved', jsonb_build_object('positionId', v_id));

    po_data := util.result_success(jsonb_build_object('positionId', v_id));
EXCEPTION
    WHEN sqlstate 'P0001' THEN
        RAISE;
    WHEN OTHERS THEN
        RAISE EXCEPTION '%', util.result_error('membership:error', sqlerrm) USING errcode = 'P0001';
END;
$$;
REVOKE ALL ON PROCEDURE rolebyte.chart_position_remove(jsonb, jsonb) FROM PUBLIC;
GRANT EXECUTE ON PROCEDURE rolebyte.chart_position_remove(jsonb, jsonb) TO rolebyte_public;

-- chart_position_permissions_set — the whole set of chart boxes a position
-- carries. A name that is not a chart box is refused whole: no role and no user
-- type carries one, and a position carries nothing else. Input {actor,
-- tenantId, positionId, permissions: ["<service>/<feature>:<act>", …]}.
CREATE OR REPLACE PROCEDURE rolebyte.chart_position_permissions_set(IN pi_data jsonb, INOUT po_data jsonb)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = rolebyte, util, pg_temp
AS $$
DECLARE
    v_actor   text := NULLIF(btrim(pi_data->>'actor'), '');
    v_tenant  text := NULLIF(btrim(pi_data->>'tenantId'), '');
    v_id      text := NULLIF(btrim(pi_data->>'positionId'), '');
    v_ids     text[];
    v_before  jsonb;
    v_after   jsonb;
BEGIN
    IF v_actor IS NULL OR v_tenant IS NULL OR v_id IS NULL THEN
        po_data := util.result_error('membership:invalid', 'actor, tenantId and positionId are required');
        RETURN;
    END IF;
    IF NOT rolebyte.chart_entitled(v_tenant) THEN
        po_data := util.result_error('membership:conflict', 'the workspace does not include the chart of authority');
        RETURN;
    END IF;
    v_ids := rolebyte.chart_permission_ids(pi_data->'permissions');
    IF v_ids IS NULL THEN
        po_data := util.result_error('membership:invalid',
            'a position carries only the chart''s own permissions: a list of names, each declared and not retired');
        RETURN;
    END IF;
    PERFORM 1 FROM rolebyte.chart_position WHERE tenant_id = v_tenant AND id = v_id FOR UPDATE;
    IF NOT FOUND THEN
        po_data := util.result_error('membership:not_found', 'no such position');
        RETURN;
    END IF;

    v_before := rolebyte.chart_position_json(v_id)->'permissions';
    DELETE FROM rolebyte.chart_position_permission WHERE position_id = v_id;
    INSERT INTO rolebyte.chart_position_permission (position_id, permission_id) SELECT v_id, unnest(v_ids);
    v_after := rolebyte.chart_position_json(v_id)->'permissions';

    IF v_after IS DISTINCT FROM v_before THEN
        INSERT INTO rolebyte.event (id, actor, tenant_id, kind, payload)
        VALUES (util.generate_ulid(), v_actor, v_tenant, 'chartPositionPermissionsSet',
                jsonb_build_object('positionId', v_id, 'permissions', v_after, 'from', v_before));
    END IF;

    po_data := util.result_success(rolebyte.chart_position_json(v_id));
EXCEPTION
    WHEN sqlstate 'P0001' THEN
        RAISE;
    WHEN OTHERS THEN
        RAISE EXCEPTION '%', util.result_error('membership:error', sqlerrm) USING errcode = 'P0001';
END;
$$;
REVOKE ALL ON PROCEDURE rolebyte.chart_position_permissions_set(jsonb, jsonb) FROM PUBLIC;
GRANT EXECUTE ON PROCEDURE rolebyte.chart_position_permissions_set(jsonb, jsonb) TO rolebyte_public;

-- chart_position_user_type_set — the user type whoever sits in a position
-- receives, or none (userTypeId empty): they keep their own. Input {actor,
-- tenantId, positionId, userTypeId?}.
CREATE OR REPLACE PROCEDURE rolebyte.chart_position_user_type_set(IN pi_data jsonb, INOUT po_data jsonb)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = rolebyte, util, pg_temp
AS $$
DECLARE
    v_actor  text := NULLIF(btrim(pi_data->>'actor'), '');
    v_tenant text := NULLIF(btrim(pi_data->>'tenantId'), '');
    v_id     text := NULLIF(btrim(pi_data->>'positionId'), '');
    v_type   text := NULLIF(btrim(COALESCE(pi_data->>'userTypeId', '')), '');
    v_before text;
BEGIN
    IF v_actor IS NULL OR v_tenant IS NULL OR v_id IS NULL THEN
        po_data := util.result_error('membership:invalid', 'actor, tenantId and positionId are required');
        RETURN;
    END IF;
    IF NOT rolebyte.chart_entitled(v_tenant) THEN
        po_data := util.result_error('membership:conflict', 'the workspace does not include the chart of authority');
        RETURN;
    END IF;
    SELECT user_type_id INTO v_before FROM rolebyte.chart_position WHERE tenant_id = v_tenant AND id = v_id FOR UPDATE;
    IF NOT FOUND THEN
        po_data := util.result_error('membership:not_found', 'no such position');
        RETURN;
    END IF;
    IF v_type IS NOT NULL AND NOT EXISTS (SELECT 1 FROM rolebyte.user_type WHERE tenant_id = v_tenant AND id = v_type) THEN
        po_data := util.result_error('membership:invalid', 'that is not one of the tenant''s user types');
        RETURN;
    END IF;

    IF v_type IS DISTINCT FROM v_before THEN
        UPDATE rolebyte.chart_position SET user_type_id = v_type WHERE id = v_id;
        INSERT INTO rolebyte.event (id, actor, tenant_id, kind, payload)
        VALUES (util.generate_ulid(), v_actor, v_tenant, 'chartPositionUserTypeSet',
                jsonb_build_object('positionId', v_id, 'userTypeId', COALESCE(v_type, ''), 'from', COALESCE(v_before, '')));
    END IF;

    po_data := util.result_success(rolebyte.chart_position_json(v_id));
EXCEPTION
    WHEN sqlstate 'P0001' THEN
        RAISE;
    WHEN OTHERS THEN
        RAISE EXCEPTION '%', util.result_error('membership:error', sqlerrm) USING errcode = 'P0001';
END;
$$;
REVOKE ALL ON PROCEDURE rolebyte.chart_position_user_type_set(jsonb, jsonb) FROM PUBLIC;
GRANT EXECUTE ON PROCEDURE rolebyte.chart_position_user_type_set(jsonb, jsonb) TO rolebyte_public;

-- chart_person_place — a person into a position; a person already in another
-- moves. Only a person who is a member of the tenant, never a machine member nor
-- one who has left. Input {actor, tenantId, userId, positionId}.
CREATE OR REPLACE PROCEDURE rolebyte.chart_person_place(IN pi_data jsonb, INOUT po_data jsonb)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = rolebyte, util, pg_temp
AS $$
DECLARE
    v_actor  text := NULLIF(btrim(pi_data->>'actor'), '');
    v_tenant text := NULLIF(btrim(pi_data->>'tenantId'), '');
    v_user   text := NULLIF(btrim(pi_data->>'userId'), '');
    v_pos    text := NULLIF(btrim(pi_data->>'positionId'), '');
    v_member rolebyte.user_account%ROWTYPE;
    v_before text;
BEGIN
    IF v_actor IS NULL OR v_tenant IS NULL OR v_user IS NULL OR v_pos IS NULL THEN
        po_data := util.result_error('membership:invalid', 'actor, tenantId, userId and positionId are required');
        RETURN;
    END IF;
    IF NOT rolebyte.chart_entitled(v_tenant) THEN
        po_data := util.result_error('membership:conflict', 'the workspace does not include the chart of authority');
        RETURN;
    END IF;
    IF NOT EXISTS (SELECT 1 FROM rolebyte.chart_position WHERE tenant_id = v_tenant AND id = v_pos) THEN
        po_data := util.result_error('membership:not_found', 'no such position');
        RETURN;
    END IF;
    SELECT * INTO v_member FROM rolebyte.user_account WHERE tenant_id = v_tenant AND id = v_user FOR UPDATE;
    IF NOT FOUND THEN
        po_data := util.result_error('membership:not_found', 'no such member');
        RETURN;
    END IF;
    IF v_member.subject_key NOT LIKE 'sub:%' THEN
        po_data := util.result_error('membership:invalid', 'only a person sits in the chart, not a service account');
        RETURN;
    END IF;
    IF v_member.status = 'revoked' THEN
        po_data := util.result_error('membership:conflict', 'this person no longer has access to the workspace');
        RETURN;
    END IF;

    SELECT position_id INTO v_before FROM rolebyte.chart_holder WHERE tenant_id = v_tenant AND user_id = v_user;
    IF v_before IS DISTINCT FROM v_pos THEN
        INSERT INTO rolebyte.chart_holder (tenant_id, user_id, position_id)
        VALUES (v_tenant, v_user, v_pos)
        ON CONFLICT (tenant_id, user_id) DO UPDATE SET position_id = EXCLUDED.position_id, placed_at = now();
        INSERT INTO rolebyte.event (id, actor, tenant_id, user_id, kind, payload)
        VALUES (util.generate_ulid(), v_actor, v_tenant, v_user, 'chartPersonPlaced',
                jsonb_build_object('positionId', v_pos, 'from', COALESCE(v_before, '')));
    END IF;

    po_data := util.result_success(rolebyte.chart_position_json(v_pos));
EXCEPTION
    WHEN sqlstate 'P0001' THEN
        RAISE;
    WHEN OTHERS THEN
        RAISE EXCEPTION '%', util.result_error('membership:error', sqlerrm) USING errcode = 'P0001';
END;
$$;
REVOKE ALL ON PROCEDURE rolebyte.chart_person_place(jsonb, jsonb) FROM PUBLIC;
GRANT EXECUTE ON PROCEDURE rolebyte.chart_person_place(jsonb, jsonb) TO rolebyte_public;

-- chart_person_remove — a person out of the chart. Input {actor, tenantId, userId}.
CREATE OR REPLACE PROCEDURE rolebyte.chart_person_remove(IN pi_data jsonb, INOUT po_data jsonb)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = rolebyte, util, pg_temp
AS $$
DECLARE
    v_actor  text := NULLIF(btrim(pi_data->>'actor'), '');
    v_tenant text := NULLIF(btrim(pi_data->>'tenantId'), '');
    v_user   text := NULLIF(btrim(pi_data->>'userId'), '');
    v_before text;
BEGIN
    IF v_actor IS NULL OR v_tenant IS NULL OR v_user IS NULL THEN
        po_data := util.result_error('membership:invalid', 'actor, tenantId and userId are required');
        RETURN;
    END IF;
    IF NOT rolebyte.chart_entitled(v_tenant) THEN
        po_data := util.result_error('membership:conflict', 'the workspace does not include the chart of authority');
        RETURN;
    END IF;
    SELECT position_id INTO v_before
      FROM rolebyte.chart_holder WHERE tenant_id = v_tenant AND user_id = v_user FOR UPDATE;
    IF NOT FOUND THEN
        po_data := util.result_error('membership:not_found', 'this person is in no position');
        RETURN;
    END IF;

    DELETE FROM rolebyte.chart_holder WHERE tenant_id = v_tenant AND user_id = v_user;
    INSERT INTO rolebyte.event (id, actor, tenant_id, user_id, kind, payload)
    VALUES (util.generate_ulid(), v_actor, v_tenant, v_user, 'chartPersonRemoved',
            jsonb_build_object('positionId', v_before));

    po_data := util.result_success(jsonb_build_object('userId', v_user));
EXCEPTION
    WHEN sqlstate 'P0001' THEN
        RAISE;
    WHEN OTHERS THEN
        RAISE EXCEPTION '%', util.result_error('membership:error', sqlerrm) USING errcode = 'P0001';
END;
$$;
REVOKE ALL ON PROCEDURE rolebyte.chart_person_remove(jsonb, jsonb) FROM PUBLIC;
GRANT EXECUTE ON PROCEDURE rolebyte.chart_person_remove(jsonb, jsonb) TO rolebyte_public;

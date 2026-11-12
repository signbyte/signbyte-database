-- R (repeatable): the deployment's door. The procedures through which the register's
-- own role opens a company, says which products a company has, names a company's
-- administrators and the deployment's administrators, and keeps the catalog of products
-- with the service accounts of each.
--
-- Every procedure here that takes a caller proves first, in its own transaction, that
-- the calling PERSON is an administrator of the deployment right now
-- (`deployment_door_refusal`): the check comes before every other check and before any
-- read of a company, and every reason for refusing answers the same sentence, so the
-- answer tells a caller nothing about which part failed. `deployment_door_check` is that
-- check and nothing else, for a caller that wants it answered before it goes on to ask
-- another service. A procedure that writes then takes the deployment's lock and asks
-- again, so a person taken off the list while the call waited is refused. The lock is
-- taken before any company or account row is locked, the order `user_revoke` documents:
-- the deployment's lock, then the company's administrators' lock, then the account rows.
--
-- A refusal found before the first write is returned; one found after a write is
-- raised, so nothing stands. Every input is checked before the first write wherever
-- that can be done. No refusal of the door carries a person's name or a key a caller
-- sent; a refusal names a product's key only where it says which product is needed.
--
-- Two procedures take no caller's check. `local_company_follow` is run by the register
-- for itself at its start. `products_register` is run as the location's owner and is
-- granted to nobody.

-- door_name — a name the door accepts, trimmed: a JSON string of 1 to 200 characters
-- with no control character after trimming. NULL for anything else.
CREATE OR REPLACE FUNCTION rolebyte.door_name(p_value jsonb)
RETURNS text
LANGUAGE sql
IMMUTABLE
SET search_path = pg_temp
AS $$
    SELECT CASE
               WHEN jsonb_typeof(p_value) = 'string'
                AND char_length(btrim(p_value #>> '{}')) BETWEEN 1 AND 200
                AND btrim(p_value #>> '{}') !~ '[[:cntrl:]]'
               THEN btrim(p_value #>> '{}')
           END;
$$;

REVOKE ALL ON FUNCTION rolebyte.door_name(jsonb) FROM PUBLIC;

-- door_language — the language a call names: exactly `en` or `lv`, else NULL. Nothing
-- is read as English when it is absent or unknown.
CREATE OR REPLACE FUNCTION rolebyte.door_language(p_value jsonb)
RETURNS text
LANGUAGE sql
IMMUTABLE
SET search_path = pg_temp
AS $$
    SELECT CASE WHEN jsonb_typeof(p_value) = 'string' AND (p_value #>> '{}') IN ('en', 'lv')
                THEN p_value #>> '{}' END;
$$;

REVOKE ALL ON FUNCTION rolebyte.door_language(jsonb) FROM PUBLIC;

-- product_offered — whether this deployment offers the product: it is in the catalog,
-- gives at least one service, and every service it gives carries at least one permission
-- that is not retired.
CREATE OR REPLACE FUNCTION rolebyte.product_offered(p_key text)
RETURNS boolean
LANGUAGE sql
STABLE
SET search_path = rolebyte, pg_temp
AS $$
    SELECT EXISTS (SELECT 1 FROM rolebyte.product p WHERE p.key = p_key)
       AND EXISTS (SELECT 1 FROM rolebyte.product_entitlement pe WHERE pe.product_key = p_key)
       AND NOT EXISTS (SELECT 1 FROM rolebyte.product_entitlement pe
                        WHERE pe.product_key = p_key
                          AND NOT EXISTS (SELECT 1 FROM rolebyte.service_permission sp
                                           WHERE sp.service_key = pe.service_key AND sp.retired_at IS NULL));
$$;

REVOKE ALL ON FUNCTION rolebyte.product_offered(text) FROM PUBLIC;

-- door_services_declared — whether any service other than the register itself has
-- declared itself.
CREATE OR REPLACE FUNCTION rolebyte.door_services_declared()
RETURNS boolean
LANGUAGE sql
STABLE
SET search_path = rolebyte, pg_temp
AS $$
    SELECT EXISTS (SELECT 1 FROM rolebyte.service s WHERE s.key <> 'rolebyte');
$$;

REVOKE ALL ON FUNCTION rolebyte.door_services_declared() FROM PUBLIC;

-- deployment_door_refusal — the caller's check. NULL when the caller passes. The
-- answer is `membership:forbidden` with one sentence for every reason, unless all of
-- these hold: the mode is `saas`; the actor is a person's key; a company is marked as
-- the deployment's own and is active; the actor has an active account in it; and that
-- account is on the list of the deployment's administrators.
CREATE OR REPLACE FUNCTION rolebyte.deployment_door_refusal(p_actor text, p_mode text)
RETURNS jsonb
LANGUAGE plpgsql
STABLE
SET search_path = rolebyte, util, pg_temp
AS $$
BEGIN
    IF p_mode IS DISTINCT FROM 'saas'
       OR (starts_with(p_actor, 'sub:') AND rolebyte.is_typed_subject_key(p_actor)) IS NOT TRUE
       OR NOT EXISTS (SELECT 1
                        FROM rolebyte.deployment d
                        JOIN rolebyte.tenant t ON t.id = d.company_tenant_id AND t.status = 'active'
                        JOIN rolebyte.user_account u ON u.tenant_id = t.id
                                                    AND u.subject_key = p_actor
                                                    AND u.status = 'active'
                        JOIN rolebyte.deployment_admin da ON da.user_id = u.id) THEN
        RETURN util.result_error('membership:forbidden', 'not a deployment administrator');
    END IF;
    RETURN NULL;
END;
$$;

REVOKE ALL ON FUNCTION rolebyte.deployment_door_refusal(text, text) FROM PUBLIC;

-- door_first_run_refusal — the caller's check of `company_first_run`. On `saas` it is
-- the deployment's door check. On `local` the caller is a person with an active
-- account in the marked company who is an administrator of it now; no company marked
-- is refused the same way.
CREATE OR REPLACE FUNCTION rolebyte.door_first_run_refusal(p_actor text, p_mode text)
RETURNS jsonb
LANGUAGE plpgsql
STABLE
SET search_path = rolebyte, util, pg_temp
AS $$
BEGIN
    IF p_mode = 'saas' THEN
        RETURN rolebyte.deployment_door_refusal(p_actor, p_mode);
    END IF;
    IF p_mode IS DISTINCT FROM 'local'
       OR (starts_with(p_actor, 'sub:') AND rolebyte.is_typed_subject_key(p_actor)) IS NOT TRUE
       OR NOT EXISTS (SELECT 1
                        FROM rolebyte.deployment d
                        JOIN rolebyte.user_account u ON u.tenant_id = d.company_tenant_id
                                                    AND u.subject_key = p_actor
                                                    AND u.status = 'active'
                       WHERE rolebyte.is_administrator(u.id)) THEN
        RETURN util.result_error('membership:forbidden', 'not a deployment administrator');
    END IF;
    RETURN NULL;
END;
$$;

REVOKE ALL ON FUNCTION rolebyte.door_first_run_refusal(text, text) FROM PUBLIC;

-- door_enter — what every procedure of the door does first. A missing actor or a mode
-- that is neither `saas` nor `local` is `membership:invalid`. Then the caller's check.
-- A procedure that writes (`p_write`) then takes the deployment's lock and asks again,
-- because who the caller is can change while the call waits for the lock. NULL when
-- the caller may go on.
CREATE OR REPLACE FUNCTION rolebyte.door_enter(pi_data jsonb, p_write boolean, p_first_run boolean)
RETURNS jsonb
LANGUAGE plpgsql
VOLATILE
SET search_path = rolebyte, util, pg_temp
AS $$
DECLARE
    v_actor   text := NULLIF(trim(pi_data->>'actor'), '');
    v_mode    text := pi_data->>'mode';
    v_refusal jsonb;
BEGIN
    IF v_actor IS NULL OR v_mode IS NULL OR v_mode NOT IN ('saas', 'local') THEN
        RETURN util.result_error('membership:invalid', 'actor is required and mode is saas or local');
    END IF;

    IF p_first_run THEN
        v_refusal := rolebyte.door_first_run_refusal(v_actor, v_mode);
    ELSE
        v_refusal := rolebyte.deployment_door_refusal(v_actor, v_mode);
    END IF;
    IF v_refusal IS NOT NULL OR NOT p_write THEN
        RETURN v_refusal;
    END IF;

    PERFORM pg_advisory_xact_lock(hashtextextended('rolebyte.deployment', 0));

    IF p_first_run THEN
        RETURN rolebyte.door_first_run_refusal(v_actor, v_mode);
    END IF;
    RETURN rolebyte.deployment_door_refusal(v_actor, v_mode);
END;
$$;

REVOKE ALL ON FUNCTION rolebyte.door_enter(jsonb, boolean, boolean) FROM PUBLIC;

-- door_entitle — give a company a whole service (empty feature) or one feature of it,
-- as `entitlement_grant` does: a revoked row flips back, one already in force changes
-- nothing. The history line is written only when something changed. Answers whether
-- it changed.
CREATE OR REPLACE FUNCTION rolebyte.door_entitle(p_actor text, p_tenant text, p_service text, p_feature text)
RETURNS boolean
LANGUAGE plpgsql
VOLATILE
SET search_path = rolebyte, util, pg_temp
AS $$
DECLARE
    v_changed boolean;
BEGIN
    INSERT INTO rolebyte.tenant_entitlement (id, tenant_id, service_key, feature_key)
    VALUES (util.generate_ulid(), p_tenant, p_service, p_feature)
    ON CONFLICT (tenant_id, service_key, feature_key)
        DO UPDATE SET state = 'entitled', entitled_at = now(), revoked_at = NULL
        WHERE rolebyte.tenant_entitlement.state = 'revoked';
    v_changed := FOUND;

    IF v_changed THEN
        INSERT INTO rolebyte.event (id, actor, tenant_id, user_id, kind, payload)
        VALUES (util.generate_ulid(), p_actor, p_tenant, NULL, 'tenantEntitled',
                jsonb_build_object('service', p_service, 'feature', p_feature));
    END IF;
    RETURN v_changed;
END;
$$;

REVOKE ALL ON FUNCTION rolebyte.door_entitle(text, text, text, text) FROM PUBLIC;

-- door_revoke_row — take one entitlement row of a company away, as `entitlement_revoke`
-- does. Answers whether it changed.
CREATE OR REPLACE FUNCTION rolebyte.door_revoke_row(p_actor text, p_tenant text, p_service text, p_feature text)
RETURNS boolean
LANGUAGE plpgsql
VOLATILE
SET search_path = rolebyte, util, pg_temp
AS $$
DECLARE
    v_changed boolean;
BEGIN
    UPDATE rolebyte.tenant_entitlement
       SET state = 'revoked', revoked_at = now()
     WHERE tenant_id = p_tenant AND service_key = p_service AND feature_key = p_feature AND state = 'entitled';
    v_changed := FOUND;
    IF v_changed THEN
        INSERT INTO rolebyte.event (id, actor, tenant_id, user_id, kind, payload)
        VALUES (util.generate_ulid(), p_actor, p_tenant, NULL, 'tenantEntitlementRevoked',
                jsonb_build_object('service', p_service, 'feature', p_feature));
    END IF;
    RETURN v_changed;
END;
$$;

REVOKE ALL ON FUNCTION rolebyte.door_revoke_row(text, text, text, text) FROM PUBLIC;

-- door_topo — the product keys given, ordered so that a product comes after every
-- product it needs that is also in the list. Keys that form a circle (the catalog
-- refuses one) come last.
CREATE OR REPLACE FUNCTION rolebyte.door_topo(p_keys text[])
RETURNS text[]
LANGUAGE plpgsql
STABLE
SET search_path = rolebyte, pg_temp
AS $$
DECLARE
    v_out  text[] := '{}'::text[];
    v_rest text[] := p_keys;
    v_next text[];
BEGIN
    WHILE COALESCE(array_length(v_rest, 1), 0) > 0 LOOP
        SELECT COALESCE(array_agg(k ORDER BY k COLLATE "C"), '{}'::text[]) INTO v_next
          FROM unnest(v_rest) k
         WHERE NOT EXISTS (SELECT 1 FROM rolebyte.product_requirement r
                            WHERE r.product_key = k AND r.requires_key = ANY (v_rest));
        IF COALESCE(array_length(v_next, 1), 0) = 0 THEN
            v_out := v_out || v_rest;
            EXIT;
        END IF;
        v_out := v_out || v_next;
        v_rest := ARRAY(SELECT k FROM unnest(v_rest) k WHERE k <> ALL (v_next));
    END LOOP;
    RETURN v_out;
END;
$$;

REVOKE ALL ON FUNCTION rolebyte.door_topo(text[]) FROM PUBLIC;

-- door_ticked — whether the company has the product: ticked and not taken away.
CREATE OR REPLACE FUNCTION rolebyte.door_ticked(p_tenant text, p_product text)
RETURNS boolean
LANGUAGE sql
STABLE
SET search_path = rolebyte, pg_temp
AS $$
    SELECT EXISTS (SELECT 1 FROM rolebyte.tenant_product tp
                    WHERE tp.tenant_id = p_tenant AND tp.product_key = p_product AND tp.state = 'ticked');
$$;

REVOKE ALL ON FUNCTION rolebyte.door_ticked(text, text) FROM PUBLIC;

-- door_need_missing — the first product, by key, that the product needs and the company
-- has not ticked; NULL when it has them all.
CREATE OR REPLACE FUNCTION rolebyte.door_need_missing(p_tenant text, p_product text)
RETURNS text
LANGUAGE sql
STABLE
SET search_path = rolebyte, pg_temp
AS $$
    SELECT r.requires_key
      FROM rolebyte.product_requirement r
     WHERE r.product_key = p_product AND NOT rolebyte.door_ticked(p_tenant, r.requires_key)
     ORDER BY r.requires_key COLLATE "C"
     LIMIT 1;
$$;

REVOKE ALL ON FUNCTION rolebyte.door_need_missing(text, text) FROM PUBLIC;

-- door_tick — tick a product for a company: a product taken away is ticked again, one
-- already ticked changes nothing. `productTicked` is written only when something
-- changed; `p_adopted` marks a tick the register made for a company that already held
-- everything the product gives. Answers whether it changed.
CREATE OR REPLACE FUNCTION rolebyte.door_tick(p_actor text, p_tenant text, p_product text, p_adopted boolean)
RETURNS boolean
LANGUAGE plpgsql
VOLATILE
SET search_path = rolebyte, util, pg_temp
AS $$
DECLARE
    v_changed boolean;
BEGIN
    INSERT INTO rolebyte.tenant_product (tenant_id, product_key)
    VALUES (p_tenant, p_product)
    ON CONFLICT (tenant_id, product_key)
        DO UPDATE SET state = 'ticked', ticked_at = now(), unticked_at = NULL
        WHERE rolebyte.tenant_product.state = 'unticked';
    v_changed := FOUND;
    IF v_changed THEN
        INSERT INTO rolebyte.event (id, actor, tenant_id, user_id, kind, payload)
        VALUES (util.generate_ulid(), p_actor, p_tenant, NULL, 'productTicked',
                CASE WHEN p_adopted THEN jsonb_build_object('product', p_product, 'adopted', true)
                     ELSE jsonb_build_object('product', p_product) END);
    END IF;
    RETURN v_changed;
END;
$$;

REVOKE ALL ON FUNCTION rolebyte.door_tick(text, text, text, boolean) FROM PUBLIC;

-- door_product_give — give a company every entitlement a product carries. Answers
-- whether any changed.
CREATE OR REPLACE FUNCTION rolebyte.door_product_give(p_actor text, p_tenant text, p_product text)
RETURNS boolean
LANGUAGE plpgsql
VOLATILE
SET search_path = rolebyte, util, pg_temp
AS $$
DECLARE
    v_row     record;
    v_changed boolean := false;
BEGIN
    FOR v_row IN SELECT pe.service_key, pe.feature_key FROM rolebyte.product_entitlement pe
                  WHERE pe.product_key = p_product
                  ORDER BY pe.service_key COLLATE "C", pe.feature_key COLLATE "C" LOOP
        IF rolebyte.door_entitle(p_actor, p_tenant, v_row.service_key, v_row.feature_key) THEN
            v_changed := true;
        END IF;
    END LOOP;
    RETURN v_changed;
END;
$$;

REVOKE ALL ON FUNCTION rolebyte.door_product_give(text, text, text) FROM PUBLIC;

-- door_product_take — take away the entitlements of a product just unticked for a
-- company. What no other ticked product gives is revoked. Where the product gave a whole
-- service and no other ticked product gives anything of that service, every row of that
-- service the company holds is revoked, feature rows written by hand included. Answers
-- whether any changed.
CREATE OR REPLACE FUNCTION rolebyte.door_product_take(p_actor text, p_tenant text, p_product text)
RETURNS boolean
LANGUAGE plpgsql
VOLATILE
SET search_path = rolebyte, util, pg_temp
AS $$
DECLARE
    v_row     record;
    v_feature text;
    v_changed boolean := false;
BEGIN
    FOR v_row IN SELECT pe.service_key, pe.feature_key FROM rolebyte.product_entitlement pe
                  WHERE pe.product_key = p_product
                  ORDER BY pe.service_key COLLATE "C", pe.feature_key COLLATE "C" LOOP
        IF v_row.feature_key = ''
           AND NOT EXISTS (SELECT 1 FROM rolebyte.tenant_product tp
                             JOIN rolebyte.product_entitlement o ON o.product_key = tp.product_key
                            WHERE tp.tenant_id = p_tenant AND tp.state = 'ticked'
                              AND o.service_key = v_row.service_key) THEN
            FOR v_feature IN SELECT e.feature_key FROM rolebyte.tenant_entitlement e
                              WHERE e.tenant_id = p_tenant AND e.service_key = v_row.service_key
                                AND e.state = 'entitled'
                              ORDER BY e.feature_key COLLATE "C" LOOP
                IF rolebyte.door_revoke_row(p_actor, p_tenant, v_row.service_key, v_feature) THEN
                    v_changed := true;
                END IF;
            END LOOP;
        ELSIF NOT EXISTS (SELECT 1 FROM rolebyte.tenant_product tp
                            JOIN rolebyte.product_entitlement o ON o.product_key = tp.product_key
                           WHERE tp.tenant_id = p_tenant AND tp.state = 'ticked'
                             AND o.service_key = v_row.service_key AND o.feature_key = v_row.feature_key) THEN
            IF rolebyte.door_revoke_row(p_actor, p_tenant, v_row.service_key, v_row.feature_key) THEN
                v_changed := true;
            END IF;
        END IF;
    END LOOP;
    RETURN v_changed;
END;
$$;

REVOKE ALL ON FUNCTION rolebyte.door_product_take(text, text, text) FROM PUBLIC;

-- door_company_json — a company as the door's reads answer it: id, name, status, when
-- it was made, whether it is the deployment's own, the products it has, what it is
-- entitled to in force, and how many administrators it has. With `p_detail` each
-- entitlement also says when it was given.
CREATE OR REPLACE FUNCTION rolebyte.door_company_json(p_tenant text, p_detail boolean)
RETURNS jsonb
LANGUAGE plpgsql
STABLE
SET search_path = rolebyte, util, pg_temp
AS $$
BEGIN
    RETURN (SELECT jsonb_build_object(
        'id',        t.id,
        'name',      t.name,
        'status',    t.status,
        'createdAt', t.created_at,
        'own',       EXISTS (SELECT 1 FROM rolebyte.deployment d WHERE d.company_tenant_id = t.id),
        'products',  COALESCE((
            SELECT jsonb_agg(tp.product_key ORDER BY tp.product_key COLLATE "C")
              FROM rolebyte.tenant_product tp
             WHERE tp.tenant_id = t.id AND tp.state = 'ticked'), '[]'::jsonb),
        'entitlements', COALESCE((
            SELECT jsonb_agg(jsonb_build_object('service', e.service_key, 'feature', e.feature_key)
                             || CASE WHEN p_detail THEN jsonb_build_object('entitledAt', e.entitled_at)
                                     ELSE '{}'::jsonb END
                             ORDER BY e.service_key COLLATE "C", e.feature_key COLLATE "C")
              FROM rolebyte.tenant_entitlement e
             WHERE e.tenant_id = t.id AND e.state = 'entitled'), '[]'::jsonb),
        'administrators', (SELECT count(*) FROM rolebyte.user_account u
                            WHERE u.tenant_id = t.id AND rolebyte.is_administrator(u.id)))
      FROM rolebyte.tenant t
     WHERE t.id = p_tenant);
END;
$$;

REVOKE ALL ON FUNCTION rolebyte.door_company_json(text, boolean) FROM PUBLIC;

-- product_accounts_follow — make a company's service accounts match the products it has.
-- The wanted members are the accounts listed for any product ticked for the company; an
-- account wanted through several products holds the union of their levels.
--   * A wanted account that does not exist is made, active at once, under the company's
--     default user type (`userTypeAssigned`, `serviceAccountAdded`).
--   * A wanted account that is revoked or invited is made active (`serviceAccountAdded`).
--   * Its levels are made equal to the wanted set (`roleGranted`, `roleRevoked`). An
--     administrator's level is never given and never taken away here, whatever the
--     account holds.
--   * An account whose key is listed but is not wanted here, and is not revoked, loses
--     its levels and is ended as `user_revoke` ends a removed member: revoked, its note
--     cleared and its seat in the chart left, with the same history lines
--     (`userRevoked`, `noteChanged`, `chartPersonRemoved`, then `serviceAccountRemoved`).
-- For an account on the list the list decides. An account whose key is on no list, and
-- a person, is never touched, except an account named in `p_ended`: the keys that a
-- product ticked for this company listed until the list was entered again and that no
-- ticked product lists now. Such an account is ended exactly as one is that is listed but
-- not wanted, by the same loop below.
--
-- Before an account is ended the company's last-administrator guard is asked
-- (`administrator_removal_refusal`); if it refuses, the whole act is raised as
-- `membership:conflict`, 'a company keeps at least one administrator', and nothing stands.
--
-- The company's administrators' lock is taken first, then the company's row, then the
-- account rows: the order `administrator_make` takes them (the lock, then the row through
-- the default user type). Answers {added, removed, changed}: the keys made or made
-- active again, the keys ended, and whether anything changed at all, a level granted or
-- revoked included.
DROP FUNCTION IF EXISTS rolebyte.product_accounts_follow(text, text);

CREATE OR REPLACE FUNCTION rolebyte.product_accounts_follow(p_actor text, p_tenant text,
                                                            p_ended text[] DEFAULT '{}'::text[])
RETURNS jsonb
LANGUAGE plpgsql
VOLATILE
SET search_path = rolebyte, util, pg_temp
AS $$
DECLARE
    v_ident   record;
    v_user    rolebyte.user_account%ROWTYPE;
    v_def     record;
    v_type    text;
    v_seat    text;
    v_wanted  text[];
    v_added   text[] := '{}'::text[];
    v_removed text[] := '{}'::text[];
    v_changed boolean := false;
    v_refusal jsonb;
BEGIN
    PERFORM rolebyte.administrator_lock(p_tenant);
    PERFORM 1 FROM rolebyte.tenant WHERE id = p_tenant FOR UPDATE;

    FOR v_ident IN
        SELECT pa.subject_key,
               (array_agg(pa.display_name ORDER BY pa.product_key COLLATE "C"))[1] AS display_name
          FROM rolebyte.product_account pa
         WHERE rolebyte.door_ticked(p_tenant, pa.product_key)
         GROUP BY pa.subject_key
         ORDER BY pa.subject_key COLLATE "C"
    LOOP
        SELECT * INTO v_user
          FROM rolebyte.user_account
         WHERE tenant_id = p_tenant AND subject_key = v_ident.subject_key
           FOR UPDATE;

        IF NOT FOUND THEN
            v_type := rolebyte.ensure_default_user_type(p_actor, p_tenant, NULL);
            INSERT INTO rolebyte.user_account (id, tenant_id, subject_key, display_name, status,
                                               user_type_id, user_type_source)
            VALUES (util.generate_ulid(), p_tenant, v_ident.subject_key, v_ident.display_name, 'active',
                    v_type, 'workspaceDefault')
            RETURNING * INTO v_user;
            INSERT INTO rolebyte.event (id, actor, tenant_id, user_id, kind, payload)
            VALUES (util.generate_ulid(), p_actor, p_tenant, v_user.id, 'userTypeAssigned',
                    jsonb_build_object('userTypeId', v_type, 'from', '', 'source', 'workspaceDefault'));
            INSERT INTO rolebyte.event (id, actor, tenant_id, user_id, kind, payload)
            VALUES (util.generate_ulid(), p_actor, p_tenant, v_user.id, 'serviceAccountAdded',
                    jsonb_build_object('subjectKey', v_ident.subject_key));
            v_added := array_append(v_added, v_ident.subject_key);
            v_changed := true;
        ELSIF v_user.status <> 'active' THEN
            UPDATE rolebyte.user_account SET status = 'active' WHERE id = v_user.id;
            INSERT INTO rolebyte.event (id, actor, tenant_id, user_id, kind, payload)
            VALUES (util.generate_ulid(), p_actor, p_tenant, v_user.id, 'serviceAccountAdded',
                    jsonb_build_object('subjectKey', v_ident.subject_key));
            v_added := array_append(v_added, v_ident.subject_key);
            v_changed := true;
        END IF;

        SELECT COALESCE(array_agg(DISTINCT rd.id), '{}'::text[]) INTO v_wanted
          FROM rolebyte.product_account pa
         CROSS JOIN LATERAL jsonb_array_elements(pa.roles) r
          JOIN rolebyte.role_definition rd ON rd.service_key = r->>'service'
                                          AND rd.role_group = r->>'group'
                                          AND rd.role_level = r->>'level'
         WHERE pa.subject_key = v_ident.subject_key
           AND rolebyte.door_ticked(p_tenant, pa.product_key)
           AND NOT rolebyte.is_administrator_rung(rd.role_group, rd.role_level);

        FOR v_def IN
            SELECT rd.id, rd.service_key, rd.role_group, rd.role_level
              FROM rolebyte.role_definition rd
             WHERE rd.id = ANY (v_wanted)
             ORDER BY rd.service_key, rd.role_group, rd.role_level
        LOOP
            INSERT INTO rolebyte.assignment (id, user_id, role_definition_id)
            VALUES (util.generate_ulid(), v_user.id, v_def.id)
            ON CONFLICT (user_id, role_definition_id)
                DO UPDATE SET state = 'granted', granted_at = now(), revoked_at = NULL
                WHERE rolebyte.assignment.state = 'revoked';
            IF FOUND THEN
                INSERT INTO rolebyte.event (id, actor, tenant_id, user_id, kind, payload)
                VALUES (util.generate_ulid(), p_actor, p_tenant, v_user.id, 'roleGranted',
                        jsonb_build_object('service', v_def.service_key, 'group', v_def.role_group,
                                           'level', v_def.role_level));
                v_changed := true;
            END IF;
        END LOOP;

        FOR v_def IN
            UPDATE rolebyte.assignment a
               SET state = 'revoked', revoked_at = now()
              FROM rolebyte.role_definition rd
             WHERE rd.id = a.role_definition_id
               AND a.user_id = v_user.id
               AND a.state = 'granted'
               AND rd.id <> ALL (v_wanted)
               AND NOT rolebyte.is_administrator_rung(rd.role_group, rd.role_level)
            RETURNING rd.service_key, rd.role_group, rd.role_level
        LOOP
            INSERT INTO rolebyte.event (id, actor, tenant_id, user_id, kind, payload)
            VALUES (util.generate_ulid(), p_actor, p_tenant, v_user.id, 'roleRevoked',
                    jsonb_build_object('service', v_def.service_key, 'group', v_def.role_group,
                                       'level', v_def.role_level));
            v_changed := true;
        END LOOP;
    END LOOP;

    FOR v_user IN
        SELECT u.*
          FROM rolebyte.user_account u
         WHERE u.tenant_id = p_tenant
           AND u.status <> 'revoked'
           AND (EXISTS (SELECT 1 FROM rolebyte.product_account pa WHERE pa.subject_key = u.subject_key)
                OR u.subject_key = ANY (COALESCE(p_ended, '{}'::text[])))
           AND NOT EXISTS (SELECT 1
                             FROM rolebyte.product_account pa
                            WHERE pa.subject_key = u.subject_key
                              AND rolebyte.door_ticked(p_tenant, pa.product_key))
         ORDER BY u.subject_key COLLATE "C"
           FOR UPDATE OF u
    LOOP
        -- A company keeps an administrator: the guard is asked before anything is ended.
        v_refusal := rolebyte.administrator_removal_refusal(p_tenant, v_user.id);
        IF v_refusal IS NOT NULL THEN
            RAISE EXCEPTION '%', util.result_error('membership:conflict', 'a company keeps at least one administrator')
                USING errcode = 'P0001';
        END IF;

        FOR v_def IN
            UPDATE rolebyte.assignment a
               SET state = 'revoked', revoked_at = now()
              FROM rolebyte.role_definition rd
             WHERE rd.id = a.role_definition_id
               AND a.user_id = v_user.id
               AND a.state = 'granted'
               AND NOT rolebyte.is_administrator_rung(rd.role_group, rd.role_level)
            RETURNING rd.service_key, rd.role_group, rd.role_level
        LOOP
            INSERT INTO rolebyte.event (id, actor, tenant_id, user_id, kind, payload)
            VALUES (util.generate_ulid(), p_actor, p_tenant, v_user.id, 'roleRevoked',
                    jsonb_build_object('service', v_def.service_key, 'group', v_def.role_group,
                                       'level', v_def.role_level));
        END LOOP;

        -- What `user_revoke` does for a removed member besides the status.
        UPDATE rolebyte.user_account SET status = 'revoked', note = '' WHERE id = v_user.id;
        INSERT INTO rolebyte.event (id, actor, tenant_id, user_id, kind, payload)
        VALUES (util.generate_ulid(), p_actor, p_tenant, v_user.id, 'userRevoked', '{}'::jsonb);
        IF v_user.note <> '' THEN
            INSERT INTO rolebyte.event (id, actor, tenant_id, user_id, kind, payload)
            VALUES (util.generate_ulid(), p_actor, p_tenant, v_user.id, 'noteChanged',
                    jsonb_build_object('cleared', true, 'revoked', true));
        END IF;
        v_seat := NULL;
        DELETE FROM rolebyte.chart_holder
         WHERE tenant_id = p_tenant AND user_id = v_user.id
        RETURNING position_id INTO v_seat;
        IF v_seat IS NOT NULL THEN
            INSERT INTO rolebyte.event (id, actor, tenant_id, user_id, kind, payload)
            VALUES (util.generate_ulid(), p_actor, p_tenant, v_user.id, 'chartPersonRemoved',
                    jsonb_build_object('positionId', v_seat, 'revoked', true));
        END IF;
        INSERT INTO rolebyte.event (id, actor, tenant_id, user_id, kind, payload)
        VALUES (util.generate_ulid(), p_actor, p_tenant, v_user.id, 'serviceAccountRemoved',
                jsonb_build_object('subjectKey', v_user.subject_key));
        v_removed := array_append(v_removed, v_user.subject_key);
        v_changed := true;
    END LOOP;

    RETURN jsonb_build_object('added', to_jsonb(v_added), 'removed', to_jsonb(v_removed),
                              'changed', v_changed);
END;
$$;

REVOKE ALL ON FUNCTION rolebyte.product_accounts_follow(text, text, text[]) FROM PUBLIC;

-- door_product_json — a product as `products_register` reads one: its key and name, what
-- it gives, what it needs and its accounts, each list in a fixed order, so that two
-- products can be compared. NULL when there is no such product.
CREATE OR REPLACE FUNCTION rolebyte.door_product_json(p_key text)
RETURNS jsonb
LANGUAGE plpgsql
STABLE
SET search_path = rolebyte, util, pg_temp
AS $$
BEGIN
    RETURN (SELECT jsonb_build_object(
        'key',         p.key,
        'displayName', p.display_name,
        'gives',       COALESCE((SELECT jsonb_agg(jsonb_build_object('service', pe.service_key, 'feature', pe.feature_key)
                                                  ORDER BY pe.service_key COLLATE "C", pe.feature_key COLLATE "C")
                                   FROM rolebyte.product_entitlement pe WHERE pe.product_key = p.key), '[]'::jsonb),
        'needs',       COALESCE((SELECT jsonb_agg(r.requires_key ORDER BY r.requires_key COLLATE "C")
                                   FROM rolebyte.product_requirement r WHERE r.product_key = p.key), '[]'::jsonb),
        'accounts',    COALESCE((SELECT jsonb_agg(jsonb_build_object('subjectKey', pa.subject_key,
                                                                     'displayName', pa.display_name,
                                                                     'roles', pa.roles)
                                                  ORDER BY pa.subject_key COLLATE "C")
                                   FROM rolebyte.product_account pa WHERE pa.product_key = p.key), '[]'::jsonb))
      FROM rolebyte.product p
     WHERE p.key = p_key);
END;
$$;

REVOKE ALL ON FUNCTION rolebyte.door_product_json(text) FROM PUBLIC;

-- ---------------------------------------------------------------------------
-- Reads. They take the caller's check and no lock.
-- ---------------------------------------------------------------------------

-- deployment_door_check — the caller's check and nothing else, for a caller that wants
-- it answered before it goes on to ask another service. Input {actor, mode}; answers
-- success with an empty object, or the refusal every procedure of the door gives.
CREATE OR REPLACE PROCEDURE rolebyte.deployment_door_check(IN pi_data jsonb, INOUT po_data jsonb)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = rolebyte, util, pg_temp
AS $$
DECLARE
    v_refusal jsonb;
BEGIN
    v_refusal := rolebyte.door_enter(pi_data, false, false);
    IF v_refusal IS NOT NULL THEN
        po_data := v_refusal;
        RETURN;
    END IF;
    po_data := util.result_success('{}'::jsonb);
EXCEPTION
    WHEN sqlstate 'P0001' THEN
        RAISE;
    WHEN OTHERS THEN
        RAISE EXCEPTION '%', util.result_error('membership:error', sqlerrm) USING errcode = 'P0001';
END;
$$;

REVOKE ALL ON PROCEDURE rolebyte.deployment_door_check(jsonb, jsonb) FROM PUBLIC;
GRANT EXECUTE ON PROCEDURE rolebyte.deployment_door_check(jsonb, jsonb) TO rolebyte_public;

-- company_list — every company, in the order it was made: {companies: [{id, name,
-- status, createdAt, own, products: [keys], entitlements: [{service, feature}],
-- administrators}]}. `own` is true for the deployment's own company, `products` are
-- the products it has, `entitlements` what it is entitled to in force, and
-- `administrators` is how many accounts are administrators of it now.
CREATE OR REPLACE PROCEDURE rolebyte.company_list(IN pi_data jsonb, INOUT po_data jsonb)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = rolebyte, util, pg_temp
AS $$
DECLARE
    v_refusal jsonb;
BEGIN
    v_refusal := rolebyte.door_enter(pi_data, false, false);
    IF v_refusal IS NOT NULL THEN
        po_data := v_refusal;
        RETURN;
    END IF;

    po_data := util.result_success(jsonb_build_object('companies', COALESCE((
        SELECT jsonb_agg(rolebyte.door_company_json(t.id, false) ORDER BY t.created_at, t.id)
          FROM rolebyte.tenant t), '[]'::jsonb)));
EXCEPTION
    WHEN sqlstate 'P0001' THEN
        RAISE;
    WHEN OTHERS THEN
        RAISE EXCEPTION '%', util.result_error('membership:error', sqlerrm) USING errcode = 'P0001';
END;
$$;

REVOKE ALL ON PROCEDURE rolebyte.company_list(jsonb, jsonb) FROM PUBLIC;
GRANT EXECUTE ON PROCEDURE rolebyte.company_list(jsonb, jsonb) TO rolebyte_public;

-- company_get — one company, with the same members as `company_list`, and each
-- entitlement also says when it was given (`entitledAt`): {company: {...}}. A missing
-- `tenantId` is `membership:invalid`, an unknown company `membership:not_found`.
CREATE OR REPLACE PROCEDURE rolebyte.company_get(IN pi_data jsonb, INOUT po_data jsonb)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = rolebyte, util, pg_temp
AS $$
DECLARE
    v_refusal jsonb;
    v_tenant  text := NULLIF(trim(pi_data->>'tenantId'), '');
BEGIN
    v_refusal := rolebyte.door_enter(pi_data, false, false);
    IF v_refusal IS NOT NULL THEN
        po_data := v_refusal;
        RETURN;
    END IF;
    IF v_tenant IS NULL THEN
        po_data := util.result_error('membership:invalid', 'tenantId is required');
        RETURN;
    END IF;
    IF NOT EXISTS (SELECT 1 FROM rolebyte.tenant WHERE id = v_tenant) THEN
        po_data := util.result_error('membership:not_found', 'no such company');
        RETURN;
    END IF;

    po_data := util.result_success(jsonb_build_object('company', rolebyte.door_company_json(v_tenant, true)));
EXCEPTION
    WHEN sqlstate 'P0001' THEN
        RAISE;
    WHEN OTHERS THEN
        RAISE EXCEPTION '%', util.result_error('membership:error', sqlerrm) USING errcode = 'P0001';
END;
$$;

REVOKE ALL ON PROCEDURE rolebyte.company_get(jsonb, jsonb) FROM PUBLIC;
GRANT EXECUTE ON PROCEDURE rolebyte.company_get(jsonb, jsonb) TO rolebyte_public;

-- company_administrators — the accounts that are administrators of a company now, by
-- display name then account id: {administrators: [{userId, subjectKey, displayName,
-- status, lastSignedInOn}]}. A revoked account is not one. An unknown company is
-- `membership:not_found`.
CREATE OR REPLACE PROCEDURE rolebyte.company_administrators(IN pi_data jsonb, INOUT po_data jsonb)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = rolebyte, util, pg_temp
AS $$
DECLARE
    v_refusal jsonb;
    v_tenant  text := NULLIF(trim(pi_data->>'tenantId'), '');
BEGIN
    v_refusal := rolebyte.door_enter(pi_data, false, false);
    IF v_refusal IS NOT NULL THEN
        po_data := v_refusal;
        RETURN;
    END IF;
    IF v_tenant IS NULL THEN
        po_data := util.result_error('membership:invalid', 'tenantId is required');
        RETURN;
    END IF;
    IF NOT EXISTS (SELECT 1 FROM rolebyte.tenant WHERE id = v_tenant) THEN
        po_data := util.result_error('membership:not_found', 'no such company');
        RETURN;
    END IF;

    po_data := util.result_success(jsonb_build_object('administrators', COALESCE((
        SELECT jsonb_agg(jsonb_build_object(
                   'userId',         u.id,
                   'subjectKey',     u.subject_key,
                   'displayName',    u.display_name,
                   'status',         u.status,
                   'lastSignedInOn', u.last_signed_in_on)
               ORDER BY u.display_name COLLATE "C", u.id COLLATE "C")
          FROM rolebyte.user_account u
         WHERE u.tenant_id = v_tenant AND rolebyte.is_administrator(u.id)), '[]'::jsonb)));
EXCEPTION
    WHEN sqlstate 'P0001' THEN
        RAISE;
    WHEN OTHERS THEN
        RAISE EXCEPTION '%', util.result_error('membership:error', sqlerrm) USING errcode = 'P0001';
END;
$$;

REVOKE ALL ON PROCEDURE rolebyte.company_administrators(jsonb, jsonb) FROM PUBLIC;
GRANT EXECUTE ON PROCEDURE rolebyte.company_administrators(jsonb, jsonb) TO rolebyte_public;

-- deployment_products — the products this deployment sells, by key: {products: [{key,
-- displayName, offered, needs: [keys], gives: [{service, feature, serviceName,
-- permissions, lastDeclaredAt}]}]}. A product is offered when every service it gives has
-- a permission that is not retired. For each service given, `permissions` counts its permissions that are not
-- retired and `lastDeclaredAt` is when a declaration of it was last accepted (null when
-- none was).
CREATE OR REPLACE PROCEDURE rolebyte.deployment_products(IN pi_data jsonb, INOUT po_data jsonb)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = rolebyte, util, pg_temp
AS $$
DECLARE
    v_refusal jsonb;
BEGIN
    v_refusal := rolebyte.door_enter(pi_data, false, false);
    IF v_refusal IS NOT NULL THEN
        po_data := v_refusal;
        RETURN;
    END IF;

    po_data := util.result_success(jsonb_build_object('products', COALESCE((
        SELECT jsonb_agg(jsonb_build_object(
                   'key',         p.key,
                   'displayName', p.display_name,
                   'offered',     rolebyte.product_offered(p.key),
                   'needs',       COALESCE((SELECT jsonb_agg(r.requires_key ORDER BY r.requires_key COLLATE "C")
                                              FROM rolebyte.product_requirement r
                                             WHERE r.product_key = p.key), '[]'::jsonb),
                   'gives',       COALESCE((
                       SELECT jsonb_agg(jsonb_build_object(
                                  'service',        pe.service_key,
                                  'feature',        pe.feature_key,
                                  'serviceName',    s.display_name,
                                  'permissions',    (SELECT count(*) FROM rolebyte.service_permission sp
                                                      WHERE sp.service_key = s.key AND sp.retired_at IS NULL),
                                  'lastDeclaredAt', (SELECT max(sd.last_declared_at)
                                                       FROM rolebyte.service_declaration sd
                                                      WHERE sd.service_key = s.key))
                                ORDER BY pe.service_key COLLATE "C", pe.feature_key COLLATE "C")
                         FROM rolebyte.product_entitlement pe
                         JOIN rolebyte.service s ON s.key = pe.service_key
                        WHERE pe.product_key = p.key), '[]'::jsonb))
               ORDER BY p.key COLLATE "C")
          FROM rolebyte.product p), '[]'::jsonb)));
EXCEPTION
    WHEN sqlstate 'P0001' THEN
        RAISE;
    WHEN OTHERS THEN
        RAISE EXCEPTION '%', util.result_error('membership:error', sqlerrm) USING errcode = 'P0001';
END;
$$;

REVOKE ALL ON PROCEDURE rolebyte.deployment_products(jsonb, jsonb) FROM PUBLIC;
GRANT EXECUTE ON PROCEDURE rolebyte.deployment_products(jsonb, jsonb) TO rolebyte_public;

-- deployment_admins — the deployment's administrators, as `deployment_admin_list`
-- answers them, behind the caller's check.
CREATE OR REPLACE PROCEDURE rolebyte.deployment_admins(IN pi_data jsonb, INOUT po_data jsonb)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = rolebyte, util, pg_temp
AS $$
DECLARE
    v_refusal jsonb;
    v_out     jsonb;
BEGIN
    v_refusal := rolebyte.door_enter(pi_data, false, false);
    IF v_refusal IS NOT NULL THEN
        po_data := v_refusal;
        RETURN;
    END IF;

    CALL rolebyte.deployment_admin_list('{}'::jsonb, v_out);
    po_data := v_out;
EXCEPTION
    WHEN sqlstate 'P0001' THEN
        RAISE;
    WHEN OTHERS THEN
        RAISE EXCEPTION '%', util.result_error('membership:error', sqlerrm) USING errcode = 'P0001';
END;
$$;

REVOKE ALL ON PROCEDURE rolebyte.deployment_admins(jsonb, jsonb) FROM PUBLIC;
GRANT EXECUTE ON PROCEDURE rolebyte.deployment_admins(jsonb, jsonb) TO rolebyte_public;

-- ---------------------------------------------------------------------------
-- Opening a company, and what it has.
-- ---------------------------------------------------------------------------

-- company_open — a new company with its first administrator, the products it has, and
-- the roles it starts with. Input {actor, mode, name, language, products,
-- administrator: {subjectKey, displayName}}.
--
-- Everything is checked before the first write, in this order after the caller's
-- check: the name; the language (exactly `en` or `lv`); `products`, absent or an array
-- of strings with no key twice (`membership:invalid`), every key one this deployment
-- offers (`membership:not_found`) and every product a listed one needs also listed
-- (`membership:conflict`); the administrator, an object whose key is a person's, never a
-- service's, and whose name is a valid name; that the services have declared themselves
-- (`membership:conflict`); and that no other company has this name, ignoring case
-- (`membership:conflict`).
--
-- It writes, in one transaction: the company (`tenantCreated`), its default user type,
-- its first administrator (invited, holding the administrator rung,
-- `administratorSetByOperator`), its starting roles named in the language, each product
-- ticked in an order that puts a needed one first with the entitlements it gives, and the
-- service accounts the products carry as active members. A refusal after the first write
-- is raised, so nothing stands. Answers {company: {id, name, status, createdAt},
-- administrator: {userId, status}, roles, products: [keys], accounts: [keys of the
-- service accounts made members]}.
CREATE OR REPLACE PROCEDURE rolebyte.company_open(IN pi_data jsonb, INOUT po_data jsonb)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = rolebyte, util, pg_temp
AS $$
DECLARE
    v_actor    text := NULLIF(trim(pi_data->>'actor'), '');
    v_refusal  jsonb;
    v_name     text;
    v_language text;
    v_list     jsonb;
    v_keys     text[] := '{}'::text[];
    v_key      text;
    v_missing  text;
    v_admin    jsonb;
    v_subject  text;
    v_display  text;
    v_tenant   rolebyte.tenant%ROWTYPE;
    v_made     jsonb;
    v_roles    jsonb;
    v_follow   jsonb;
BEGIN
    v_refusal := rolebyte.door_enter(pi_data, true, false);
    IF v_refusal IS NOT NULL THEN
        po_data := v_refusal;
        RETURN;
    END IF;

    v_name := rolebyte.door_name(pi_data->'name');
    IF v_name IS NULL THEN
        po_data := util.result_error('membership:invalid', 'name is 1 to 200 characters with no control character');
        RETURN;
    END IF;

    v_language := rolebyte.door_language(pi_data->'language');
    IF v_language IS NULL THEN
        po_data := util.result_error('membership:invalid', 'language is en or lv');
        RETURN;
    END IF;

    v_list := COALESCE(pi_data->'products', '[]'::jsonb);
    IF jsonb_typeof(v_list) <> 'array'
       OR EXISTS (SELECT 1 FROM jsonb_array_elements(v_list) e WHERE jsonb_typeof(e) <> 'string') THEN
        po_data := util.result_error('membership:invalid', 'products is a list of product keys');
        RETURN;
    END IF;
    SELECT COALESCE(array_agg(e #>> '{}' ORDER BY ord), '{}'::text[]) INTO v_keys
      FROM jsonb_array_elements(v_list) WITH ORDINALITY AS t(e, ord);
    IF (SELECT count(DISTINCT k) FROM unnest(v_keys) k) <> COALESCE(array_length(v_keys, 1), 0) THEN
        po_data := util.result_error('membership:invalid', 'a product is named twice');
        RETURN;
    END IF;
    FOREACH v_key IN ARRAY v_keys LOOP
        IF NOT rolebyte.product_offered(v_key) THEN
            po_data := util.result_error('membership:not_found', 'this deployment offers no such product');
            RETURN;
        END IF;
    END LOOP;
    SELECT r.requires_key INTO v_missing
      FROM rolebyte.product_requirement r
     WHERE r.product_key = ANY (v_keys) AND r.requires_key <> ALL (v_keys)
     ORDER BY r.requires_key COLLATE "C"
     LIMIT 1;
    IF v_missing IS NOT NULL THEN
        po_data := util.result_error('membership:conflict', 'this product needs ' || v_missing);
        RETURN;
    END IF;

    v_admin := pi_data->'administrator';
    IF jsonb_typeof(v_admin) IS DISTINCT FROM 'object' THEN
        po_data := util.result_error('membership:invalid',
            'administrator must be an object with subjectKey and displayName');
        RETURN;
    END IF;
    v_subject := CASE WHEN jsonb_typeof(v_admin->'subjectKey') = 'string' THEN trim(v_admin->>'subjectKey') END;
    IF (starts_with(v_subject, 'sub:') AND rolebyte.is_typed_subject_key(v_subject)) IS NOT TRUE THEN
        po_data := util.result_error('membership:invalid', 'subjectKey must be a person''s key, sub:<person id>');
        RETURN;
    END IF;
    v_display := rolebyte.door_name(v_admin->'displayName');
    IF v_display IS NULL THEN
        po_data := util.result_error('membership:invalid',
            'displayName is 1 to 200 characters with no control character');
        RETURN;
    END IF;

    IF NOT rolebyte.door_services_declared() THEN
        po_data := util.result_error('membership:conflict', 'the deployment''s services have not declared themselves yet');
        RETURN;
    END IF;
    IF EXISTS (SELECT 1 FROM rolebyte.tenant t WHERE lower(t.name) = lower(v_name)) THEN
        po_data := util.result_error('membership:conflict', 'a company of this name already exists');
        RETURN;
    END IF;

    INSERT INTO rolebyte.tenant (id, name)
    VALUES (util.generate_ulid(), v_name)
    RETURNING * INTO v_tenant;
    INSERT INTO rolebyte.event (id, actor, tenant_id, kind, payload)
    VALUES (util.generate_ulid(), v_actor, v_tenant.id, 'tenantCreated', jsonb_build_object('name', v_tenant.name));

    PERFORM rolebyte.ensure_default_user_type(v_actor, v_tenant.id, v_language);

    v_made := rolebyte.administrator_make(v_actor, v_tenant.id, v_subject, v_display);
    IF v_made->>'result' IS DISTINCT FROM 'success' THEN
        RAISE EXCEPTION '%', v_made USING errcode = 'P0001';
    END IF;
    INSERT INTO rolebyte.event (id, actor, tenant_id, user_id, kind, payload)
    VALUES (util.generate_ulid(), v_actor, v_tenant.id, v_made->'data'->>'userId',
            'administratorSetByOperator', '{}'::jsonb);

    v_roles := rolebyte.seed_roles(v_actor, v_tenant.id, v_language);

    FOREACH v_key IN ARRAY rolebyte.door_topo(v_keys) LOOP
        PERFORM rolebyte.door_tick(v_actor, v_tenant.id, v_key, false);
        PERFORM rolebyte.door_product_give(v_actor, v_tenant.id, v_key);
    END LOOP;

    v_follow := rolebyte.product_accounts_follow(v_actor, v_tenant.id);

    po_data := util.result_success(jsonb_build_object(
        'company', jsonb_build_object(
            'id',        v_tenant.id,
            'name',      v_tenant.name,
            'status',    v_tenant.status,
            'createdAt', v_tenant.created_at),
        'administrator', jsonb_build_object(
            'userId', v_made->'data'->>'userId',
            'status', v_made->'data'->>'status'),
        'roles',    v_roles,
        'products', (SELECT COALESCE(jsonb_agg(k ORDER BY k COLLATE "C"), '[]'::jsonb) FROM unnest(v_keys) k),
        'accounts', v_follow->'added'));
EXCEPTION
    WHEN sqlstate 'P0001' THEN
        RAISE;
    WHEN OTHERS THEN
        RAISE EXCEPTION '%', util.result_error('membership:error', sqlerrm) USING errcode = 'P0001';
END;
$$;

REVOKE ALL ON PROCEDURE rolebyte.company_open(jsonb, jsonb) FROM PUBLIC;
GRANT EXECUTE ON PROCEDURE rolebyte.company_open(jsonb, jsonb) TO rolebyte_public;

-- company_has_set — give a company a product, or take it away. Input {actor, mode,
-- tenantId, product, has}, `has` a JSON boolean (anything else is `membership:invalid`).
-- An unknown company is `membership:not_found`.
--
-- Giving needs a product this deployment offers (`membership:not_found`) whose needs
-- the company has all ticked (`membership:conflict`, 'this product needs <key>'); then
-- the product is ticked (`productTicked`), each entitlement it gives is given (the same
-- `tenantEntitled` lines `entitlement_grant` writes, only when something changed), and
-- the company's service accounts are made to match.
--
-- Taking away: a product never ticked for the company is `membership:not_found`; one a
-- ticked product needs is `membership:conflict` ('<key> needs this product'); one
-- already taken away changes nothing. Otherwise it is unticked (`productUnticked`),
-- every entitlement it gives that no other ticked product gives is revoked, and where it
-- gave a whole service and no other ticked product gives anything of that service every
-- entitlement row of that service the company holds is revoked, feature rows included
-- (`tenantEntitlementRevoked` for each row changed); then the service accounts follow.
--
-- Answers {changed, accounts: {added, removed}}; `changed` is true when the tick, an
-- entitlement or an account changed.
CREATE OR REPLACE PROCEDURE rolebyte.company_has_set(IN pi_data jsonb, INOUT po_data jsonb)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = rolebyte, util, pg_temp
AS $$
DECLARE
    v_actor   text := NULLIF(trim(pi_data->>'actor'), '');
    v_tenant  text := NULLIF(trim(pi_data->>'tenantId'), '');
    v_product text := CASE WHEN jsonb_typeof(pi_data->'product') = 'string' THEN NULLIF(trim(pi_data->>'product'), '') END;
    v_refusal jsonb;
    v_state   text;
    v_other   text;
    v_changed boolean;
    v_follow  jsonb;
BEGIN
    v_refusal := rolebyte.door_enter(pi_data, true, false);
    IF v_refusal IS NOT NULL THEN
        po_data := v_refusal;
        RETURN;
    END IF;
    IF v_tenant IS NULL OR v_product IS NULL THEN
        po_data := util.result_error('membership:invalid', 'tenantId and product are required');
        RETURN;
    END IF;
    IF jsonb_typeof(pi_data->'has') IS DISTINCT FROM 'boolean' THEN
        po_data := util.result_error('membership:invalid', 'has is true or false');
        RETURN;
    END IF;
    IF NOT EXISTS (SELECT 1 FROM rolebyte.tenant WHERE id = v_tenant) THEN
        po_data := util.result_error('membership:not_found', 'no such company');
        RETURN;
    END IF;

    IF (pi_data->>'has')::boolean THEN
        IF NOT rolebyte.product_offered(v_product) THEN
            po_data := util.result_error('membership:not_found', 'this deployment offers no such product');
            RETURN;
        END IF;
        v_other := rolebyte.door_need_missing(v_tenant, v_product);
        IF v_other IS NOT NULL THEN
            po_data := util.result_error('membership:conflict', 'this product needs ' || v_other);
            RETURN;
        END IF;
        v_changed := rolebyte.door_tick(v_actor, v_tenant, v_product, false);
        IF rolebyte.door_product_give(v_actor, v_tenant, v_product) THEN
            v_changed := true;
        END IF;
    ELSE
        SELECT tp.state INTO v_state FROM rolebyte.tenant_product tp
         WHERE tp.tenant_id = v_tenant AND tp.product_key = v_product;
        IF NOT FOUND THEN
            po_data := util.result_error('membership:not_found', 'the company was never given this');
            RETURN;
        END IF;
        IF v_state = 'unticked' THEN
            po_data := util.result_success(jsonb_build_object('changed', false,
                'accounts', jsonb_build_object('added', '[]'::jsonb, 'removed', '[]'::jsonb)));
            RETURN;
        END IF;
        SELECT r.product_key INTO v_other
          FROM rolebyte.product_requirement r
         WHERE r.requires_key = v_product AND rolebyte.door_ticked(v_tenant, r.product_key)
         ORDER BY r.product_key COLLATE "C"
         LIMIT 1;
        IF v_other IS NOT NULL THEN
            po_data := util.result_error('membership:conflict', v_other || ' needs this product');
            RETURN;
        END IF;

        UPDATE rolebyte.tenant_product SET state = 'unticked', unticked_at = now()
         WHERE tenant_id = v_tenant AND product_key = v_product;
        INSERT INTO rolebyte.event (id, actor, tenant_id, user_id, kind, payload)
        VALUES (util.generate_ulid(), v_actor, v_tenant, NULL, 'productUnticked',
                jsonb_build_object('product', v_product));
        v_changed := true;
        PERFORM rolebyte.door_product_take(v_actor, v_tenant, v_product);
    END IF;

    v_follow := rolebyte.product_accounts_follow(v_actor, v_tenant);
    IF (v_follow->>'changed')::boolean THEN
        v_changed := true;
    END IF;

    po_data := util.result_success(jsonb_build_object('changed', v_changed,
        'accounts', jsonb_build_object('added', v_follow->'added', 'removed', v_follow->'removed')));
EXCEPTION
    WHEN sqlstate 'P0001' THEN
        RAISE;
    WHEN OTHERS THEN
        RAISE EXCEPTION '%', util.result_error('membership:error', sqlerrm) USING errcode = 'P0001';
END;
$$;

REVOKE ALL ON PROCEDURE rolebyte.company_has_set(jsonb, jsonb) FROM PUBLIC;
GRANT EXECUTE ON PROCEDURE rolebyte.company_has_set(jsonb, jsonb) TO rolebyte_public;

-- ---------------------------------------------------------------------------
-- A company's administrators, and its starting roles.
-- ---------------------------------------------------------------------------

-- company_administrator_set — make a person an administrator of a company. Input {actor,
-- mode, tenantId, subjectKey, displayName}. An unknown company is
-- `membership:not_found`; the key must be a person's (`membership:invalid`). Then
-- exactly what `administrator_set` does. A person whose access to the company was
-- removed is refused `membership:conflict` ('this person no longer has access to the
-- company'), a sentence that names nobody. Answers {tenantId, userId, invited, changed}.
CREATE OR REPLACE PROCEDURE rolebyte.company_administrator_set(IN pi_data jsonb, INOUT po_data jsonb)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = rolebyte, util, pg_temp
AS $$
DECLARE
    v_actor   text := NULLIF(trim(pi_data->>'actor'), '');
    v_tenant  text := NULLIF(trim(pi_data->>'tenantId'), '');
    v_subject text := CASE WHEN jsonb_typeof(pi_data->'subjectKey') = 'string' THEN trim(pi_data->>'subjectKey') END;
    v_display text;
    v_refusal jsonb;
    v_in      jsonb;
    v_out     jsonb;
BEGIN
    v_refusal := rolebyte.door_enter(pi_data, true, false);
    IF v_refusal IS NOT NULL THEN
        po_data := v_refusal;
        RETURN;
    END IF;
    IF v_tenant IS NULL THEN
        po_data := util.result_error('membership:invalid', 'tenantId is required');
        RETURN;
    END IF;
    IF NOT EXISTS (SELECT 1 FROM rolebyte.tenant WHERE id = v_tenant) THEN
        po_data := util.result_error('membership:not_found', 'no such company');
        RETURN;
    END IF;
    IF (starts_with(v_subject, 'sub:') AND rolebyte.is_typed_subject_key(v_subject)) IS NOT TRUE THEN
        po_data := util.result_error('membership:invalid', 'subjectKey must be a person''s key, sub:<person id>');
        RETURN;
    END IF;
    IF pi_data->'displayName' IS NOT NULL AND jsonb_typeof(pi_data->'displayName') <> 'null' THEN
        v_display := rolebyte.door_name(pi_data->'displayName');
        IF v_display IS NULL THEN
            po_data := util.result_error('membership:invalid',
                'displayName is 1 to 200 characters with no control character');
            RETURN;
        END IF;
    END IF;

    v_in := jsonb_build_object('actor', v_actor, 'tenantId', v_tenant, 'subjectKey', v_subject,
                               'displayName', v_display);
    CALL rolebyte.administrator_set(v_in, v_out);
    IF v_out->>'result' = 'error' AND v_out->>'code' = 'membership:conflict' THEN
        -- The neighbour's sentence carries the person's name; this one does not.
        v_out := util.result_error('membership:conflict', 'this person no longer has access to the company');
    END IF;
    po_data := v_out;
EXCEPTION
    WHEN sqlstate 'P0001' THEN
        RAISE;
    WHEN OTHERS THEN
        RAISE EXCEPTION '%', util.result_error('membership:error', sqlerrm) USING errcode = 'P0001';
END;
$$;

REVOKE ALL ON PROCEDURE rolebyte.company_administrator_set(jsonb, jsonb) FROM PUBLIC;
GRANT EXECUTE ON PROCEDURE rolebyte.company_administrator_set(jsonb, jsonb) TO rolebyte_public;

-- company_administrator_unset — take the administrator rung from an account of a
-- company. Input {actor, mode, tenantId, userId}: exactly what `administrator_unset`
-- does. The company's last administrator is refused `membership:conflict` ('a company
-- keeps at least one administrator'), a sentence that names nobody; an account that is
-- not of the company is `membership:not_found`. Answers {changed}.
CREATE OR REPLACE PROCEDURE rolebyte.company_administrator_unset(IN pi_data jsonb, INOUT po_data jsonb)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = rolebyte, util, pg_temp
AS $$
DECLARE
    v_actor   text := NULLIF(trim(pi_data->>'actor'), '');
    v_tenant  text := NULLIF(trim(pi_data->>'tenantId'), '');
    v_user    text := NULLIF(trim(pi_data->>'userId'), '');
    v_refusal jsonb;
    v_in      jsonb;
    v_out     jsonb;
BEGIN
    v_refusal := rolebyte.door_enter(pi_data, true, false);
    IF v_refusal IS NOT NULL THEN
        po_data := v_refusal;
        RETURN;
    END IF;
    IF v_tenant IS NULL OR v_user IS NULL THEN
        po_data := util.result_error('membership:invalid', 'tenantId and userId are required');
        RETURN;
    END IF;

    v_in := jsonb_build_object('actor', v_actor, 'tenantId', v_tenant, 'userId', v_user);
    CALL rolebyte.administrator_unset(v_in, v_out);
    IF v_out->>'result' = 'error' AND v_out->>'code' = 'membership:conflict' THEN
        v_out := util.result_error('membership:conflict', 'a company keeps at least one administrator');
    END IF;
    po_data := v_out;
EXCEPTION
    WHEN sqlstate 'P0001' THEN
        RAISE;
    WHEN OTHERS THEN
        RAISE EXCEPTION '%', util.result_error('membership:error', sqlerrm) USING errcode = 'P0001';
END;
$$;

REVOKE ALL ON PROCEDURE rolebyte.company_administrator_unset(jsonb, jsonb) FROM PUBLIC;
GRANT EXECUTE ON PROCEDURE rolebyte.company_administrator_unset(jsonb, jsonb) TO rolebyte_public;

-- company_roles_seed — give a company the starting roles it does not have yet. Input
-- {actor, mode, tenantId, language}. An unknown company is `membership:not_found`; the
-- language is exactly `en` or `lv` (`membership:invalid`). Then what `tenant_seed_roles`
-- does and answers: {roles, kept, missing}.
CREATE OR REPLACE PROCEDURE rolebyte.company_roles_seed(IN pi_data jsonb, INOUT po_data jsonb)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = rolebyte, util, pg_temp
AS $$
DECLARE
    v_actor    text := NULLIF(trim(pi_data->>'actor'), '');
    v_tenant   text := NULLIF(trim(pi_data->>'tenantId'), '');
    v_language text;
    v_refusal  jsonb;
    v_in       jsonb;
    v_out      jsonb;
BEGIN
    v_refusal := rolebyte.door_enter(pi_data, true, false);
    IF v_refusal IS NOT NULL THEN
        po_data := v_refusal;
        RETURN;
    END IF;
    IF v_tenant IS NULL THEN
        po_data := util.result_error('membership:invalid', 'tenantId is required');
        RETURN;
    END IF;
    IF NOT EXISTS (SELECT 1 FROM rolebyte.tenant WHERE id = v_tenant) THEN
        po_data := util.result_error('membership:not_found', 'no such company');
        RETURN;
    END IF;
    v_language := rolebyte.door_language(pi_data->'language');
    IF v_language IS NULL THEN
        po_data := util.result_error('membership:invalid', 'language is en or lv');
        RETURN;
    END IF;

    v_in := jsonb_build_object('actor', v_actor, 'tenantId', v_tenant, 'language', v_language);
    CALL rolebyte.tenant_seed_roles(v_in, v_out);
    po_data := v_out;
EXCEPTION
    WHEN sqlstate 'P0001' THEN
        RAISE;
    WHEN OTHERS THEN
        RAISE EXCEPTION '%', util.result_error('membership:error', sqlerrm) USING errcode = 'P0001';
END;
$$;

REVOKE ALL ON PROCEDURE rolebyte.company_roles_seed(jsonb, jsonb) FROM PUBLIC;
GRANT EXECUTE ON PROCEDURE rolebyte.company_roles_seed(jsonb, jsonb) TO rolebyte_public;

-- door_local_products — on a deployment run on the customer's own machines, give a
-- company every offered product it does not have, a needed product first, with the
-- entitlements each gives. A product whose needs are not all had is left. Answers the
-- keys ticked.
CREATE OR REPLACE FUNCTION rolebyte.door_local_products(p_actor text, p_tenant text)
RETURNS text[]
LANGUAGE plpgsql
VOLATILE
SET search_path = rolebyte, util, pg_temp
AS $$
DECLARE
    v_key   text;
    v_keys  text[];
    v_added text[] := '{}'::text[];
BEGIN
    SELECT COALESCE(array_agg(p.key), '{}'::text[]) INTO v_keys
      FROM rolebyte.product p WHERE rolebyte.product_offered(p.key);
    FOREACH v_key IN ARRAY rolebyte.door_topo(v_keys) LOOP
        IF rolebyte.door_need_missing(p_tenant, v_key) IS NULL THEN
            IF rolebyte.door_tick(p_actor, p_tenant, v_key, false) THEN
                v_added := array_append(v_added, v_key);
            END IF;
            PERFORM rolebyte.door_product_give(p_actor, p_tenant, v_key);
        END IF;
    END LOOP;
    RETURN (SELECT COALESCE(array_agg(k ORDER BY k COLLATE "C"), '{}'::text[]) FROM unnest(v_added) k);
END;
$$;

REVOKE ALL ON FUNCTION rolebyte.door_local_products(text, text) FROM PUBLIC;

-- company_first_run — set up the deployment's own company the first time: name it and
-- give it its starting roles. Input {actor, mode, name, language}.
--
-- The caller's check differs by mode. On `saas` it is the deployment's door check. On
-- `local` the caller is a person with an active account in the marked company who is an
-- administrator of it now; with no company marked that is refused the same way.
--
-- Checked before the first write: the name; the language (exactly `en` or `lv`); that
-- the services have declared themselves (`membership:conflict`); and that the marked
-- company has no name yet (`membership:conflict`, 'the company is already set up').
-- Writes the name (`tenantRenamed`, from empty), the default user type and the starting
-- roles; on `local` it also gives the company every offered product it does not have and
-- makes its service accounts match. Answers {company: {id, name}, roles, missing: [the
-- starting roles the company still lacks], products: [the products it has now]}.
CREATE OR REPLACE PROCEDURE rolebyte.company_first_run(IN pi_data jsonb, INOUT po_data jsonb)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = rolebyte, util, pg_temp
AS $$
DECLARE
    v_actor    text := NULLIF(trim(pi_data->>'actor'), '');
    v_mode     text := pi_data->>'mode';
    v_refusal  jsonb;
    v_name     text;
    v_language text;
    v_company  text;
    v_current  text;
    v_roles    jsonb;
BEGIN
    v_refusal := rolebyte.door_enter(pi_data, true, true);
    IF v_refusal IS NOT NULL THEN
        po_data := v_refusal;
        RETURN;
    END IF;

    v_name := rolebyte.door_name(pi_data->'name');
    IF v_name IS NULL THEN
        po_data := util.result_error('membership:invalid', 'name is 1 to 200 characters with no control character');
        RETURN;
    END IF;
    v_language := rolebyte.door_language(pi_data->'language');
    IF v_language IS NULL THEN
        po_data := util.result_error('membership:invalid', 'language is en or lv');
        RETURN;
    END IF;
    IF NOT rolebyte.door_services_declared() THEN
        po_data := util.result_error('membership:conflict', 'the deployment''s services have not declared themselves yet');
        RETURN;
    END IF;

    SELECT d.company_tenant_id, t.name INTO v_company, v_current
      FROM rolebyte.deployment d
      JOIN rolebyte.tenant t ON t.id = d.company_tenant_id;
    IF v_current <> '' THEN
        po_data := util.result_error('membership:conflict', 'the company is already set up');
        RETURN;
    END IF;

    UPDATE rolebyte.tenant SET name = v_name WHERE id = v_company;
    INSERT INTO rolebyte.event (id, actor, tenant_id, kind, payload)
    VALUES (util.generate_ulid(), v_actor, v_company, 'tenantRenamed',
            jsonb_build_object('from', '', 'to', v_name));

    PERFORM rolebyte.ensure_default_user_type(v_actor, v_company, v_language);
    v_roles := rolebyte.seed_roles(v_actor, v_company, v_language);

    IF v_mode = 'local' THEN
        PERFORM rolebyte.door_local_products(v_actor, v_company);
        PERFORM rolebyte.product_accounts_follow(v_actor, v_company);
    END IF;

    po_data := util.result_success(jsonb_build_object(
        'company', jsonb_build_object('id', v_company, 'name', v_name),
        'roles',   v_roles,
        'missing', COALESCE((
            SELECT jsonb_agg(sd ORDER BY sd)
              FROM unnest(ARRAY['guest', 'worker', 'manager']) sd
             WHERE NOT EXISTS (SELECT 1 FROM rolebyte.tenant_role r
                                WHERE r.tenant_id = v_company AND r.seed = sd)), '[]'::jsonb),
        'products', COALESCE((
            SELECT jsonb_agg(tp.product_key ORDER BY tp.product_key COLLATE "C")
              FROM rolebyte.tenant_product tp
             WHERE tp.tenant_id = v_company AND tp.state = 'ticked'), '[]'::jsonb)));
EXCEPTION
    WHEN sqlstate 'P0001' THEN
        RAISE;
    WHEN OTHERS THEN
        RAISE EXCEPTION '%', util.result_error('membership:error', sqlerrm) USING errcode = 'P0001';
END;
$$;

REVOKE ALL ON PROCEDURE rolebyte.company_first_run(jsonb, jsonb) FROM PUBLIC;
GRANT EXECUTE ON PROCEDURE rolebyte.company_first_run(jsonb, jsonb) TO rolebyte_public;

-- ---------------------------------------------------------------------------
-- The deployment's administrators.
-- ---------------------------------------------------------------------------

-- deployment_admin_grant — put a person on the list of the deployment's administrators,
-- from the deployment's screen. Input {actor, mode, subjectKey}: exactly what
-- `deployment_admin_add` does with `addedFrom` `screen`, its refusals passed through.
-- Answers {userId, changed}.
CREATE OR REPLACE PROCEDURE rolebyte.deployment_admin_grant(IN pi_data jsonb, INOUT po_data jsonb)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = rolebyte, util, pg_temp
AS $$
DECLARE
    v_actor   text := NULLIF(trim(pi_data->>'actor'), '');
    v_subject text := CASE WHEN jsonb_typeof(pi_data->'subjectKey') = 'string' THEN trim(pi_data->>'subjectKey') END;
    v_refusal jsonb;
    v_in      jsonb;
    v_out     jsonb;
BEGIN
    v_refusal := rolebyte.door_enter(pi_data, true, false);
    IF v_refusal IS NOT NULL THEN
        po_data := v_refusal;
        RETURN;
    END IF;

    v_in := jsonb_build_object('actor', v_actor, 'subjectKey', v_subject, 'addedFrom', 'screen');
    CALL rolebyte.deployment_admin_add(v_in, v_out);
    po_data := v_out;
EXCEPTION
    WHEN sqlstate 'P0001' THEN
        RAISE;
    WHEN OTHERS THEN
        RAISE EXCEPTION '%', util.result_error('membership:error', sqlerrm) USING errcode = 'P0001';
END;
$$;

REVOKE ALL ON PROCEDURE rolebyte.deployment_admin_grant(jsonb, jsonb) FROM PUBLIC;
GRANT EXECUTE ON PROCEDURE rolebyte.deployment_admin_grant(jsonb, jsonb) TO rolebyte_public;

-- deployment_admin_revoke — take an account off the list of the deployment's
-- administrators. Input {actor, mode, userId}. An account that is not on the list is
-- `membership:not_found`. The last entry whose account is active cannot be removed
-- (`membership:conflict`, 'the last deployment administrator cannot be removed'): an
-- invited or revoked account does not count as one. Otherwise exactly what
-- `deployment_admin_remove` does. Answers {userId, subjectKey, changed}.
CREATE OR REPLACE PROCEDURE rolebyte.deployment_admin_revoke(IN pi_data jsonb, INOUT po_data jsonb)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = rolebyte, util, pg_temp
AS $$
DECLARE
    v_actor   text := NULLIF(trim(pi_data->>'actor'), '');
    v_user    text := NULLIF(trim(pi_data->>'userId'), '');
    v_refusal jsonb;
    v_status  text;
    v_in      jsonb;
    v_out     jsonb;
BEGIN
    v_refusal := rolebyte.door_enter(pi_data, true, false);
    IF v_refusal IS NOT NULL THEN
        po_data := v_refusal;
        RETURN;
    END IF;
    IF v_user IS NULL THEN
        po_data := util.result_error('membership:invalid', 'userId is required');
        RETURN;
    END IF;

    SELECT u.status INTO v_status
      FROM rolebyte.deployment_admin da
      JOIN rolebyte.user_account u ON u.id = da.user_id
     WHERE da.user_id = v_user;
    IF NOT FOUND THEN
        po_data := util.result_error('membership:not_found', 'the account is not a deployment administrator');
        RETURN;
    END IF;
    IF v_status = 'active'
       AND NOT EXISTS (SELECT 1
                         FROM rolebyte.deployment_admin da
                         JOIN rolebyte.user_account u ON u.id = da.user_id
                        WHERE da.user_id <> v_user AND u.status = 'active') THEN
        po_data := util.result_error('membership:conflict', 'the last deployment administrator cannot be removed');
        RETURN;
    END IF;

    v_in := jsonb_build_object('actor', v_actor, 'userId', v_user);
    CALL rolebyte.deployment_admin_remove(v_in, v_out);
    po_data := v_out;
EXCEPTION
    WHEN sqlstate 'P0001' THEN
        RAISE;
    WHEN OTHERS THEN
        RAISE EXCEPTION '%', util.result_error('membership:error', sqlerrm) USING errcode = 'P0001';
END;
$$;

REVOKE ALL ON PROCEDURE rolebyte.deployment_admin_revoke(jsonb, jsonb) FROM PUBLIC;
GRANT EXECUTE ON PROCEDURE rolebyte.deployment_admin_revoke(jsonb, jsonb) TO rolebyte_public;

-- ---------------------------------------------------------------------------
-- Service accounts and the catalog.
-- ---------------------------------------------------------------------------

-- local_company_follow — on a deployment run on the customer's own machines, the
-- deployment's own company has every product the deployment offers. The register runs
-- this at its start, for itself, so there is no caller's check. Input {actor, mode}: the
-- mode must be `local` (`membership:invalid` otherwise). With no company marked it
-- succeeds and does nothing ({changed: false, added: []}). Otherwise, under the
-- deployment's lock, it ticks every offered product the company lacks, a needed product
-- first, gives the entitlements they carry, and makes its service accounts match.
-- Answers {changed, added: [product keys ticked], accounts: {added, removed}}.
CREATE OR REPLACE PROCEDURE rolebyte.local_company_follow(IN pi_data jsonb, INOUT po_data jsonb)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = rolebyte, util, pg_temp
AS $$
DECLARE
    v_actor   text := NULLIF(trim(pi_data->>'actor'), '');
    v_company text;
    v_before  bigint;
    v_after   bigint;
    v_added   text[];
    v_follow  jsonb;
BEGIN
    IF v_actor IS NULL OR pi_data->>'mode' IS DISTINCT FROM 'local' THEN
        po_data := util.result_error('membership:invalid', 'actor is required and mode is local');
        RETURN;
    END IF;

    PERFORM pg_advisory_xact_lock(hashtextextended('rolebyte.deployment', 0));

    SELECT company_tenant_id INTO v_company FROM rolebyte.deployment;
    IF v_company IS NULL THEN
        po_data := util.result_success(jsonb_build_object('changed', false, 'added', '[]'::jsonb));
        RETURN;
    END IF;

    SELECT count(*) INTO v_before FROM rolebyte.event WHERE tenant_id = v_company;
    v_added := rolebyte.door_local_products(v_actor, v_company);
    v_follow := rolebyte.product_accounts_follow(v_actor, v_company);
    SELECT count(*) INTO v_after FROM rolebyte.event WHERE tenant_id = v_company;

    po_data := util.result_success(jsonb_build_object(
        'changed',  v_after > v_before OR (v_follow->>'changed')::boolean,
        'added',    to_jsonb(v_added),
        'accounts', jsonb_build_object('added', v_follow->'added', 'removed', v_follow->'removed')));
EXCEPTION
    WHEN sqlstate 'P0001' THEN
        RAISE;
    WHEN OTHERS THEN
        RAISE EXCEPTION '%', util.result_error('membership:error', sqlerrm) USING errcode = 'P0001';
END;
$$;

REVOKE ALL ON PROCEDURE rolebyte.local_company_follow(jsonb, jsonb) FROM PUBLIC;
GRANT EXECUTE ON PROCEDURE rolebyte.local_company_follow(jsonb, jsonb) TO rolebyte_public;

-- products_register — make the catalog of products equal to the list given, and bring
-- the companies in line. Input {actor, products: [{key, displayName, gives: [{service,
-- feature}], needs: [product keys], accounts: [{subjectKey, displayName, roles:
-- [{service, group, level}]}]}]}. The deployment runs it as the location's owner: it is
-- granted to nobody, and the register's own role is refused it.
--
-- The whole list is checked before anything is written; a refusal is
-- `membership:invalid` and its message names the position of the product (counting from
-- one) and never repeats a key. A product's `key` is one lower-case word and is not
-- listed twice; its `displayName` is a valid name; `gives` is a list that is not empty,
-- each entry naming a registered service and a feature that is absent, empty (the whole
-- service) or carried by a permission of that service, no pair twice; `needs` names
-- products of this list, never the product itself, and the needs form no circle;
-- `accounts` is a list (it may be empty) of service accounts, each a key `svc:` followed
-- by something that is not an assistant's, a valid name, and levels that exist, none in
-- the group `deployment` and none that is an administrator's, no key twice. A product
-- that some company has ticked and the list leaves out is refused `membership:conflict`.
--
-- Then, under the deployment's lock, in one transaction: the four catalog tables are made
-- equal to the list (`productRegistered` for a product added or changed,
-- `productUnregistered` for one removed, each belonging to no company). The register's own
-- service cannot be given by a product, and a list in which a product needs one that a
-- company having it has not ticked is refused `membership:conflict` ('<a> needs <b>').
--
-- `adopt` (a JSON boolean, absent means false) asks for adoption. Only then is a company
-- taken as having a product it does not have, and holds in force every entitlement of, a
-- whole service covering any feature of it, with every product it needs ticked: the
-- product is ticked for it (`productTicked`, adopted), a needed product first, and given
-- like any ticked product, every entitlement it gives written. A product a company has
-- had and had taken away is not adopted again. Without `adopt` nothing is ticked.
--
-- Then, only for a company with at least one ticked product: every entitlement its
-- ticked products give is given where it is missing or was revoked, one the ticked
-- products gave before this call and none gives now is revoked, entitlements no product
-- ever gave are left alone, and the company's service accounts are made to match: an
-- account that a product ticked for the company listed before this call and no ticked
-- product lists now is ended like one whose product was taken away (which accounts leave
-- is read before the old lists are replaced); an account no list ever named is left alone;
-- ending a company's last administrator is refused and refuses the whole call. A
-- company with no ticked product is not touched. Answers {registered, unregistered,
-- adopted, companies}: the products added or changed, the products removed, the ticks
-- adopted, and the companies in which anything changed.
CREATE OR REPLACE PROCEDURE rolebyte.products_register(IN pi_data jsonb, INOUT po_data jsonb)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = rolebyte, util, pg_temp
AS $$
DECLARE
    v_actor     text := NULLIF(trim(pi_data->>'actor'), '');
    v_list      jsonb;
    v_entry     jsonb;
    v_give      jsonb;
    v_acct      jsonb;
    v_role      jsonb;
    v_pos       integer;
    v_key       text;
    v_display   text;
    v_service   text;
    v_feature   text;
    v_subject   text;
    v_keys      text[] := '{}'::text[];
    v_norm      jsonb := '[]'::jsonb;
    v_gives     jsonb;
    v_needs     jsonb;
    v_accts     jsonb;
    v_roles     jsonb;
    v_seen      jsonb[];
    v_seen_acct text[];
    v_rest      text[];
    v_next      text[];
    v_changed   text[] := '{}'::text[];
    v_before    jsonb;
    v_tenant    text;
    v_product   text;
    v_row       record;
    v_ev_before bigint;
    v_ev_after  bigint;
    v_reg       integer := 0;
    v_unreg     integer := 0;
    v_adopted   integer := 0;
    v_companies integer := 0;
    v_adopt     boolean := false;
    v_follow    jsonb;
    v_need      text;
    v_listed    jsonb;
    v_ended     text[];
BEGIN
    IF v_actor IS NULL THEN
        po_data := util.result_error('membership:invalid', 'actor is required');
        RETURN;
    END IF;
    IF pi_data->'adopt' IS NOT NULL AND jsonb_typeof(pi_data->'adopt') <> 'null' THEN
        IF jsonb_typeof(pi_data->'adopt') <> 'boolean' THEN
            po_data := util.result_error('membership:invalid', 'adopt is true or false');
            RETURN;
        END IF;
        v_adopt := (pi_data->>'adopt')::boolean;
    END IF;
    v_list := pi_data->'products';
    IF jsonb_typeof(v_list) IS DISTINCT FROM 'array' THEN
        po_data := util.result_error('membership:invalid', 'products is a list');
        RETURN;
    END IF;

    FOR i IN 0 .. jsonb_array_length(v_list) - 1 LOOP
        v_pos   := i + 1;
        v_entry := v_list->i;
        IF jsonb_typeof(v_entry) IS DISTINCT FROM 'object' THEN
            po_data := util.result_error('membership:invalid', format('product %s is not an object', v_pos));
            RETURN;
        END IF;

        v_key := CASE WHEN jsonb_typeof(v_entry->'key') = 'string' THEN v_entry->>'key' END;
        IF v_key IS NULL OR v_key !~ '^[a-z][a-z0-9-]{0,63}$' THEN
            po_data := util.result_error('membership:invalid',
                format('product %s needs a key of one lower-case word', v_pos));
            RETURN;
        END IF;
        IF v_key = ANY (v_keys) THEN
            po_data := util.result_error('membership:invalid', format('product %s is listed twice', v_pos));
            RETURN;
        END IF;
        v_keys := array_append(v_keys, v_key);

        v_display := rolebyte.door_name(v_entry->'displayName');
        IF v_display IS NULL THEN
            po_data := util.result_error('membership:invalid',
                format('product %s needs a displayName of 1 to 200 characters with no control character', v_pos));
            RETURN;
        END IF;

        -- What the product gives.
        IF jsonb_typeof(v_entry->'gives') IS DISTINCT FROM 'array' OR jsonb_array_length(v_entry->'gives') = 0 THEN
            po_data := util.result_error('membership:invalid', format('product %s needs a list of what it gives', v_pos));
            RETURN;
        END IF;
        v_seen := '{}'::jsonb[];
        v_gives := '[]'::jsonb;
        FOR j IN 0 .. jsonb_array_length(v_entry->'gives') - 1 LOOP
            v_give := (v_entry->'gives')->j;
            v_service := CASE WHEN jsonb_typeof(v_give->'service') = 'string' THEN v_give->>'service' END;
            IF jsonb_typeof(v_give) IS DISTINCT FROM 'object'
               OR v_service IS NULL
               OR v_service = 'rolebyte'
               OR NOT EXISTS (SELECT 1 FROM rolebyte.service WHERE key = v_service) THEN
                po_data := util.result_error('membership:invalid',
                    format('product %s gives a service that is not registered', v_pos));
                RETURN;
            END IF;
            IF v_give->'feature' IS NULL OR jsonb_typeof(v_give->'feature') = 'null' THEN
                v_feature := '';
            ELSIF jsonb_typeof(v_give->'feature') = 'string' THEN
                v_feature := v_give->>'feature';
            ELSE
                po_data := util.result_error('membership:invalid', format('product %s gives a feature that is not text', v_pos));
                RETURN;
            END IF;
            IF v_feature <> '' AND (rolebyte.is_permission_feature(v_feature) IS NOT TRUE
               OR NOT EXISTS (SELECT 1 FROM rolebyte.service_permission sp
                               WHERE sp.service_key = v_service
                                 AND (sp.feature_key = v_feature OR starts_with(sp.feature_key, v_feature || '/')))) THEN
                po_data := util.result_error('membership:invalid',
                    format('product %s gives a feature no permission of the service carries', v_pos));
                RETURN;
            END IF;
            IF jsonb_build_array(v_service, v_feature) = ANY (v_seen) THEN
                po_data := util.result_error('membership:invalid', format('product %s gives the same thing twice', v_pos));
                RETURN;
            END IF;
            v_seen := array_append(v_seen, jsonb_build_array(v_service, v_feature));
            v_gives := v_gives || jsonb_build_array(jsonb_build_object('service', v_service, 'feature', v_feature));
        END LOOP;
        SELECT jsonb_agg(g ORDER BY g->>'service' COLLATE "C", g->>'feature' COLLATE "C") INTO v_gives
          FROM jsonb_array_elements(v_gives) g;

        -- What it needs: checked against the whole list below.
        IF v_entry->'needs' IS NULL OR jsonb_typeof(v_entry->'needs') = 'null' THEN
            v_needs := '[]'::jsonb;
        ELSIF jsonb_typeof(v_entry->'needs') = 'array'
              AND NOT EXISTS (SELECT 1 FROM jsonb_array_elements(v_entry->'needs') n WHERE jsonb_typeof(n) <> 'string') THEN
            SELECT COALESCE(jsonb_agg(n ORDER BY n #>> '{}' COLLATE "C"), '[]'::jsonb) INTO v_needs
              FROM (SELECT DISTINCT n FROM jsonb_array_elements(v_entry->'needs') n) d;
        ELSE
            po_data := util.result_error('membership:invalid', format('product %s needs a list of product keys', v_pos));
            RETURN;
        END IF;
        IF v_needs ? v_key THEN
            po_data := util.result_error('membership:invalid', format('product %s needs itself', v_pos));
            RETURN;
        END IF;

        -- Its service accounts.
        IF v_entry->'accounts' IS NULL OR jsonb_typeof(v_entry->'accounts') = 'null' THEN
            v_accts := '[]'::jsonb;
        ELSIF jsonb_typeof(v_entry->'accounts') = 'array' THEN
            v_accts := '[]'::jsonb;
            v_seen_acct := '{}'::text[];
            FOR j IN 0 .. jsonb_array_length(v_entry->'accounts') - 1 LOOP
                v_acct := (v_entry->'accounts')->j;
                v_subject := CASE WHEN jsonb_typeof(v_acct->'subjectKey') = 'string' THEN v_acct->>'subjectKey' END;
                IF jsonb_typeof(v_acct) IS DISTINCT FROM 'object'
                   OR v_subject IS NULL OR NOT starts_with(v_subject, 'svc:') OR length(v_subject) = 4
                   OR starts_with(v_subject, 'svc:assistant-') THEN
                    po_data := util.result_error('membership:invalid',
                        format('product %s has an account that needs a key, svc:<client id>, that is not an assistant''s', v_pos));
                    RETURN;
                END IF;
                IF rolebyte.door_name(v_acct->'displayName') IS NULL THEN
                    po_data := util.result_error('membership:invalid',
                        format('product %s has an account that needs a displayName of 1 to 200 characters with no control character', v_pos));
                    RETURN;
                END IF;
                IF v_subject = ANY (v_seen_acct) THEN
                    po_data := util.result_error('membership:invalid',
                        format('product %s lists an account twice', v_pos));
                    RETURN;
                END IF;
                v_seen_acct := array_append(v_seen_acct, v_subject);
                v_roles := v_acct->'roles';
                IF jsonb_typeof(v_roles) IS DISTINCT FROM 'array' THEN
                    po_data := util.result_error('membership:invalid',
                        format('product %s has an account that needs its roles as a list', v_pos));
                    RETURN;
                END IF;
                FOR k IN 0 .. jsonb_array_length(v_roles) - 1 LOOP
                    v_role := v_roles->k;
                    IF jsonb_typeof(v_role) IS DISTINCT FROM 'object'
                       OR jsonb_typeof(v_role->'service') IS DISTINCT FROM 'string'
                       OR jsonb_typeof(v_role->'group') IS DISTINCT FROM 'string'
                       OR jsonb_typeof(v_role->'level') IS DISTINCT FROM 'string'
                       OR NOT EXISTS (SELECT 1 FROM rolebyte.role_definition rd
                                       WHERE rd.service_key = v_role->>'service'
                                         AND rd.role_group  = v_role->>'group'
                                         AND rd.role_level  = v_role->>'level') THEN
                        po_data := util.result_error('membership:invalid',
                            format('product %s has an account holding a level that does not exist', v_pos));
                        RETURN;
                    END IF;
                    IF v_role->>'group' = 'deployment'
                       OR rolebyte.is_administrator_rung(v_role->>'group', v_role->>'level') THEN
                        po_data := util.result_error('membership:invalid',
                            format('product %s has an account holding a level a service account may not hold', v_pos));
                        RETURN;
                    END IF;
                END LOOP;
                v_accts := v_accts || jsonb_build_array(jsonb_build_object(
                    'subjectKey',  v_subject,
                    'displayName', rolebyte.door_name(v_acct->'displayName'),
                    'roles',       COALESCE((
                        SELECT jsonb_agg(jsonb_build_object('service', s, 'group', g, 'level', l)
                                         ORDER BY s COLLATE "C", g COLLATE "C", l COLLATE "C")
                          FROM (SELECT DISTINCT r->>'service' AS s, r->>'group' AS g, r->>'level' AS l
                                  FROM jsonb_array_elements(v_roles) r) x), '[]'::jsonb)));
            END LOOP;
            SELECT COALESCE(jsonb_agg(a ORDER BY a->>'subjectKey' COLLATE "C"), '[]'::jsonb) INTO v_accts
              FROM jsonb_array_elements(v_accts) a;
        ELSE
            po_data := util.result_error('membership:invalid', format('product %s needs its accounts as a list', v_pos));
            RETURN;
        END IF;

        v_norm := v_norm || jsonb_build_array(jsonb_build_object(
            'key', v_key, 'displayName', v_display, 'gives', v_gives, 'needs', v_needs, 'accounts', v_accts));
    END LOOP;

    -- Every need is a product of this list, and the needs form no circle.
    FOR i IN 0 .. jsonb_array_length(v_norm) - 1 LOOP
        IF EXISTS (SELECT 1 FROM jsonb_array_elements_text(v_norm->i->'needs') n WHERE n <> ALL (v_keys)) THEN
            po_data := util.result_error('membership:invalid',
                format('product %s needs a product that is not in the list', i + 1));
            RETURN;
        END IF;
    END LOOP;
    v_rest := v_keys;
    WHILE COALESCE(array_length(v_rest, 1), 0) > 0 LOOP
        SELECT COALESCE(array_agg(e->>'key'), '{}'::text[]) INTO v_next
          FROM jsonb_array_elements(v_norm) e
         WHERE (e->>'key') = ANY (v_rest)
           AND NOT EXISTS (SELECT 1 FROM jsonb_array_elements_text(e->'needs') n WHERE n = ANY (v_rest));
        IF COALESCE(array_length(v_next, 1), 0) = 0 THEN
            po_data := util.result_error('membership:invalid', 'the needs of the products form a circle');
            RETURN;
        END IF;
        v_rest := ARRAY(SELECT k FROM unnest(v_rest) k WHERE k <> ALL (v_next));
    END LOOP;

    PERFORM pg_advisory_xact_lock(hashtextextended('rolebyte.deployment', 0));

    -- A product some company has cannot leave the catalog.
    IF EXISTS (SELECT 1 FROM rolebyte.tenant_product tp
                WHERE tp.state = 'ticked' AND tp.product_key <> ALL (v_keys)) THEN
        po_data := util.result_error('membership:conflict', 'a product that a company has cannot be removed');
        RETURN;
    END IF;

    -- The new list may not break the guard: no product may need one that a company having
    -- it has not ticked.
    FOR i IN 0 .. jsonb_array_length(v_norm) - 1 LOOP
        FOR v_need IN SELECT n FROM jsonb_array_elements_text(v_norm->i->'needs') n ORDER BY n COLLATE "C" LOOP
            IF EXISTS (SELECT 1 FROM rolebyte.tenant_product tp
                        WHERE tp.product_key = v_norm->i->>'key' AND tp.state = 'ticked'
                          AND NOT rolebyte.door_ticked(tp.tenant_id, v_need)) THEN
                po_data := util.result_error('membership:conflict', (v_norm->i->>'key') || ' needs ' || v_need);
                RETURN;
            END IF;
        END LOOP;
    END LOOP;

    -- What the ticked products give, per company, before anything changes.
    SELECT COALESCE(jsonb_agg(DISTINCT jsonb_build_object('t', tp.tenant_id, 's', pe.service_key, 'f', pe.feature_key)), '[]'::jsonb)
      INTO v_before
      FROM rolebyte.tenant_product tp
      JOIN rolebyte.product_entitlement pe ON pe.product_key = tp.product_key
     WHERE tp.state = 'ticked';

    -- Which service accounts the ticked products listed, per company, before the old lists
    -- are replaced: a company's account that no ticked product lists afterwards is ended.
    SELECT COALESCE(jsonb_agg(DISTINCT jsonb_build_object('t', tp.tenant_id, 'k', pa.subject_key)), '[]'::jsonb)
      INTO v_listed
      FROM rolebyte.tenant_product tp
      JOIN rolebyte.product_account pa ON pa.product_key = tp.product_key
     WHERE tp.state = 'ticked';

    -- The catalog.
    FOR i IN 0 .. jsonb_array_length(v_norm) - 1 LOOP
        v_entry := v_norm->i;
        IF rolebyte.door_product_json(v_entry->>'key') IS DISTINCT FROM v_entry THEN
            v_changed := array_append(v_changed, v_entry->>'key');
        END IF;
    END LOOP;

    DELETE FROM rolebyte.product_requirement WHERE product_key = ANY (v_changed);
    DELETE FROM rolebyte.tenant_product WHERE product_key <> ALL (v_keys);
    FOR v_row IN
        DELETE FROM rolebyte.product p WHERE p.key <> ALL (v_keys) RETURNING p.key
    LOOP
        INSERT INTO rolebyte.event (id, actor, tenant_id, user_id, kind, payload)
        VALUES (util.generate_ulid(), v_actor, NULL, NULL, 'productUnregistered',
                jsonb_build_object('product', v_row.key));
        v_unreg := v_unreg + 1;
    END LOOP;

    FOR i IN 0 .. jsonb_array_length(v_norm) - 1 LOOP
        v_entry := v_norm->i;
        v_key := v_entry->>'key';
        IF v_key = ANY (v_changed) THEN
            INSERT INTO rolebyte.product AS p (key, display_name, registered_by)
            VALUES (v_key, v_entry->>'displayName', v_actor)
            ON CONFLICT (key) DO UPDATE
                SET display_name = EXCLUDED.display_name, registered_by = EXCLUDED.registered_by,
                    registered_at = now();
            DELETE FROM rolebyte.product_entitlement WHERE product_key = v_key;
            DELETE FROM rolebyte.product_account WHERE product_key = v_key;
            INSERT INTO rolebyte.product_entitlement (product_key, service_key, feature_key)
            SELECT v_key, g->>'service', g->>'feature' FROM jsonb_array_elements(v_entry->'gives') g;
            INSERT INTO rolebyte.product_account (product_key, subject_key, display_name, roles)
            SELECT v_key, a->>'subjectKey', a->>'displayName', a->'roles' FROM jsonb_array_elements(v_entry->'accounts') a;
            INSERT INTO rolebyte.event (id, actor, tenant_id, user_id, kind, payload)
            VALUES (util.generate_ulid(), v_actor, NULL, NULL, 'productRegistered',
                    jsonb_build_object('product', v_key));
            v_reg := v_reg + 1;
        END IF;
    END LOOP;
    FOR i IN 0 .. jsonb_array_length(v_norm) - 1 LOOP
        v_entry := v_norm->i;
        IF (v_entry->>'key') = ANY (v_changed) THEN
            INSERT INTO rolebyte.product_requirement (product_key, requires_key)
            SELECT v_entry->>'key', n FROM jsonb_array_elements_text(v_entry->'needs') n;
        END IF;
    END LOOP;

    -- The companies, one at a time: adoption, the entitlements the catalog changed, then
    -- the service accounts.
    FOR v_tenant IN SELECT t.id FROM rolebyte.tenant t ORDER BY t.created_at, t.id LOOP
        SELECT count(*) INTO v_ev_before FROM rolebyte.event WHERE tenant_id = v_tenant;

        -- Adoption, only when asked for: a product the company already holds everything of
        -- is ticked and given like any ticked product, a needed product first.
        IF v_adopt THEN
            FOREACH v_product IN ARRAY rolebyte.door_topo(v_keys) LOOP
                IF NOT EXISTS (SELECT 1 FROM rolebyte.tenant_product tp
                                WHERE tp.tenant_id = v_tenant AND tp.product_key = v_product)
                   AND rolebyte.door_need_missing(v_tenant, v_product) IS NULL
                   AND NOT EXISTS (
                        SELECT 1 FROM rolebyte.product_entitlement pe
                         WHERE pe.product_key = v_product
                           AND NOT EXISTS (SELECT 1 FROM rolebyte.tenant_entitlement e
                                            WHERE e.tenant_id = v_tenant AND e.state = 'entitled'
                                              AND e.service_key = pe.service_key
                                              AND (e.feature_key = pe.feature_key OR e.feature_key = ''))) THEN
                    PERFORM rolebyte.door_tick(v_actor, v_tenant, v_product, true);
                    PERFORM rolebyte.door_product_give(v_actor, v_tenant, v_product);
                    v_adopted := v_adopted + 1;
                END IF;
            END LOOP;
        END IF;

        -- A company with no ticked product is not touched.
        CONTINUE WHEN NOT EXISTS (SELECT 1 FROM rolebyte.tenant_product tp
                                   WHERE tp.tenant_id = v_tenant AND tp.state = 'ticked');

        FOR v_row IN
            SELECT DISTINCT pe.service_key, pe.feature_key
              FROM rolebyte.tenant_product tp
              JOIN rolebyte.product_entitlement pe ON pe.product_key = tp.product_key
             WHERE tp.tenant_id = v_tenant AND tp.state = 'ticked'
        LOOP
            PERFORM rolebyte.door_entitle(v_actor, v_tenant, v_row.service_key, v_row.feature_key);
        END LOOP;
        FOR v_row IN
            SELECT b->>'s' AS service_key, b->>'f' AS feature_key
              FROM jsonb_array_elements(v_before) b
             WHERE b->>'t' = v_tenant
               AND NOT EXISTS (SELECT 1 FROM rolebyte.tenant_product tp
                                JOIN rolebyte.product_entitlement pe ON pe.product_key = tp.product_key
                               WHERE tp.tenant_id = v_tenant AND tp.state = 'ticked'
                                 AND pe.service_key = b->>'s' AND pe.feature_key = b->>'f')
        LOOP
            PERFORM rolebyte.door_revoke_row(v_actor, v_tenant, v_row.service_key, v_row.feature_key);
        END LOOP;

        -- The accounts a ticked product of this company listed before and none lists now.
        SELECT COALESCE(array_agg(DISTINCT l->>'k'), '{}'::text[]) INTO v_ended
          FROM jsonb_array_elements(v_listed) l
         WHERE l->>'t' = v_tenant
           AND NOT EXISTS (SELECT 1 FROM rolebyte.product_account pa
                            WHERE pa.subject_key = l->>'k'
                              AND rolebyte.door_ticked(v_tenant, pa.product_key));

        v_follow := rolebyte.product_accounts_follow(v_actor, v_tenant, v_ended);

        SELECT count(*) INTO v_ev_after FROM rolebyte.event WHERE tenant_id = v_tenant;
        IF v_ev_after > v_ev_before OR (v_follow->>'changed')::boolean THEN
            v_companies := v_companies + 1;
        END IF;
    END LOOP;

    po_data := util.result_success(jsonb_build_object(
        'registered',   v_reg,
        'unregistered', v_unreg,
        'adopted',      v_adopted,
        'companies',    v_companies));
EXCEPTION
    WHEN sqlstate 'P0001' THEN
        RAISE;
    WHEN OTHERS THEN
        RAISE EXCEPTION '%', util.result_error('membership:error', sqlerrm) USING errcode = 'P0001';
END;
$$;

REVOKE ALL ON PROCEDURE rolebyte.products_register(jsonb, jsonb) FROM PUBLIC;
REVOKE EXECUTE ON PROCEDURE rolebyte.products_register(jsonb, jsonb) FROM rolebyte_public;

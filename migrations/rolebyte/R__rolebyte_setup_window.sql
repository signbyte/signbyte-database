-- R (repeatable): the setup window. A company that was just opened can be given its
-- first configuration before any of its people has signed in: for ten minutes one
-- service account is a member of that company and holds exactly the company's
-- configuration permissions, and nothing else.
--
-- The account's row carries `setup_until` (V28). Such a row is answered as a member
-- only while its window is open, and then holds only what `setup_scopes` returns: no
-- level, no role, no administrator's box, no place on the list of the deployment's
-- administrators, and no strong-sign-in scope.
--
-- The window closes by itself when its time is up, and the moment a person of the
-- company is active; the procedures that make a person active also end the company's
-- setup rows for good (`setup_rows_end`), as does `company_setup_close` on purpose. Both procedures take the
-- door's caller check first, like every procedure of the deployment's door.

-- setup_company_entered — whether somebody of a company has signed in: the company has
-- an active account of a person (a key that starts with `sub:`), or its history has a
-- line of a person's account becoming active (`claimAttached`, `directoryAdmitted`; a
-- line of a service account's row does not count). The history only grows, so a
-- company a person has ever signed in to stays entered, whatever became of that person
-- or of any setup row since. This is the one definition every caller below uses.
CREATE OR REPLACE FUNCTION rolebyte.setup_company_entered(p_tenant text)
RETURNS boolean
LANGUAGE sql
STABLE
SET search_path = rolebyte, pg_temp
AS $$
    SELECT EXISTS (SELECT 1
                     FROM rolebyte.user_account p
                    WHERE p.tenant_id = p_tenant
                      AND starts_with(p.subject_key, 'sub:')
                      AND p.status = 'active')
        OR EXISTS (SELECT 1
                     FROM rolebyte.event e
                     JOIN rolebyte.user_account p ON p.id = e.user_id
                    WHERE e.tenant_id = p_tenant
                      AND e.kind IN ('claimAttached', 'directoryAdmitted')
                      AND p.tenant_id = p_tenant
                      AND starts_with(p.subject_key, 'sub:'));
$$;

REVOKE ALL ON FUNCTION rolebyte.setup_company_entered(text) FROM PUBLIC;

-- setup_window_open — whether a setup window is open for an account's row now: the
-- row is active, its `setup_until` is later than now and nobody of the company has
-- signed in (`setup_company_entered`). False for a row that is not a setup account's
-- row, and for an account that does not exist. This is the one definition every
-- caller below uses.
CREATE OR REPLACE FUNCTION rolebyte.setup_window_open(p_user_id text)
RETURNS boolean
LANGUAGE sql
STABLE
SET search_path = rolebyte, pg_temp
AS $$
    SELECT EXISTS (
        SELECT 1
          FROM rolebyte.user_account u
         WHERE u.id = p_user_id
           AND u.status = 'active'
           AND u.setup_until > now()
           AND NOT rolebyte.setup_company_entered(u.tenant_id));
$$;

REVOKE ALL ON FUNCTION rolebyte.setup_window_open(text) FROM PUBLIC;

-- setup_scopes — what a setup account holds in a company: a JSON array of
-- `service/feature:act` texts, one for every permission of the class
-- `tenantConfiguration` that is not retired and whose service and feature the company
-- is entitled to (the whole service, the feature itself, or a feature it is nested
-- under; the same rule `resolve` applies to every other permission). Nothing else: no
-- level and no other class. An empty array when the company has none.
CREATE OR REPLACE FUNCTION rolebyte.setup_scopes(p_tenant text)
RETURNS jsonb
LANGUAGE sql
STABLE
SET search_path = rolebyte, pg_temp
AS $$
    SELECT COALESCE(jsonb_agg(DISTINCT s.scope), '[]'::jsonb)
      FROM (SELECT sp.service_key || '/' || sp.feature_key || ':' || sp.act AS scope
              FROM rolebyte.service_permission sp
             WHERE sp.class = 'tenantConfiguration'
               AND sp.retired_at IS NULL
               AND EXISTS (
                   SELECT 1 FROM rolebyte.tenant_entitlement e
                    WHERE e.tenant_id = p_tenant
                      AND e.service_key = sp.service_key
                      AND e.state = 'entitled'
                      AND (e.feature_key = ''
                           OR sp.feature_key = e.feature_key
                           OR starts_with(sp.feature_key, e.feature_key || '/')))) s;
$$;

REVOKE ALL ON FUNCTION rolebyte.setup_scopes(text) FROM PUBLIC;

-- setup_rows_end — end every setup account's row of a company that is still active:
-- each is made revoked (`setup_until` stays as it is) and gets a `setupClosed` history
-- line of its own, carrying the row and the account's key. Answers whether it ended at
-- least one row; with none to end it writes nothing. Used by `company_setup_close` and
-- by every procedure that makes a person's account active, in the same transaction, so
-- that a window never comes back once a person has signed in.
CREATE OR REPLACE FUNCTION rolebyte.setup_rows_end(p_actor text, p_tenant text)
RETURNS boolean
LANGUAGE plpgsql
VOLATILE
SET search_path = rolebyte, util, pg_temp
AS $$
DECLARE
    v_row   record;
    v_ended boolean := false;
BEGIN
    FOR v_row IN
        UPDATE rolebyte.user_account
           SET status = 'revoked'
         WHERE tenant_id = p_tenant AND setup_until IS NOT NULL AND status = 'active'
        RETURNING id, subject_key
    LOOP
        INSERT INTO rolebyte.event (id, actor, tenant_id, user_id, kind, payload)
        VALUES (util.generate_ulid(), p_actor, p_tenant, v_row.id, 'setupClosed',
                jsonb_build_object('subjectKey', v_row.subject_key));
        v_ended := true;
    END LOOP;
    RETURN v_ended;
END;
$$;

REVOKE ALL ON FUNCTION rolebyte.setup_rows_end(text, text) FROM PUBLIC;

-- company_setup_open — open a setup window in a company for a service account. Input
-- {actor, mode, tenantId, account}. The window lasts ten minutes from the call; the
-- length is fixed here and is not an input. Refusals, in this order, each before the
-- first write:
--   * `account` missing, not a typed subject key, or not a service account's key:
--     `membership:invalid`;
--   * no such company, or one that is not active: `membership:not_found`;
--   * the account is listed as an account of a product: `membership:conflict`;
--   * somebody of the company has signed in, even if that person was removed since
--     (`setup_company_entered`): `membership:conflict`;
--   * a window is already open in the company: `membership:conflict`;
--   * the account is already a standing member of the company: `membership:conflict`.
-- Otherwise the account's row in the company is made (active, named by its key, under
-- the company's default user type), or, when an earlier window left one, made active
-- again, and its `setup_until` is set. A history line `setupOpened` of the company
-- carries the account's key. The account gets no assignment, no role and no place on
-- any list. Answers {account, scopes, endsAt}: `scopes` is what `setup_scopes` says.
CREATE OR REPLACE PROCEDURE rolebyte.company_setup_open(IN pi_data jsonb, INOUT po_data jsonb)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = rolebyte, util, pg_temp
AS $$
DECLARE
    v_actor   text := NULLIF(trim(pi_data->>'actor'), '');
    v_tenant  text := CASE WHEN jsonb_typeof(pi_data->'tenantId') = 'string'
                           THEN NULLIF(trim(pi_data->>'tenantId'), '') END;
    v_account text := CASE WHEN jsonb_typeof(pi_data->'account') = 'string'
                           THEN trim(pi_data->>'account') END;
    v_refusal jsonb;
    v_status  text;
    v_row     rolebyte.user_account%ROWTYPE;
    v_id      text;
    v_type    text;
    v_until   timestamptz := now() + interval '10 minutes';
BEGIN
    v_refusal := rolebyte.door_enter(pi_data, true, false);
    IF v_refusal IS NOT NULL THEN
        po_data := v_refusal;
        RETURN;
    END IF;
    IF (starts_with(v_account, 'svc:') AND rolebyte.is_typed_subject_key(v_account)) IS NOT TRUE THEN
        po_data := util.result_error('membership:invalid', 'account is a service account''s key');
        RETURN;
    END IF;
    SELECT t.status INTO v_status FROM rolebyte.tenant t WHERE t.id = v_tenant;
    IF v_status IS DISTINCT FROM 'active' THEN
        po_data := util.result_error('membership:not_found', 'no such company');
        RETURN;
    END IF;

    -- The company's administrators' lock, then the company's row, then the account's
    -- row: the order the other writers of a company's accounts take them.
    PERFORM rolebyte.administrator_lock(v_tenant);
    PERFORM 1 FROM rolebyte.tenant WHERE id = v_tenant FOR UPDATE;

    IF EXISTS (SELECT 1 FROM rolebyte.product_account pa WHERE pa.subject_key = v_account) THEN
        po_data := util.result_error('membership:conflict', 'this account already belongs to a product');
        RETURN;
    END IF;
    IF rolebyte.setup_company_entered(v_tenant) THEN
        po_data := util.result_error('membership:conflict', 'somebody of this company has signed in');
        RETURN;
    END IF;
    IF EXISTS (SELECT 1 FROM rolebyte.user_account u
                WHERE u.tenant_id = v_tenant AND u.setup_until IS NOT NULL
                  AND rolebyte.setup_window_open(u.id)) THEN
        po_data := util.result_error('membership:conflict', 'the company is already being set up');
        RETURN;
    END IF;
    SELECT * INTO v_row
      FROM rolebyte.user_account u
     WHERE u.tenant_id = v_tenant AND u.subject_key = v_account
       FOR UPDATE;
    IF FOUND AND v_row.setup_until IS NULL THEN
        po_data := util.result_error('membership:conflict', 'this account is already a member of the company');
        RETURN;
    END IF;

    IF v_row.id IS NOT NULL THEN
        UPDATE rolebyte.user_account
           SET status = 'active', setup_until = v_until
         WHERE id = v_row.id;
        v_id := v_row.id;
    ELSE
        v_type := rolebyte.ensure_default_user_type(v_actor, v_tenant, NULL);
        v_id := util.generate_ulid();
        INSERT INTO rolebyte.user_account (id, tenant_id, subject_key, display_name, status,
                                           user_type_id, user_type_source, setup_until)
        VALUES (v_id, v_tenant, v_account, v_account, 'active',
                v_type, 'workspaceDefault', v_until);
    END IF;

    -- The line carries the account's row, so that the row's status can be followed
    -- through the history.
    INSERT INTO rolebyte.event (id, actor, tenant_id, user_id, kind, payload)
    VALUES (util.generate_ulid(), v_actor, v_tenant, v_id, 'setupOpened',
            jsonb_build_object('subjectKey', v_account));

    po_data := util.result_success(jsonb_build_object(
        'account', v_account,
        'scopes',  rolebyte.setup_scopes(v_tenant),
        'endsAt',  v_until));
EXCEPTION
    WHEN sqlstate 'P0001' THEN
        RAISE;
    WHEN OTHERS THEN
        RAISE EXCEPTION '%', util.result_error('membership:error', sqlerrm) USING errcode = 'P0001';
END;
$$;

REVOKE ALL ON PROCEDURE rolebyte.company_setup_open(jsonb, jsonb) FROM PUBLIC;
GRANT EXECUTE ON PROCEDURE rolebyte.company_setup_open(jsonb, jsonb) TO rolebyte_public;

-- company_setup_close — end a company's setup window. Input {actor, mode, tenantId}.
-- A missing `tenantId` is `membership:invalid`, an unknown company
-- `membership:not_found`. Every setup account's row of the company that is still
-- active is made revoked (`setup_until` stays as it is), a row whose time ran out and
-- was never closed included, each with a `setupClosed` history line (`setup_rows_end`).
-- `changed` is true when at least one row was ended; a second close ends nothing and
-- writes nothing. Answers {changed}.
CREATE OR REPLACE PROCEDURE rolebyte.company_setup_close(IN pi_data jsonb, INOUT po_data jsonb)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = rolebyte, util, pg_temp
AS $$
DECLARE
    v_actor   text := NULLIF(trim(pi_data->>'actor'), '');
    v_tenant  text := CASE WHEN jsonb_typeof(pi_data->'tenantId') = 'string'
                           THEN NULLIF(trim(pi_data->>'tenantId'), '') END;
    v_refusal jsonb;
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

    PERFORM rolebyte.administrator_lock(v_tenant);
    PERFORM 1 FROM rolebyte.tenant WHERE id = v_tenant FOR UPDATE;

    po_data := util.result_success(jsonb_build_object('changed',
        rolebyte.setup_rows_end(v_actor, v_tenant)));
EXCEPTION
    WHEN sqlstate 'P0001' THEN
        RAISE;
    WHEN OTHERS THEN
        RAISE EXCEPTION '%', util.result_error('membership:error', sqlerrm) USING errcode = 'P0001';
END;
$$;

REVOKE ALL ON PROCEDURE rolebyte.company_setup_close(jsonb, jsonb) FROM PUBLIC;
GRANT EXECUTE ON PROCEDURE rolebyte.company_setup_close(jsonb, jsonb) TO rolebyte_public;

-- Unit test: the setup window, the few minutes in which one service account is a member of a
-- company that nobody has signed in to yet and holds that company's configuration permissions.
--
-- Opening is tested whole (the answer, the row, the one history line, nothing given to the
-- account beyond the permissions) and refused for every input and every state of the company
-- (each refusal says its code and writes nothing). What the register answers for the account
-- is tested against every way a window ends: closing it, its time running out, a person of the
-- company becoming active, an entitlement taken away, and in another company. Closing is tested
-- twice over, by the one who opened and by another administrator. The door's reads of a company
-- and its count of administrators are compared before, during and after a window.
--
-- The whole test runs in one transaction that is rolled back at the end. It empties the
-- register's tenants and services inside it, and the rollback restores them.
--   psql -v ON_ERROR_STOP=1 -f migrations/testing/tests/unit.rolebyte_setup_window.sql

BEGIN;

-- Calls one register procedure and returns its answer; a raised refusal is its answer too.
CREATE OR REPLACE FUNCTION pg_temp.rb(p_proc text, p_in jsonb) RETURNS jsonb
LANGUAGE plpgsql AS $$
DECLARE
    v jsonb;
BEGIN
    BEGIN
        EXECUTE format('CALL rolebyte.%I($1, NULL::jsonb)', p_proc) INTO v USING p_in;
    EXCEPTION
        WHEN sqlstate 'P0001' THEN
            v := sqlerrm::jsonb;
    END;
    RETURN v;
END $$;

-- The call must succeed; returns its data.
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

-- The condition must hold; NULL is a failure.
CREATE OR REPLACE FUNCTION pg_temp.must(p_cond boolean, p_why text) RETURNS void
LANGUAGE plpgsql AS $$
BEGIN
    IF p_cond IS NOT TRUE THEN
        RAISE EXCEPTION '%', p_why;
    END IF;
END $$;

-- What the tables a window touches hold, as one comparable text.
CREATE OR REPLACE FUNCTION pg_temp.fingerprint() RETURNS text
LANGUAGE sql AS $$
    SELECT md5(concat_ws('|',
        (SELECT coalesce(string_agg(t::text, ',' ORDER BY t::text), '') FROM rolebyte.tenant t),
        (SELECT coalesce(string_agg(t::text, ',' ORDER BY t::text), '') FROM rolebyte.user_account t),
        (SELECT coalesce(string_agg(t::text, ',' ORDER BY t::text), '') FROM rolebyte.assignment t),
        (SELECT coalesce(string_agg(t::text, ',' ORDER BY t::text), '') FROM rolebyte.tenant_entitlement t),
        (SELECT coalesce(string_agg(t::text, ',' ORDER BY t::text), '') FROM rolebyte.deployment_admin t),
        (SELECT coalesce(string_agg(t::text, ',' ORDER BY t::text), '') FROM rolebyte.product_account t),
        (SELECT coalesce(string_agg(t::text, ',' ORDER BY t::text), '') FROM rolebyte.product t),
        (SELECT coalesce(string_agg(t::text, ',' ORDER BY t::text), '') FROM rolebyte.product_entitlement t),
        (SELECT count(*) FROM rolebyte.event)))
$$;

-- The call must be refused with this code and sentence, and change nothing.
CREATE OR REPLACE FUNCTION pg_temp.refused(p_proc text, p_in jsonb, p_code text, p_says text, p_why text) RETURNS void
LANGUAGE plpgsql AS $$
DECLARE
    v      jsonb;
    before text := pg_temp.fingerprint();
BEGIN
    v := pg_temp.rb(p_proc, p_in);
    IF v->>'result' IS DISTINCT FROM 'error' OR v->>'code' IS DISTINCT FROM p_code THEN
        RAISE EXCEPTION '% should be refused %: %', p_why, p_code, v;
    END IF;
    IF p_says IS NOT NULL AND position(p_says IN coalesce(v->>'message', '')) = 0 THEN
        RAISE EXCEPTION '% must say "%", said "%"', p_why, p_says, v->>'message';
    END IF;
    IF pg_temp.fingerprint() IS DISTINCT FROM before THEN
        RAISE EXCEPTION '% was refused but changed something', p_why;
    END IF;
END $$;

CREATE OR REPLACE FUNCTION pg_temp.person() RETURNS text
LANGUAGE sql AS $$ SELECT 'sub:' || util.generate_ulid() $$;

-- A person with an account in a company, in the state asked for (invited, active, revoked).
CREATE OR REPLACE FUNCTION pg_temp.member(p_tenant text, p_name text, p_status text) RETURNS text
LANGUAGE plpgsql AS $$
DECLARE
    v_key text := pg_temp.person();
BEGIN
    PERFORM pg_temp.ok('user_invite', jsonb_build_object('actor', 'fx', 'tenantId', p_tenant,
        'subjectKey', v_key, 'displayName', p_name), 'invite a member');
    IF p_status = 'active' THEN
        PERFORM pg_temp.ok('claim_attach', jsonb_build_object('actor', 'fx', 'subjectKey', v_key), 'activate a member');
    ELSIF p_status = 'revoked' THEN
        UPDATE rolebyte.user_account SET status = 'revoked' WHERE tenant_id = p_tenant AND subject_key = v_key;
    END IF;
    RETURN v_key;
END $$;

-- A service account that is a standing member of a company, in the state asked for.
CREATE OR REPLACE FUNCTION pg_temp.svc_member(p_tenant text, p_key text, p_status text) RETURNS void
LANGUAGE plpgsql AS $$
BEGIN
    INSERT INTO rolebyte.user_account (id, tenant_id, subject_key, display_name, status, user_type_id, user_type_source)
    VALUES (util.generate_ulid(), p_tenant, p_key, p_key, p_status,
            rolebyte.ensure_default_user_type('fx', p_tenant, NULL), 'workspaceDefault');
END $$;

-- An active member of the deployment's company who is on the list of its administrators.
CREATE OR REPLACE FUNCTION pg_temp.admin(p_dep text) RETURNS text
LANGUAGE plpgsql AS $$
DECLARE
    v_key text := pg_temp.member(p_dep, 'Deployment admin', 'active');
BEGIN
    PERFORM pg_temp.ok('deployment_admin_add', jsonb_build_object('actor', 'fx', 'subjectKey', v_key,
        'addedFrom', 'screen'), 'list an administrator');
    RETURN v_key;
END $$;

CREATE OR REPLACE FUNCTION pg_temp.customer(p_name text) RETURNS text
LANGUAGE sql AS $$
    SELECT pg_temp.ok('tenant_create', jsonb_build_object('actor', 'fx', 'name', p_name), 'a customer company')->>'id'
$$;

CREATE OR REPLACE FUNCTION pg_temp.entitle(p_tenant text, p_service text, p_feature text) RETURNS void
LANGUAGE sql AS $$
    INSERT INTO rolebyte.tenant_entitlement (id, tenant_id, service_key, feature_key)
    VALUES (util.generate_ulid(), p_tenant, p_service, p_feature)
$$;

CREATE OR REPLACE FUNCTION pg_temp.permission(p_service text, p_feature text, p_act text, p_class text,
                                              p_retired boolean DEFAULT false) RETURNS void
LANGUAGE sql AS $$
    INSERT INTO rolebyte.service_permission (id, service_key, feature_key, act, class, plane, retired_at)
    VALUES (util.generate_ulid(), p_service, p_feature, p_act, p_class, 'tenant',
            CASE WHEN p_retired THEN now() END)
$$;

-- The door's calls, as an administrator makes them on the saas mode.
CREATE OR REPLACE FUNCTION pg_temp.sopen(p_actor text, p_tenant text, p_account text) RETURNS jsonb
LANGUAGE sql AS $$
    SELECT pg_temp.rb('company_setup_open', jsonb_build_object('actor', p_actor, 'mode', 'saas',
        'tenantId', p_tenant, 'account', p_account))
$$;

CREATE OR REPLACE FUNCTION pg_temp.sclose(p_actor text, p_tenant text) RETURNS jsonb
LANGUAGE sql AS $$
    SELECT pg_temp.rb('company_setup_close', jsonb_build_object('actor', p_actor, 'mode', 'saas', 'tenantId', p_tenant))
$$;

-- The open call must succeed; returns its data.
CREATE OR REPLACE FUNCTION pg_temp.opened(p_actor text, p_tenant text, p_account text, p_why text) RETURNS jsonb
LANGUAGE plpgsql AS $$
DECLARE
    v jsonb := pg_temp.sopen(p_actor, p_tenant, p_account);
BEGIN
    IF v->>'result' IS DISTINCT FROM 'success' THEN
        RAISE EXCEPTION '% failed: %', p_why, v;
    END IF;
    RETURN v->'data';
END $$;

-- The open call must be refused, with nothing written.
CREATE OR REPLACE FUNCTION pg_temp.open_refused(p_actor text, p_tenant text, p_account jsonb, p_code text,
                                                p_says text, p_why text) RETURNS void
LANGUAGE sql AS $$
    SELECT pg_temp.refused('company_setup_open',
        jsonb_strip_nulls(jsonb_build_object('actor', p_actor, 'mode', 'saas', 'tenantId', p_tenant,
                                             'account', p_account)),
        p_code, p_says, p_why)
$$;

-- The close call must succeed; returns whether it changed something.
CREATE OR REPLACE FUNCTION pg_temp.closed(p_actor text, p_tenant text, p_why text) RETURNS boolean
LANGUAGE plpgsql AS $$
DECLARE
    v jsonb := pg_temp.sclose(p_actor, p_tenant);
BEGIN
    IF v->>'result' IS DISTINCT FROM 'success' THEN
        RAISE EXCEPTION '% failed: %', p_why, v;
    END IF;
    RETURN (v->'data'->>'changed')::boolean;
END $$;

-- What the register answers for a subject: its membership in one company, or NULL.
CREATE OR REPLACE FUNCTION pg_temp.membership(p_subject text, p_tenant text) RETURNS jsonb
LANGUAGE plpgsql AS $$
DECLARE
    v jsonb;
BEGIN
    CALL rolebyte.resolve(jsonb_build_object('subjectKey', p_subject), v);
    RETURN (SELECT m FROM jsonb_array_elements(v->'data'->'memberships') m WHERE m->>'tenantId' = p_tenant);
END $$;

-- An array of texts as one comparable text.
CREATE OR REPLACE FUNCTION pg_temp.texts(p_list jsonb) RETURNS text
LANGUAGE sql AS $$
    SELECT coalesce(string_agg(t, ',' ORDER BY t COLLATE "C"), '') FROM jsonb_array_elements_text(p_list) t
$$;

CREATE OR REPLACE FUNCTION pg_temp.lines(p_kind text, p_tenant text) RETURNS int
LANGUAGE sql AS $$ SELECT count(*)::int FROM rolebyte.event WHERE kind = p_kind AND tenant_id = p_tenant $$;

CREATE OR REPLACE FUNCTION pg_temp.row_of(p_tenant text, p_key text) RETURNS rolebyte.user_account
LANGUAGE sql AS $$ SELECT u FROM rolebyte.user_account u WHERE u.tenant_id = p_tenant AND u.subject_key = p_key $$;

-- What the door's reads answer for a company, and how many administrators it counts, as one text.
CREATE OR REPLACE FUNCTION pg_temp.reads(p_actor text, p_tenant text) RETURNS text
LANGUAGE plpgsql AS $$
DECLARE
    v_in jsonb := jsonb_build_object('actor', p_actor, 'mode', 'saas', 'tenantId', p_tenant);
BEGIN
    RETURN concat_ws('|',
        pg_temp.rb('company_list', jsonb_build_object('actor', p_actor, 'mode', 'saas'))::text,
        pg_temp.rb('company_get', v_in)::text,
        pg_temp.rb('company_administrators', v_in)::text,
        (pg_temp.rb('company_get', v_in)->'data'->'company'->>'administrators'));
END $$;

-- The register's services, the permissions of each by class, and the levels used below.
--   alpha: setup:edit and setup/extra:manage (configuration), legacy:edit (configuration, retired),
--          task:view (ordinary), access:assign (role management)
--   beta:  cfg:edit and cfg/deep:edit and other:edit (configuration)
--   gamma: cfg:edit (configuration)
DO $$
BEGIN
    TRUNCATE rolebyte.tenant CASCADE;
    TRUNCATE rolebyte.service CASCADE;

    PERFORM pg_temp.ok('service_register', '{"actor":"fx","service":"alpha","displayName":"Alpha"}', 'register alpha');
    PERFORM pg_temp.ok('service_register', '{"actor":"fx","service":"beta","displayName":"Beta"}', 'register beta');
    PERFORM pg_temp.ok('service_register', '{"actor":"fx","service":"gamma","displayName":"Gamma"}', 'register gamma');
    PERFORM pg_temp.ok('role_define', '{"actor":"fx","service":"alpha","group":"api","level":"read"}', 'alpha read');
    PERFORM pg_temp.ok('role_define', '{"actor":"fx","service":"alpha","group":"membership","level":"admin"}',
        'alpha administrator level');

    PERFORM pg_temp.permission('alpha', 'setup', 'edit', 'tenantConfiguration');
    PERFORM pg_temp.permission('alpha', 'setup/extra', 'manage', 'tenantConfiguration');
    PERFORM pg_temp.permission('alpha', 'legacy', 'edit', 'tenantConfiguration', true);
    PERFORM pg_temp.permission('alpha', 'task', 'view', 'ordinary');
    PERFORM pg_temp.permission('alpha', 'access', 'assign', 'roleManagement');
    PERFORM pg_temp.permission('beta', 'cfg', 'edit', 'tenantConfiguration');
    PERFORM pg_temp.permission('beta', 'cfg/deep', 'edit', 'tenantConfiguration');
    PERFORM pg_temp.permission('beta', 'other', 'edit', 'tenantConfiguration');
    PERFORM pg_temp.permission('gamma', 'cfg', 'edit', 'tenantConfiguration');
END $$;

-- a. The mark on a row, and the constraint that keeps it on a service account's row alone.
DO $$
DECLARE
    v_dep text := util.generate_ulid();
    v_c   text;
    v_ok  boolean := false;
BEGIN
    INSERT INTO rolebyte.tenant (id, name) VALUES (v_dep, 'Constraint Co');
    v_c := v_dep;

    -- The silent side: a person's row and a service account's standing row carry no mark and are accepted.
    PERFORM pg_temp.member(v_c, 'Plain person', 'active');
    PERFORM pg_temp.svc_member(v_c, 'svc:standing', 'active');
    PERFORM pg_temp.must((SELECT count(*) FROM rolebyte.user_account WHERE tenant_id = v_c AND setup_until IS NULL) = 2,
        'rows without the mark are accepted and hold null');

    -- A service account's row may carry the mark.
    INSERT INTO rolebyte.user_account (id, tenant_id, subject_key, display_name, status, user_type_id,
                                       user_type_source, setup_until)
    VALUES (util.generate_ulid(), v_c, 'svc:marked', 'svc:marked', 'active',
            rolebyte.ensure_default_user_type('fx', v_c, NULL), 'workspaceDefault', now() + interval '1 minute');

    -- A person's row may not.
    BEGIN
        INSERT INTO rolebyte.user_account (id, tenant_id, subject_key, display_name, status, user_type_id,
                                           user_type_source, setup_until)
        VALUES (util.generate_ulid(), v_c, 'sub:' || util.generate_ulid(), 'A person', 'active',
                rolebyte.ensure_default_user_type('fx', v_c, NULL), 'workspaceDefault', now() + interval '1 minute');
    EXCEPTION
        WHEN check_violation THEN
            v_ok := true;
    END;
    PERFORM pg_temp.must(v_ok, 'a person''s row may not carry the mark');
    RAISE NOTICE 't: the mark and its constraint';
END $$;

-- b. Opening: the whole of the happy path.
DO $$
DECLARE
    v_dep   text;
    v_a     text;
    v_c     text;
    v       jsonb;
    v_row   rolebyte.user_account;
    v_m     jsonb;
BEGIN
    TRUNCATE rolebyte.tenant CASCADE;
    v_dep := util.generate_ulid();
    INSERT INTO rolebyte.tenant (id, name) VALUES (v_dep, 'Deployment Co');
    PERFORM pg_temp.ok('deployment_company_set', jsonb_build_object('actor', 'fx', 'tenantId', v_dep), 'mark');
    v_a := pg_temp.admin(v_dep);

    v_c := pg_temp.customer('Customer One');
    PERFORM pg_temp.entitle(v_c, 'alpha', '');
    PERFORM pg_temp.entitle(v_c, 'beta', 'cfg');

    v := pg_temp.opened(v_a, v_c, 'svc:setup-one', 'open a window');
    PERFORM pg_temp.must(v->>'account' = 'svc:setup-one', 'the answer names the account');
    PERFORM pg_temp.must(pg_temp.texts(v->'scopes') = 'alpha/setup/extra:manage,alpha/setup:edit,beta/cfg/deep:edit,beta/cfg:edit',
        'the answer lists exactly the configuration permissions of the entitled services: ' || (v->'scopes')::text);
    PERFORM pg_temp.must(jsonb_array_length(v->'scopes') = 4, 'the answer lists four scopes, no more');
    PERFORM pg_temp.must(abs(extract(epoch FROM ((v->>'endsAt')::timestamptz - (now() + interval '10 minutes')))) < 5,
        'the window ends ten minutes on: ' || (v->>'endsAt'));

    v_row := pg_temp.row_of(v_c, 'svc:setup-one');
    PERFORM pg_temp.must(v_row.id IS NOT NULL, 'the account has a row in the company');
    PERFORM pg_temp.must(v_row.status = 'active', 'the row is active');
    PERFORM pg_temp.must(v_row.setup_until = (v->>'endsAt')::timestamptz, 'the row holds the end of the window');
    PERFORM pg_temp.must(v_row.display_name = 'svc:setup-one', 'the row is named by the key');
    PERFORM pg_temp.must(v_row.user_type_id = (SELECT default_user_type_id FROM rolebyte.tenant WHERE id = v_c),
        'the row has the company''s default user type');

    PERFORM pg_temp.must(pg_temp.lines('setupOpened', v_c) = 1, 'one setupOpened line');
    PERFORM pg_temp.must((SELECT payload FROM rolebyte.event WHERE kind = 'setupOpened' AND tenant_id = v_c)
                         = '{"subjectKey": "svc:setup-one"}'::jsonb,
        'the line''s payload is exactly the account''s key');
    PERFORM pg_temp.must((SELECT user_id FROM rolebyte.event WHERE kind = 'setupOpened' AND tenant_id = v_c) = v_row.id,
        'the line carries the account''s row');
    PERFORM pg_temp.must((SELECT actor FROM rolebyte.event WHERE kind = 'setupOpened' AND tenant_id = v_c) = v_a,
        'the line is the caller''s');

    -- Nothing beyond the permissions.
    PERFORM pg_temp.must(NOT EXISTS (SELECT 1 FROM rolebyte.assignment WHERE user_id = v_row.id),
        'no level is given');
    PERFORM pg_temp.must(NOT EXISTS (SELECT 1 FROM rolebyte.tenant_role_assignment WHERE user_id = v_row.id),
        'no company role is given');
    PERFORM pg_temp.must(NOT EXISTS (SELECT 1 FROM rolebyte.deployment_admin WHERE user_id = v_row.id),
        'it is not on the list of the deployment''s administrators');
    PERFORM pg_temp.must(NOT rolebyte.is_administrator(v_row.id), 'it is not an administrator');
    PERFORM pg_temp.must(rolebyte.setup_window_open(v_row.id), 'the window is open');

    -- What the register answers for it.
    v_m := pg_temp.membership('svc:setup-one', v_c);
    PERFORM pg_temp.must(v_m IS NOT NULL, 'the register answers a membership in the company');
    PERFORM pg_temp.must(v_m->>'userId' = v_row.id AND v_m->>'tenantId' = v_c, 'the membership is the row''s');
    PERFORM pg_temp.must(pg_temp.texts(v_m->'scopes') = pg_temp.texts(v->'scopes'),
        'the membership''s scopes are the answer''s: ' || (v_m->'scopes')::text);
    PERFORM pg_temp.must(NOT (v_m ? 'highScopes'), 'no scope that counts on a strong sign-in');
    RAISE NOTICE 't: opening';
END $$;

-- c. What decides the permissions: class, retirement, the company's entitlements.
DO $$
DECLARE
    v_dep text;
    v_a   text;
    v_c   text;
    v     jsonb;
BEGIN
    TRUNCATE rolebyte.tenant CASCADE;
    v_dep := util.generate_ulid();
    INSERT INTO rolebyte.tenant (id, name) VALUES (v_dep, 'Deployment Co');
    PERFORM pg_temp.ok('deployment_company_set', jsonb_build_object('actor', 'fx', 'tenantId', v_dep), 'mark');
    v_a := pg_temp.admin(v_dep);

    -- A company with no product: it opens, holding nothing.
    v_c := pg_temp.customer('No Product Co');
    v := pg_temp.opened(v_a, v_c, 'svc:setup-bare', 'open where nothing is entitled');
    PERFORM pg_temp.must(v->'scopes' = '[]'::jsonb, 'an empty list of scopes: ' || (v->'scopes')::text);
    PERFORM pg_temp.must((pg_temp.membership('svc:setup-bare', v_c)->'scopes') = '[]'::jsonb,
        'the membership is answered and holds nothing');
    PERFORM pg_temp.must(pg_temp.closed(v_a, v_c, 'close it'), 'it closes');

    -- A service the company lacks gives nothing, a feature it holds gives that feature and what is nested in it,
    -- a retired permission, an ordinary one and one of role management give nothing.
    v_c := pg_temp.customer('Feature Co');
    PERFORM pg_temp.entitle(v_c, 'beta', 'cfg');
    v := pg_temp.opened(v_a, v_c, 'svc:setup-feature', 'open with one feature');
    PERFORM pg_temp.must(pg_temp.texts(v->'scopes') = 'beta/cfg/deep:edit,beta/cfg:edit',
        'a feature and the feature nested in it, nothing of the same service outside it, nothing of another service: '
        || (v->'scopes')::text);
    PERFORM pg_temp.must(pg_temp.texts(pg_temp.membership('svc:setup-feature', v_c)->'scopes') = pg_temp.texts(v->'scopes'),
        'the register answers the same');
    PERFORM pg_temp.closed(v_a, v_c, 'close it');

    v_c := pg_temp.customer('Alpha Co');
    PERFORM pg_temp.entitle(v_c, 'alpha', '');
    v := pg_temp.opened(v_a, v_c, 'svc:setup-alpha', 'open with a whole service');
    PERFORM pg_temp.must(pg_temp.texts(v->'scopes') = 'alpha/setup/extra:manage,alpha/setup:edit',
        'no retired, no ordinary and no role-management permission: ' || (v->'scopes')::text);
    PERFORM pg_temp.must(position('alpha/legacy:edit' IN (v->'scopes')::text) = 0, 'a retired permission is not held');
    PERFORM pg_temp.must(position('alpha/task:view' IN (v->'scopes')::text) = 0, 'an ordinary permission is not held');
    PERFORM pg_temp.must(position('alpha/access:assign' IN (v->'scopes')::text) = 0,
        'a permission of role management is not held');
    PERFORM pg_temp.must(NOT EXISTS (SELECT 1 FROM jsonb_array_elements_text(v->'scopes') s
                                      WHERE s !~ '^[a-z]+/[A-Za-z/]+:[A-Za-z]+$'),
        'every scope is service/feature:act, no level');

    -- An entitlement taken away while the window is open: those permissions are gone at once.
    UPDATE rolebyte.tenant_entitlement SET state = 'revoked', revoked_at = now()
     WHERE tenant_id = v_c AND service_key = 'alpha';
    PERFORM pg_temp.must(pg_temp.membership('svc:setup-alpha', v_c)->'scopes' = '[]'::jsonb,
        'the permissions of a service taken away are gone at once');
    PERFORM pg_temp.must(pg_temp.membership('svc:setup-alpha', v_c) IS NOT NULL,
        'the window itself is still open');
    UPDATE rolebyte.tenant_entitlement SET state = 'entitled', revoked_at = NULL
     WHERE tenant_id = v_c AND service_key = 'alpha';
    PERFORM pg_temp.must(pg_temp.texts(pg_temp.membership('svc:setup-alpha', v_c)->'scopes')
                         = 'alpha/setup/extra:manage,alpha/setup:edit', 'and back with the entitlement');

    -- A permission retired while the window is open is gone as well.
    UPDATE rolebyte.service_permission SET retired_at = now() WHERE service_key = 'alpha' AND feature_key = 'setup/extra';
    PERFORM pg_temp.must(pg_temp.texts(pg_temp.membership('svc:setup-alpha', v_c)->'scopes') = 'alpha/setup:edit',
        'a permission retired in the window is gone');
    RAISE NOTICE 't: what a setup account holds';
END $$;

-- d. Opening is refused, for every input and every state of the company; nothing is written.
DO $$
DECLARE
    v_dep    text;
    v_a      text;
    v_plain  text;
    v_c      text;
    v_p      text;
    v_other  text;
    v_dead   text;
    v_prod   text := 'svc:of-a-product';
    v        jsonb;
BEGIN
    TRUNCATE rolebyte.tenant CASCADE;
    v_dep := util.generate_ulid();
    INSERT INTO rolebyte.tenant (id, name) VALUES (v_dep, 'Deployment Co');
    PERFORM pg_temp.ok('deployment_company_set', jsonb_build_object('actor', 'fx', 'tenantId', v_dep), 'mark');
    v_a := pg_temp.admin(v_dep);
    v_plain := pg_temp.member(v_dep, 'Plain member', 'active');
    v_c := pg_temp.customer('Refusals Co');
    PERFORM pg_temp.entitle(v_c, 'alpha', '');

    -- The door's own check, for the two ways asked for here.
    PERFORM pg_temp.open_refused(v_plain, v_c, to_jsonb('svc:x'::text), 'membership:forbidden',
        'not a deployment administrator', 'a caller who is not an administrator');
    PERFORM pg_temp.refused('company_setup_open', jsonb_build_object('actor', v_a, 'mode', 'local',
        'tenantId', v_c, 'account', 'svc:x'), 'membership:forbidden', 'not a deployment administrator',
        'the local mode');

    -- The account.
    PERFORM pg_temp.open_refused(v_a, v_c, NULL, 'membership:invalid', 'account is a service account''s key',
        'no account');
    PERFORM pg_temp.open_refused(v_a, v_c, to_jsonb(pg_temp.person()), 'membership:invalid',
        'account is a service account''s key', 'a person''s key');
    PERFORM pg_temp.open_refused(v_a, v_c, to_jsonb('svc:'::text), 'membership:invalid',
        'account is a service account''s key', 'a key with nothing after the type');
    PERFORM pg_temp.open_refused(v_a, v_c, to_jsonb('not a key'::text), 'membership:invalid',
        'account is a service account''s key', 'a malformed key');
    PERFORM pg_temp.open_refused(v_a, v_c, to_jsonb(42), 'membership:invalid',
        'account is a service account''s key', 'a number');

    -- The company.
    PERFORM pg_temp.open_refused(v_a, util.generate_ulid(), to_jsonb('svc:x'::text), 'membership:not_found',
        'no such company', 'no such company');
    PERFORM pg_temp.open_refused(v_a, NULL, to_jsonb('svc:x'::text), 'membership:not_found',
        'no such company', 'no company named');
    v_dead := pg_temp.customer('Suspended Co');
    UPDATE rolebyte.tenant SET status = 'suspended' WHERE id = v_dead;
    PERFORM pg_temp.open_refused(v_a, v_dead, to_jsonb('svc:x'::text), 'membership:not_found',
        'no such company', 'a company that is not active');

    -- The account belongs to a product.
    INSERT INTO rolebyte.product (key, display_name, registered_by) VALUES ('probe-pack', 'Probe pack', 'fx');
    INSERT INTO rolebyte.product_account (product_key, subject_key, display_name)
    VALUES ('probe-pack', v_prod, 'A product''s account');
    PERFORM pg_temp.open_refused(v_a, v_c, to_jsonb(v_prod), 'membership:conflict',
        'this account already belongs to a product', 'a product''s account');

    -- Somebody of the company has signed in: an active person only. A person who is only invited,
    -- or who was revoked, does not stop it; a service account of a product does not either.
    v_p := pg_temp.member(v_c, 'Active person', 'active');
    PERFORM pg_temp.open_refused(v_a, v_c, to_jsonb('svc:x'::text), 'membership:conflict',
        'somebody of this company has signed in', 'an active person');
    PERFORM pg_temp.open_refused(v_a, v_dep, to_jsonb('svc:x'::text), 'membership:conflict',
        'somebody of this company has signed in', 'the deployment''s own company');

    v_other := pg_temp.customer('Invited Co');
    PERFORM pg_temp.member(v_other, 'Only invited', 'invited');
    PERFORM pg_temp.opened(v_a, v_other, 'svc:x1', 'a company with only an invited person');
    PERFORM pg_temp.closed(v_a, v_other, 'close it');

    v_other := pg_temp.customer('Revoked Co');
    PERFORM pg_temp.member(v_other, 'Only revoked', 'revoked');
    PERFORM pg_temp.opened(v_a, v_other, 'svc:x2', 'a company with only a revoked person');
    PERFORM pg_temp.closed(v_a, v_other, 'close it');

    v_other := pg_temp.customer('Product Account Co');
    PERFORM pg_temp.svc_member(v_other, 'svc:of-another-product', 'active');
    PERFORM pg_temp.opened(v_a, v_other, 'svc:x3', 'a company with an active service account and no active person');
    PERFORM pg_temp.closed(v_a, v_other, 'close it');

    -- The account is a standing member of the company, active or not: the window never takes over a standing row.
    v_other := pg_temp.customer('Standing Co');
    PERFORM pg_temp.svc_member(v_other, 'svc:standing', 'active');
    PERFORM pg_temp.open_refused(v_a, v_other, to_jsonb('svc:standing'::text), 'membership:conflict',
        'this account is already a member of the company', 'a standing member');
    UPDATE rolebyte.user_account SET status = 'revoked' WHERE tenant_id = v_other AND subject_key = 'svc:standing';
    PERFORM pg_temp.open_refused(v_a, v_other, to_jsonb('svc:standing'::text), 'membership:conflict',
        'this account is already a member of the company', 'a standing member who was revoked');
    PERFORM pg_temp.must((pg_temp.row_of(v_other, 'svc:standing')).setup_until IS NULL, 'the standing row is untouched');

    -- A window already open: any account, in the same company only.
    v_other := pg_temp.customer('Open Co');
    PERFORM pg_temp.entitle(v_other, 'alpha', '');
    PERFORM pg_temp.opened(v_a, v_other, 'svc:first', 'open the first window');
    PERFORM pg_temp.open_refused(v_a, v_other, to_jsonb('svc:second'::text), 'membership:conflict',
        'the company is already being set up', 'another account while a window is open');
    PERFORM pg_temp.open_refused(v_a, v_other, to_jsonb('svc:first'::text), 'membership:conflict',
        'the company is already being set up', 'the same account while its window is open');
    v_other := pg_temp.customer('Elsewhere Co');
    PERFORM pg_temp.opened(v_a, v_other, 'svc:elsewhere', 'a window in another company is not in the way');
    RAISE NOTICE 't: refusals';
END $$;

-- e. A window ends, and opens again: its time running out, a close, and a person becoming active.
DO $$
DECLARE
    v_dep text;
    v_a   text;
    v_a2  text;
    v_c   text;
    v_d   text;
    v     jsonb;
    v_row rolebyte.user_account;
    v_end timestamptz;
    v_print text;
BEGIN
    TRUNCATE rolebyte.tenant CASCADE;
    v_dep := util.generate_ulid();
    INSERT INTO rolebyte.tenant (id, name) VALUES (v_dep, 'Deployment Co');
    PERFORM pg_temp.ok('deployment_company_set', jsonb_build_object('actor', 'fx', 'tenantId', v_dep), 'mark');
    v_a := pg_temp.admin(v_dep);
    v_a2 := pg_temp.admin(v_dep);
    v_c := pg_temp.customer('Window Co');
    v_d := pg_temp.customer('Other Co');
    PERFORM pg_temp.entitle(v_c, 'alpha', '');
    PERFORM pg_temp.entitle(v_d, 'alpha', '');

    PERFORM pg_temp.opened(v_a, v_c, 'svc:one', 'open');
    PERFORM pg_temp.must(pg_temp.membership('svc:one', v_d) IS NULL, 'the same account in another company: no membership');

    -- The second of the edge: one second in the past is closed, one second in the future is open.
    UPDATE rolebyte.user_account SET setup_until = now() - interval '1 second'
     WHERE tenant_id = v_c AND subject_key = 'svc:one';
    PERFORM pg_temp.must(pg_temp.membership('svc:one', v_c) IS NULL, 'a second after the end: no membership');
    PERFORM pg_temp.must(NOT rolebyte.setup_window_open((pg_temp.row_of(v_c, 'svc:one')).id), 'the window is not open');
    UPDATE rolebyte.user_account SET setup_until = now() + interval '1 second'
     WHERE tenant_id = v_c AND subject_key = 'svc:one';
    PERFORM pg_temp.must(pg_temp.membership('svc:one', v_c) IS NOT NULL, 'a second before the end: a membership');

    -- A window that ran out opens again, for another account and for the same one; the row stays active
    -- until it is closed, and is a row of a setup account for ever.
    UPDATE rolebyte.user_account SET setup_until = now() - interval '1 second'
     WHERE tenant_id = v_c AND subject_key = 'svc:one';
    v := pg_temp.opened(v_a, v_c, 'svc:two', 'open after the first ran out');
    PERFORM pg_temp.must((pg_temp.row_of(v_c, 'svc:one')).status = 'active'
                         AND NOT rolebyte.setup_window_open((pg_temp.row_of(v_c, 'svc:one')).id),
        'the row of the window that ran out is still active, and not a member');
    PERFORM pg_temp.must(pg_temp.membership('svc:one', v_c) IS NULL, 'it is not answered');
    PERFORM pg_temp.must(pg_temp.membership('svc:two', v_c) IS NOT NULL, 'the new one is');
    PERFORM pg_temp.must(pg_temp.lines('setupOpened', v_c) = 2, 'two lines of opening');

    -- Closing: the open window ends, once; the row of the one that ran out is made revoked as well.
    v_end := (pg_temp.row_of(v_c, 'svc:two')).setup_until;
    PERFORM pg_temp.must(pg_temp.closed(v_a2, v_c, 'close by another administrator') IS TRUE,
        'a window open is closed by a different administrator than the one who opened it');
    PERFORM pg_temp.must(pg_temp.lines('setupClosed', v_c) = 2, 'one line of closing for each row ended');
    PERFORM pg_temp.must((SELECT payload FROM rolebyte.event
                           WHERE kind = 'setupClosed' AND tenant_id = v_c AND user_id = (pg_temp.row_of(v_c, 'svc:two')).id)
                         = '{"subjectKey": "svc:two"}'::jsonb,
        'the line of the account that was open carries exactly its key, and its row');
    PERFORM pg_temp.must((SELECT payload FROM rolebyte.event
                           WHERE kind = 'setupClosed' AND tenant_id = v_c AND user_id = (pg_temp.row_of(v_c, 'svc:one')).id)
                         = '{"subjectKey": "svc:one"}'::jsonb,
        'and the line of the one that had run out');
    PERFORM pg_temp.must((SELECT count(*) FROM rolebyte.event WHERE kind = 'setupClosed' AND tenant_id = v_c
                             AND actor = v_a2) = 2,
        'the lines are the one who closed it');
    PERFORM pg_temp.must((pg_temp.row_of(v_c, 'svc:two')).status = 'revoked'
                         AND (pg_temp.row_of(v_c, 'svc:two')).setup_until = v_end,
        'the row is revoked and keeps its end');
    PERFORM pg_temp.must((pg_temp.row_of(v_c, 'svc:one')).status = 'revoked', 'the one that ran out is revoked too');
    PERFORM pg_temp.must(pg_temp.membership('svc:two', v_c) IS NULL, 'after the close: no membership');

    -- Closing again changes nothing and writes nothing.
    v_print := pg_temp.fingerprint();
    PERFORM pg_temp.must(pg_temp.closed(v_a, v_c, 'close again') IS FALSE, 'closing again: changed false');
    PERFORM pg_temp.must(pg_temp.fingerprint() IS NOT DISTINCT FROM v_print, 'and nothing is written');
    PERFORM pg_temp.must(pg_temp.lines('setupClosed', v_c) = 2, 'no new line');

    -- A window that ran out and was never closed: the close ends its row, with a line, and says it changed.
    PERFORM pg_temp.opened(v_a, v_c, 'svc:three', 'open after a close');
    UPDATE rolebyte.user_account SET setup_until = now() - interval '1 second'
     WHERE tenant_id = v_c AND subject_key = 'svc:three';
    PERFORM pg_temp.must(pg_temp.closed(v_a, v_c, 'close an expired window') IS TRUE,
        'a window that ran out: changed true');
    PERFORM pg_temp.must((pg_temp.row_of(v_c, 'svc:three')).status = 'revoked', 'its row is revoked');
    PERFORM pg_temp.must(pg_temp.lines('setupClosed', v_c) = 3, 'and it has a line');
    PERFORM pg_temp.must(pg_temp.closed(v_a, v_c, 'close once more') IS FALSE, 'a second close ends nothing');
    PERFORM pg_temp.must(pg_temp.lines('setupClosed', v_c) = 3, 'and writes no line');

    -- Reopened after a close, the same account: its row is made active again with a new end.
    UPDATE rolebyte.user_account SET setup_until = now() - interval '1 hour'
     WHERE tenant_id = v_c AND subject_key = 'svc:two';
    v := pg_temp.opened(v_a, v_c, 'svc:two', 'reopen the account that was closed');
    v_row := pg_temp.row_of(v_c, 'svc:two');
    PERFORM pg_temp.must(v_row.status = 'active' AND v_row.setup_until = (v->>'endsAt')::timestamptz
                         AND v_row.setup_until > now(), 'the same row is active again with a new end');
    PERFORM pg_temp.must((SELECT count(*) FROM rolebyte.user_account WHERE tenant_id = v_c AND subject_key = 'svc:two') = 1,
        'no second row');
    PERFORM pg_temp.must(pg_temp.membership('svc:two', v_c) IS NOT NULL, 'it is a member again');

    -- A person of the company becomes active (by claiming an invitation) while the window is open: no
    -- membership for the account, no opening, and the row is ended at that moment, with its line.
    PERFORM pg_temp.member(v_c, 'First person', 'active');
    PERFORM pg_temp.must(pg_temp.membership('svc:two', v_c) IS NULL,
        'a person became active: the account is no longer a member');
    PERFORM pg_temp.must(NOT rolebyte.setup_window_open((pg_temp.row_of(v_c, 'svc:two')).id), 'the window is not open');
    PERFORM pg_temp.must((pg_temp.row_of(v_c, 'svc:two')).status = 'revoked', 'its row is revoked at once');
    PERFORM pg_temp.must(pg_temp.lines('setupClosed', v_c) = 4, 'and the person''s arrival wrote its line');
    PERFORM pg_temp.must((SELECT user_id FROM rolebyte.event WHERE kind = 'setupClosed' AND tenant_id = v_c
                           ORDER BY at DESC, id DESC LIMIT 1) = (pg_temp.row_of(v_c, 'svc:two')).id,
        'the line is the row''s');
    PERFORM pg_temp.open_refused(v_a, v_c, to_jsonb('svc:four'::text), 'membership:conflict',
        'somebody of this company has signed in', 'an opening after a person signed in');
    PERFORM pg_temp.must(pg_temp.closed(v_a, v_c, 'close after a person signed in') IS FALSE,
        'nothing is left to close: changed false');
    PERFORM pg_temp.must(pg_temp.lines('setupClosed', v_c) = 4, 'no new line');

    RAISE NOTICE 't: closing and opening again';
END $$;

-- e2. A person becoming active ends the window for good, by every way a person becomes active.
DO $$
DECLARE
    v_dep  text;
    v_a    text;
    v_c    text;
    v_c2   text;
    v_c3   text;
    v_c4   text;
    v_p    text;
    v_iss  text := 'https://issuer.example/' || util.generate_ulid();
    v_q    text := pg_temp.person();
    v_row  text;
    v      jsonb;
BEGIN
    TRUNCATE rolebyte.tenant CASCADE;
    v_dep := util.generate_ulid();
    INSERT INTO rolebyte.tenant (id, name) VALUES (v_dep, 'Deployment Co');
    PERFORM pg_temp.ok('deployment_company_set', jsonb_build_object('actor', 'fx', 'tenantId', v_dep), 'mark');
    v_a := pg_temp.admin(v_dep);
    v_c := pg_temp.customer('Arrival Co');
    PERFORM pg_temp.entitle(v_c, 'alpha', '');

    -- By claiming an invitation: the person is revoked later, the window does not come back.
    v_p := pg_temp.member(v_c, 'Invited first', 'invited');
    PERFORM pg_temp.opened(v_a, v_c, 'svc:arr-one', 'open while the person is only invited');
    v_row := (pg_temp.row_of(v_c, 'svc:arr-one')).id;
    PERFORM pg_temp.ok('claim_attach', jsonb_build_object('actor', 'fx', 'subjectKey', v_p), 'the person claims');
    PERFORM pg_temp.must((pg_temp.row_of(v_c, 'svc:arr-one')).status = 'revoked', 'claiming ends the row');
    PERFORM pg_temp.must((SELECT count(*) FROM rolebyte.event WHERE kind = 'setupClosed' AND user_id = v_row
                             AND payload = '{"subjectKey": "svc:arr-one"}'::jsonb AND actor = 'fx') = 1,
        'with its line, as the actor of the claim');
    UPDATE rolebyte.user_account SET status = 'revoked' WHERE tenant_id = v_c AND subject_key = v_p;
    PERFORM pg_temp.must(pg_temp.membership('svc:arr-one', v_c) IS NULL,
        'the person is revoked later: the account is still not a member');
    PERFORM pg_temp.must(NOT rolebyte.setup_window_open(v_row), 'the window did not come back');
    -- A company a person has signed in to is never opened again, though that person was removed:
    -- refused, with nothing written.
    PERFORM pg_temp.open_refused(v_a, v_c, to_jsonb('svc:arr-two'::text), 'membership:conflict',
        'somebody of this company has signed in', 'an opening where the only person who signed in was removed');
    -- A row left active with time to spare, as a race would leave it, is not answered either.
    UPDATE rolebyte.user_account SET status = 'active', setup_until = now() + interval '5 minutes'
     WHERE id = v_row;
    PERFORM pg_temp.must(pg_temp.membership('svc:arr-one', v_c) IS NULL,
        'a row left active in an entered company is not answered');
    PERFORM pg_temp.must(NOT rolebyte.setup_window_open(v_row), 'and its window is not open');
    PERFORM pg_temp.must(pg_temp.closed(v_a, v_c, 'close the left-over row') IS TRUE, 'a close still ends it');

    -- By the directory admitting a person who arrives for the first time (a new row).
    v_c2 := pg_temp.customer('Directory Co');
    PERFORM pg_temp.entitle(v_c2, 'alpha', '');
    PERFORM pg_temp.ok('directory_attach', jsonb_build_object('actor', 'fx', 'tenantId', v_c2, 'issuer', v_iss),
        'attach a directory');
    PERFORM pg_temp.opened(v_a, v_c2, 'svc:arr-three', 'open');
    v_row := (pg_temp.row_of(v_c2, 'svc:arr-three')).id;
    v := pg_temp.ok('directory_admit', jsonb_build_object('actor', 'fx', 'subjectKey', v_q, 'issuer', v_iss,
        'displayName', 'Arriving person'), 'admit a new person');
    PERFORM pg_temp.must(v->>'outcome' = 'admitted', 'the person is admitted');
    PERFORM pg_temp.must((pg_temp.row_of(v_c2, 'svc:arr-three')).status = 'revoked', 'the admission ends the row');
    PERFORM pg_temp.must((SELECT count(*) FROM rolebyte.event WHERE kind = 'setupClosed' AND user_id = v_row) = 1,
        'with its line');
    PERFORM pg_temp.must(pg_temp.membership('svc:arr-three', v_c2) IS NULL, 'the account is not a member');
    UPDATE rolebyte.user_account SET status = 'revoked' WHERE tenant_id = v_c2 AND subject_key = v_q;
    PERFORM pg_temp.open_refused(v_a, v_c2, to_jsonb('svc:arr-five'::text), 'membership:conflict',
        'somebody of this company has signed in', 'an opening after the directory''s person was removed');

    -- By the directory admitting a person who was invited (an existing row).
    v_c3 := pg_temp.customer('Directory Two Co');
    PERFORM pg_temp.entitle(v_c3, 'alpha', '');
    v_iss := 'https://issuer.example/' || util.generate_ulid();
    PERFORM pg_temp.ok('directory_attach', jsonb_build_object('actor', 'fx', 'tenantId', v_c3, 'issuer', v_iss),
        'attach a directory');
    v_p := pg_temp.member(v_c3, 'Invited second', 'invited');
    PERFORM pg_temp.opened(v_a, v_c3, 'svc:arr-four', 'open while the person is only invited');
    v_row := (pg_temp.row_of(v_c3, 'svc:arr-four')).id;
    v := pg_temp.ok('directory_admit', jsonb_build_object('actor', 'fx', 'subjectKey', v_p, 'issuer', v_iss,
        'displayName', 'Invited second'), 'admit an invited person');
    PERFORM pg_temp.must(v->>'outcome' = 'admitted', 'the invited person is admitted');
    PERFORM pg_temp.must((pg_temp.row_of(v_c3, 'svc:arr-four')).status = 'revoked', 'that admission ends the row too');
    PERFORM pg_temp.must((SELECT count(*) FROM rolebyte.event WHERE kind = 'setupClosed' AND user_id = v_row) = 1,
        'with its line');
    PERFORM pg_temp.must(pg_temp.closed(v_a, v_c3, 'close') IS FALSE, 'nothing is left for a close to end');

    -- A company with only invited people, and one with only a removed person who never signed in, still open.
    v_c4 := pg_temp.customer('Never Entered Co');
    PERFORM pg_temp.member(v_c4, 'Only invited', 'invited');
    PERFORM pg_temp.member(v_c4, 'Removed, never signed in', 'revoked');
    PERFORM pg_temp.opened(v_a, v_c4, 'svc:arr-six', 'a company nobody signed in to');
    PERFORM pg_temp.must(pg_temp.membership('svc:arr-six', v_c4) IS NOT NULL, 'and is answered');
    PERFORM pg_temp.closed(v_a, v_c4, 'close');

    -- Every row was ended by a person's arrival: nothing is left for a close to end.
    PERFORM pg_temp.must(pg_temp.closed(v_a, v_c, 'close') IS FALSE, 'nothing is left to close');

    -- The close's own refusals.
    PERFORM pg_temp.refused('company_setup_close', jsonb_build_object('actor', v_a, 'mode', 'saas',
        'tenantId', util.generate_ulid()), 'membership:not_found', 'no such company', 'close in no such company');
    PERFORM pg_temp.refused('company_setup_close', jsonb_build_object('actor', v_a, 'mode', 'saas'),
        'membership:invalid', 'tenantId is required', 'close with no company');
    PERFORM pg_temp.refused('company_setup_close', jsonb_build_object('actor', v_a, 'mode', 'local', 'tenantId', v_c),
        'membership:forbidden', 'not a deployment administrator', 'close in the local mode');
    PERFORM pg_temp.refused('company_setup_close', jsonb_build_object('actor', pg_temp.member(v_dep, 'Plain', 'active'),
        'mode', 'saas', 'tenantId', v_c), 'membership:forbidden', 'not a deployment administrator',
        'close by a caller who is not an administrator');
    RAISE NOTICE 't: closing and opening again';
END $$;

-- f. Nothing is given beyond the permissions, whatever the row holds, and the door's reads do not move.
DO $$
DECLARE
    v_dep    text;
    v_a      text;
    v_c      text;
    v_row    rolebyte.user_account;
    v_before text;
    v_during text;
    v_m      jsonb;
BEGIN
    TRUNCATE rolebyte.tenant CASCADE;
    v_dep := util.generate_ulid();
    INSERT INTO rolebyte.tenant (id, name) VALUES (v_dep, 'Deployment Co');
    PERFORM pg_temp.ok('deployment_company_set', jsonb_build_object('actor', 'fx', 'tenantId', v_dep), 'mark');
    v_a := pg_temp.admin(v_dep);
    v_c := pg_temp.customer('Reads Co');
    PERFORM pg_temp.entitle(v_c, 'alpha', '');

    v_before := pg_temp.reads(v_a, v_c);
    PERFORM pg_temp.opened(v_a, v_c, 'svc:setup-reads', 'open');
    v_during := pg_temp.reads(v_a, v_c);
    PERFORM pg_temp.must(v_during IS NOT DISTINCT FROM v_before,
        'the door''s reads of the company and its administrators are the same during a window');
    PERFORM pg_temp.must(pg_temp.rb('company_get', jsonb_build_object('actor', v_a, 'mode', 'saas', 'tenantId', v_c))
                         #>> '{data,company,administrators}' = '0', 'no administrator is counted');
    PERFORM pg_temp.closed(v_a, v_c, 'close');
    PERFORM pg_temp.must(pg_temp.reads(v_a, v_c) IS NOT DISTINCT FROM v_before,
        'and after it');

    -- Whatever a setup account's row is given, the register answers its permissions and nothing else:
    -- a level, and the level of an administrator, are never read for it.
    PERFORM pg_temp.opened(v_a, v_c, 'svc:setup-levels', 'open again');
    v_row := pg_temp.row_of(v_c, 'svc:setup-levels');
    INSERT INTO rolebyte.assignment (id, user_id, role_definition_id)
    SELECT util.generate_ulid(), v_row.id, rd.id FROM rolebyte.role_definition rd
     WHERE rd.service_key = 'alpha' AND rd.role_group = 'api' AND rd.role_level = 'read';
    INSERT INTO rolebyte.assignment (id, user_id, role_definition_id)
    SELECT util.generate_ulid(), v_row.id, rd.id FROM rolebyte.role_definition rd
     WHERE rd.service_key = 'alpha' AND rd.role_group = 'membership' AND rd.role_level = 'admin';
    v_m := pg_temp.membership('svc:setup-levels', v_c);
    -- (the earlier block retired one of alpha's permissions, and the retirement stands)
    PERFORM pg_temp.must(pg_temp.texts(v_m->'scopes') = 'alpha/setup:edit',
        'a level stored on the row is not answered: ' || (v_m->'scopes')::text);
    PERFORM pg_temp.must(NOT (v_m ? 'highScopes'), 'and no scope for a strong sign-in');

    -- An existing member's answer is the same as ever: a person and a standing service account.
    PERFORM pg_temp.closed(v_a, v_c, 'close');
    PERFORM pg_temp.svc_member(v_c, 'svc:standing', 'active');
    PERFORM pg_temp.must(pg_temp.membership('svc:standing', v_c) = jsonb_build_object(
            'tenantId', v_c, 'userId', (pg_temp.row_of(v_c, 'svc:standing')).id, 'displayName', 'svc:standing',
            'tenantName', (SELECT t.name FROM rolebyte.tenant t WHERE t.id = v_c),
            'scopes', '[]'::jsonb),
        'a standing service account is answered as before');
    RAISE NOTICE 't: nothing beyond the permissions, the reads';
END $$;

-- h. A setup account's row is never an ordinary member: nothing is given to it, during its window or after
-- it, and it is never an administrator, whatever is forced onto it.
DO $$
DECLARE
    v_dep   text;
    v_a     text;
    v_c     text;
    v_real  text;
    v_row   text;
    v_role  text;
    v_pos   text;
    v_type  text;
    v_count text;
    v_when  text;
BEGIN
    TRUNCATE rolebyte.tenant CASCADE;
    v_dep := util.generate_ulid();
    INSERT INTO rolebyte.tenant (id, name) VALUES (v_dep, 'Deployment Co');
    PERFORM pg_temp.ok('deployment_company_set', jsonb_build_object('actor', 'fx', 'tenantId', v_dep), 'mark');
    v_a := pg_temp.admin(v_dep);
    PERFORM pg_temp.ok('service_register', '{"actor":"fx","service":"authority","displayName":"Authority"}',
        'register the chart''s service');

    v_c := pg_temp.customer('Grants Co');
    PERFORM pg_temp.entitle(v_c, 'alpha', '');
    PERFORM pg_temp.entitle(v_c, 'authority', '');
    -- The company's one real administrator: invited, not yet signed in.
    v_real := pg_temp.person();
    PERFORM pg_temp.ok('administrator_set', jsonb_build_object('actor', 'fx', 'tenantId', v_c,
        'subjectKey', v_real, 'displayName', 'Real administrator'), 'the real administrator');
    v_role := pg_temp.ok('tenant_role_define', jsonb_build_object('actor', 'fx', 'tenantId', v_c,
        'name', 'Site lead'), 'a company role')->>'id';
    v_pos := pg_temp.ok('chart_position_add', jsonb_build_object('actor', 'fx', 'tenantId', v_c,
        'name', 'Director'), 'a position')->>'id';
    v_type := (SELECT default_user_type_id FROM rolebyte.tenant WHERE id = v_c);

    PERFORM pg_temp.opened(v_a, v_c, 'svc:grants-one', 'open');
    v_row := (pg_temp.row_of(v_c, 'svc:grants-one')).id;
    v_count := pg_temp.rb('company_get', jsonb_build_object('actor', v_a, 'mode', 'saas', 'tenantId', v_c))
               #>> '{data,company,administrators}';
    PERFORM pg_temp.must(v_count = '1', 'the company has its one real administrator: ' || v_count);

    FOREACH v_when IN ARRAY ARRAY['during the window', 'after the window'] LOOP
        PERFORM pg_temp.refused('role_grant', jsonb_build_object('actor', 'fx', 'tenantId', v_c, 'userId', v_row,
            'service', 'alpha', 'group', 'api', 'level', 'read'), 'membership:not_found', 'user does not exist',
            'a level given to a setup account ' || v_when);
        PERFORM pg_temp.refused('tenant_role_grant', jsonb_build_object('actor', 'fx', 'tenantId', v_c,
            'userId', v_row, 'roleId', v_role), 'membership:not_found', 'user does not exist',
            'a company role given to a setup account ' || v_when);
        PERFORM pg_temp.refused('chart_person_place', jsonb_build_object('actor', 'fx', 'tenantId', v_c,
            'userId', v_row, 'positionId', v_pos), 'membership:invalid', 'only a person sits in the chart',
            'a place in the chart given to a setup account ' || v_when);
        PERFORM pg_temp.refused('user_type_assign', jsonb_build_object('actor', 'fx', 'tenantId', v_c,
            'userId', v_row, 'userTypeId', v_type), 'membership:not_found', 'no such member',
            'a user type given to a setup account ' || v_when);
        PERFORM pg_temp.refused('administrator_set', jsonb_build_object('actor', 'fx', 'tenantId', v_c,
            'subjectKey', 'svc:grants-one'), 'membership:conflict', 'cannot be made its administrator',
            'the administrator''s level given to a setup account ' || v_when);
        IF v_when = 'during the window' THEN
            PERFORM pg_temp.closed(v_a, v_c, 'close');
        END IF;
    END LOOP;

    -- Forced onto the row, the administrator's level makes no administrator of it.
    PERFORM pg_temp.opened(v_a, v_c, 'svc:grants-two', 'open again');
    v_row := (pg_temp.row_of(v_c, 'svc:grants-two')).id;
    INSERT INTO rolebyte.assignment (id, user_id, role_definition_id)
    VALUES (util.generate_ulid(), v_row, rolebyte.administrator_rung('fx'));
    PERFORM pg_temp.must(NOT rolebyte.is_administrator(v_row), 'a setup row is never an administrator');
    PERFORM pg_temp.must((SELECT rolebyte.is_administrator(id) FROM rolebyte.user_account
                           WHERE tenant_id = v_c AND subject_key = v_real),
        'the real administrator still is one');
    PERFORM pg_temp.must(pg_temp.rb('company_get', jsonb_build_object('actor', v_a, 'mode', 'saas', 'tenantId', v_c))
                         #>> '{data,company,administrators}' = v_count,
        'the door''s count of administrators does not move');
    PERFORM pg_temp.must(jsonb_array_length(pg_temp.rb('company_administrators', jsonb_build_object('actor', v_a,
        'mode', 'saas', 'tenantId', v_c))->'data'->'administrators') = 1, 'and its list holds the real one only');
    -- The last real administrator is still the last one.
    PERFORM pg_temp.refused('administrator_unset', jsonb_build_object('actor', 'fx', 'tenantId', v_c,
        'userId', (SELECT id FROM rolebyte.user_account WHERE tenant_id = v_c AND subject_key = v_real)),
        'membership:conflict', 'last administrator', 'unsetting the last real administrator');
    PERFORM pg_temp.refused('user_revoke', jsonb_build_object('actor', 'fx', 'tenantId', v_c,
        'userId', (SELECT id FROM rolebyte.user_account WHERE tenant_id = v_c AND subject_key = v_real)),
        'membership:conflict', 'last administrator', 'revoking the last real administrator');
    RAISE NOTICE 't: nothing is given to a setup account';
END $$;

-- i. An entitlement taken away through the door, while a window is open, takes its permissions away at once.
DO $$
DECLARE
    v_dep  text;
    v_a    text;
    v_c    text;
    v_list jsonb;
    v      jsonb;
BEGIN
    TRUNCATE rolebyte.tenant CASCADE;
    v_dep := util.generate_ulid();
    INSERT INTO rolebyte.tenant (id, name) VALUES (v_dep, 'Deployment Co');
    PERFORM pg_temp.ok('deployment_company_set', jsonb_build_object('actor', 'fx', 'tenantId', v_dep), 'mark');
    v_a := pg_temp.admin(v_dep);
    v_list := jsonb_build_array(jsonb_build_object('key', 'door-pack', 'displayName', 'Door pack',
        'gives', jsonb_build_array(jsonb_build_object('service', 'beta', 'feature', '')),
        'accounts', '[]'::jsonb));
    PERFORM pg_temp.ok('products_register', jsonb_build_object('actor', 'fx', 'products', v_list), 'the catalog');
    v_c := pg_temp.customer('Door Co');
    PERFORM pg_temp.ok('company_has_set', jsonb_build_object('actor', v_a, 'mode', 'saas', 'tenantId', v_c,
        'product', 'door-pack', 'has', true), 'give the product');

    PERFORM pg_temp.opened(v_a, v_c, 'svc:door-one', 'open');
    PERFORM pg_temp.must(pg_temp.texts(pg_temp.membership('svc:door-one', v_c)->'scopes') = 'beta/cfg/deep:edit,beta/cfg:edit,beta/other:edit',
        'the product''s service gives its configuration permissions: '
        || (pg_temp.membership('svc:door-one', v_c)->'scopes')::text);

    PERFORM pg_temp.ok('company_has_set', jsonb_build_object('actor', v_a, 'mode', 'saas', 'tenantId', v_c,
        'product', 'door-pack', 'has', false), 'take the product away');
    PERFORM pg_temp.must(pg_temp.membership('svc:door-one', v_c)->'scopes' = '[]'::jsonb,
        'the permissions are gone at once');
    PERFORM pg_temp.must(pg_temp.membership('svc:door-one', v_c) IS NOT NULL, 'the window itself is still open');
    RAISE NOTICE 't: a product taken away through the door';
END $$;

-- g. A list of products may not name, as a product's account, a key a company's setup window uses.
DO $$
DECLARE
    v_dep  text;
    v_a    text;
    v_c    text;
    v_list jsonb;
    v      jsonb;
BEGIN
    TRUNCATE rolebyte.tenant CASCADE;
    v_dep := util.generate_ulid();
    INSERT INTO rolebyte.tenant (id, name) VALUES (v_dep, 'Deployment Co');
    PERFORM pg_temp.ok('deployment_company_set', jsonb_build_object('actor', 'fx', 'tenantId', v_dep), 'mark');
    v_a := pg_temp.admin(v_dep);
    v_c := pg_temp.customer('Listing Co');
    PERFORM pg_temp.opened(v_a, v_c, 'svc:used-for-setup', 'open a window');
    PERFORM pg_temp.closed(v_a, v_c, 'close it');

    -- The row is a setup row for ever, closed or not: the account may not be listed.
    v_list := jsonb_build_array(jsonb_build_object('key', 'listed-pack', 'displayName', 'Listed pack',
        'gives', jsonb_build_array(jsonb_build_object('service', 'alpha', 'feature', '')),
        'accounts', jsonb_build_array(jsonb_build_object('subjectKey', 'svc:used-for-setup',
                                                         'displayName', 'Setup', 'roles', '[]'::jsonb))));
    PERFORM pg_temp.refused('products_register', jsonb_build_object('actor', 'fx', 'products', v_list),
        'membership:invalid', 'product 1 lists an account that is used for setting companies up',
        'a list naming an account a setup window used');

    -- A list without that account registers.
    v_list := jsonb_build_array(jsonb_build_object('key', 'listed-pack', 'displayName', 'Listed pack',
        'gives', jsonb_build_array(jsonb_build_object('service', 'alpha', 'feature', '')),
        'accounts', jsonb_build_array(jsonb_build_object('subjectKey', 'svc:another',
                                                         'displayName', 'Another', 'roles', '[]'::jsonb))));
    v := pg_temp.ok('products_register', jsonb_build_object('actor', 'fx', 'products', v_list), 'a list without it');
    PERFORM pg_temp.must(EXISTS (SELECT 1 FROM rolebyte.product_account WHERE subject_key = 'svc:another'),
        'the account of the list is registered');
    RAISE NOTICE 't: a product list and a setup account';
END $$;

DO $$
BEGIN
    RAISE NOTICE 'PASS unit.rolebyte_setup_window';
END $$;

ROLLBACK;

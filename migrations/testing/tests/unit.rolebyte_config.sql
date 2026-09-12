-- Unit test: the rolebyte configuration transport.
-- The vocabulary travels additively — a document defines what is missing and
-- never removes what exists — and the tenant display name follows the
-- document. The get→apply round trip reports all-unchanged.
--   psql -v ON_ERROR_STOP=1 -f migrations/testing/tests/unit.rolebyte_config.sql

DO $$
DECLARE
    v jsonb;
    v_tenant text;
    v_section jsonb;
    v_defs_before int;
BEGIN
    CALL rolebyte.tenant_create('{"actor":"config-test","name":"Config demo"}'::jsonb, v);
    IF v->>'result' IS DISTINCT FROM 'success' THEN
        RAISE EXCEPTION 'tenant_create failed: %', v;
    END IF;
    v_tenant := v->'data'->>'id';

    -- 1. First apply: one service with two roles + a renamed tenant.
    CALL rolebyte.config_apply(jsonb_build_object(
        'tenantId', v_tenant, 'actor', 'config-test',
        'section', '{
          "tenant": {"displayName": "Config demo, renamed"},
          "services": [
            {"key":"cfgdemo","displayName":"Config demo service",
             "roles":[{"group":"demo","level":"read","description":""},
                      {"group":"demo","level":"admin","description":"the admin"}]}
          ]}'::jsonb), v);
    IF v->>'result' IS DISTINCT FROM 'success' THEN
        RAISE EXCEPTION 'first apply failed: %', v;
    END IF;
    IF v->'data'->'services'->0->>'status' IS DISTINCT FROM 'added'
       OR v->'data'->'roles'->0->>'status' IS DISTINCT FROM 'added'
       OR v->'data'->'tenant'->>'status' IS DISTINCT FROM 'changed' THEN
        RAISE EXCEPTION 'first apply should add the vocabulary and rename: %', v;
    END IF;
    IF NOT EXISTS (SELECT 1 FROM rolebyte.tenant WHERE id = v_tenant AND name = 'Config demo, renamed') THEN
        RAISE EXCEPTION 'the display name should follow the document';
    END IF;

    -- The rename is history, not just state.
    IF NOT EXISTS (SELECT 1 FROM rolebyte.event
                   WHERE tenant_id = v_tenant AND kind = 'tenantRenamed') THEN
        RAISE EXCEPTION 'a rename must land in the event stream';
    END IF;

    -- 2. The round trip: config_get's own answer re-applies as all-unchanged,
    --    and removes nothing however much the register holds beyond the file.
    SELECT count(*) INTO v_defs_before FROM rolebyte.role_definition;
    CALL rolebyte.config_get(jsonb_build_object('tenantId', v_tenant), v);
    IF v->>'result' IS DISTINCT FROM 'success' THEN
        RAISE EXCEPTION 'config_get failed: %', v;
    END IF;
    v_section := v->'data';
    CALL rolebyte.config_apply(jsonb_build_object(
        'tenantId', v_tenant, 'actor', 'config-test', 'section', v_section), v);
    IF v->>'result' IS DISTINCT FROM 'success' THEN
        RAISE EXCEPTION 'round-trip apply failed: %', v;
    END IF;
    IF EXISTS (SELECT 1 FROM jsonb_array_elements(v->'data'->'services') e WHERE e->>'status' <> 'unchanged')
       OR EXISTS (SELECT 1 FROM jsonb_array_elements(v->'data'->'roles') e WHERE e->>'status' <> 'unchanged')
       OR v->'data'->'tenant'->>'status' IS DISTINCT FROM 'unchanged' THEN
        RAISE EXCEPTION 'round trip should change nothing: %', v;
    END IF;
    IF (SELECT count(*) FROM rolebyte.role_definition) <> v_defs_before THEN
        RAISE EXCEPTION 'an apply must never remove a definition';
    END IF;

    -- 3. A partial document leaves the rest of the vocabulary alone: apply a
    --    single unrelated service, then assert the demo roles still stand.
    CALL rolebyte.config_apply(jsonb_build_object(
        'tenantId', v_tenant, 'actor', 'config-test',
        'section', '{"services":[{"key":"cfgother","displayName":"Another","roles":[]}]}'::jsonb), v);
    IF v->>'result' IS DISTINCT FROM 'success' THEN
        RAISE EXCEPTION 'partial apply failed: %', v;
    END IF;
    IF (SELECT count(*) FROM rolebyte.role_definition d WHERE d.service_key = 'cfgdemo') <> 2 THEN
        RAISE EXCEPTION 'a section absent from the file must stay untouched';
    END IF;

    -- 4. A malformed entry writes nothing (the service that precedes it
    --    included).
    BEGIN
        CALL rolebyte.config_apply(jsonb_build_object(
            'tenantId', v_tenant, 'actor', 'config-test',
            'section', '{"services":[
              {"key":"cfgpoison","displayName":"Should not survive","roles":[]},
              {"displayName":"No key at all","roles":[]}
            ]}'::jsonb), v);
        RAISE EXCEPTION 'a keyless service entry should have been refused';
    EXCEPTION WHEN sqlstate 'P0001' THEN
        IF SQLERRM NOT LIKE '%membership:config_bad_document%' THEN
            RAISE EXCEPTION 'malformed entry raised the wrong code: %', SQLERRM;
        END IF;
    END;
    IF EXISTS (SELECT 1 FROM rolebyte.service WHERE key = 'cfgpoison') THEN
        RAISE EXCEPTION 'a poisoned document must write nothing';
    END IF;

    -- 5. An unknown tenant is refused.
    CALL rolebyte.config_get('{"tenantId":"no-such"}'::jsonb, v);
    IF v->>'code' IS DISTINCT FROM 'membership:not_found' THEN
        RAISE EXCEPTION 'unknown tenant should refuse not_found: %', v;
    END IF;

    RAISE NOTICE 'unit.rolebyte_config: all assertions passed';
END $$;

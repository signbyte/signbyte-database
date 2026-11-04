-- Unit test: the rolebyte configuration section, `rolebyte-config/1`.
-- The section reads with a version derived from its own bytes and never carries
-- the workspace's name or corporate login; a preview reports exactly what an
-- apply would do and writes nothing; an apply names the version its preview
-- answered and is refused without one or once it has moved; an import never
-- writes the deployment's list of services — what the list holds as the file
-- says is unchanged, anything else skipped — and never the workspace's name or
-- login, whatever the file holds; a document with an unreadable entry writes
-- nothing; every import and every export leaves one line in the tenant's
-- history; and the deployment registers the services' permissions through a
-- procedure of its own.
--   psql -v ON_ERROR_STOP=1 -f migrations/testing/tests/unit.rolebyte_config.sql

DO $$
DECLARE
    v          jsonb;
    v_tenant   text;
    v_other    text;
    v_section  jsonb;
    v_doc      jsonb;
    v_pre      jsonb;
    v0         text;
    v1         text;
    v_other0   text;
    v_events   int;
    v_imports  int;
    v_defs     int;
    v_part     text := 'sha256:' || repeat('a', 64);
    v_file     text := 'sha256:' || repeat('b', 64);
    v_line     jsonb;
    v_issuer   text;
BEGIN
    -- Everything below is undone at the end, so the test leaves nothing behind:
    -- it registers a seeded permission, and a later test needs a database where
    -- no service declared a seed.
    BEGIN
    CALL rolebyte.tenant_create('{"actor":"config-test","name":"Config demo"}'::jsonb, v);
    IF v->>'result' IS DISTINCT FROM 'success' THEN
        RAISE EXCEPTION 'tenant_create failed: %', v;
    END IF;
    v_tenant := v->'data'->>'id';
    CALL rolebyte.tenant_create('{"actor":"config-test","name":"Another demo"}'::jsonb, v);
    v_other := v->'data'->>'id';

    -- A service the deployment registered, with a permission a new tenant's
    -- seeded roles hold: the section must carry the seeds, or reading it back
    -- would take them away.
    CALL rolebyte.permissions_register(jsonb_build_object('actor', 'config-test', 'section', '{
      "services":[{"key":"cfgseed","displayName":"Seeded demo","permissions":[
        {"feature":"thing","act":"view","description":"See a thing","class":"ordinary","plane":"object",
         "labels":{"lv":"Redzēt lietu"},"seeds":["worker","manager"]}]}]}'::jsonb), v);
    IF v->>'result' IS DISTINCT FROM 'success' OR v->'data'->'permissions'->0->>'status' IS DISTINCT FROM 'added' THEN
        RAISE EXCEPTION 'the deployment should register a service''s permissions: %', v;
    END IF;

    -- 1. The section: its schema and every service, keys and never identifiers,
    --    the seeds aboard — and never the workspace's name or corporate login.
    CALL rolebyte.config_get(jsonb_build_object('tenantId', v_tenant), v);
    IF v->>'result' IS DISTINCT FROM 'success' THEN
        RAISE EXCEPTION 'config_get failed: %', v;
    END IF;
    v_section := v->'data'->'section';
    v0 := v->'data'->>'version';
    IF v_section->>'schema' IS DISTINCT FROM 'rolebyte-config/1'
       OR jsonb_typeof(v_section->'services') IS DISTINCT FROM 'array' THEN
        RAISE EXCEPTION 'the section should be rolebyte-config/1 with the services: %', v_section;
    END IF;
    IF v_section ? 'tenant' OR v_section::text LIKE '%Config demo%' THEN
        RAISE EXCEPTION 'the section carries the workspace''s name: %', v_section;
    END IF;
    IF v_section::text LIKE '%"id"%' THEN
        RAISE EXCEPTION 'the section carries identifiers: %', v_section;
    END IF;
    IF NOT EXISTS (SELECT 1 FROM jsonb_array_elements(v_section->'services') s,
                                 jsonb_array_elements(s->'permissions') p
                    WHERE s->>'key' = 'cfgseed' AND p->'seeds' = '["manager", "worker"]'::jsonb) THEN
        RAISE EXCEPTION 'the section should carry the seeds of a seeded permission: %', v_section;
    END IF;

    -- 2. The version: the token over exactly these bytes, the same from both
    --    reads, salted with the tenant, never moved by a read.
    IF v0 IS DISTINCT FROM util.config_token('rolebyte-config/1', v_tenant, v_section) THEN
        RAISE EXCEPTION 'the version should be the token over the section answered: % vs %', v0,
            util.config_token('rolebyte-config/1', v_tenant, v_section);
    END IF;
    CALL rolebyte.config_version(jsonb_build_object('tenantId', v_tenant), v);
    IF v->'data'->>'version' IS DISTINCT FROM v0 THEN
        RAISE EXCEPTION 'config_version should answer the token config_get carried: %', v;
    END IF;
    CALL rolebyte.config_version(jsonb_build_object('tenantId', v_other), v);
    v_other0 := v->'data'->>'version';
    IF v_other0 = v0 THEN
        RAISE EXCEPTION 'two tenants share a version';
    END IF;

    -- 3. A preview writes nothing and reports what an apply would do: a service
    --    the deployment's list does not hold is skipped, with its roles and its
    --    permissions, and the workspace's name the file still carries is skipped
    --    too, saying the workspace keeps its own.
    v_doc := jsonb_build_object('schema', 'rolebyte-config/1',
        'tenant', jsonb_build_object('displayName', 'Config demo, renamed'),
        'services', '[{"key":"cfgdemo","displayName":"Config demo service",
            "roles":[{"group":"demo","level":"read","description":""},
                     {"group":"demo","level":"admin","description":"the admin"}],
            "permissions":[{"feature":"thing","act":"edit","description":"Change a thing","class":"ordinary","plane":"object"}]}]'::jsonb);
    SELECT count(*) INTO v_events FROM rolebyte.event;
    CALL rolebyte.config_apply(jsonb_build_object('tenantId', v_tenant, 'actor', 'config-test',
        'section', v_doc, 'dryRun', true), v);
    IF v->>'result' IS DISTINCT FROM 'success' THEN
        RAISE EXCEPTION 'the preview failed: %', v;
    END IF;
    v_pre := v->'data';
    IF (v_pre->>'dryRun')::boolean IS NOT TRUE OR (v_pre->>'applied')::boolean OR (v_pre->>'refused')::boolean
       OR v_pre->>'version' IS DISTINCT FROM v0 OR v_pre->>'schema' IS DISTINCT FROM 'rolebyte-config/1' THEN
        RAISE EXCEPTION 'a preview answers dryRun, not applied, not refused, the current version: %', v_pre;
    END IF;
    IF (SELECT string_agg(e->>'key' || '=' || (e->>'status') || '/' || (e->>'reason'), ',')
          FROM jsonb_array_elements(v_pre->'services') e)
           IS DISTINCT FROM 'cfgdemo=skipped/config_deployment_owned'
       OR (SELECT string_agg(e->>'key' || '=' || (e->>'status'), ',') FROM jsonb_array_elements(v_pre->'roles') e)
           IS DISTINCT FROM 'cfgdemo demo:read=skipped,cfgdemo demo:admin=skipped'
       OR (SELECT string_agg(e->>'key' || '=' || (e->>'status'), ',') FROM jsonb_array_elements(v_pre->'permissions') e)
           IS DISTINCT FROM 'cfgdemo/thing:edit=skipped'
       OR (SELECT string_agg(e->>'key' || '=' || (e->>'status') || '/' || (e->>'reason'), ',')
             FROM jsonb_array_elements(v_pre->'workspace') e)
           IS DISTINCT FROM 'displayName=skipped/config_workspace_owned' THEN
        RAISE EXCEPTION 'the preview should skip each entry the list does not hold, and the name: %', v_pre;
    END IF;
    IF v_pre->'services'->0->>'detail' NOT LIKE '%only whoever runs the deployment adds to it%'
       OR v_pre->'workspace'->0->>'detail' NOT LIKE '%keeps its own name%' THEN
        RAISE EXCEPTION 'a skipped entry says why: %', v_pre;
    END IF;
    IF v_pre ? 'tenant' OR v_pre ? 'directory' THEN
        RAISE EXCEPTION 'the report keeps no single tenant or directory item any more: %', v_pre;
    END IF;
    IF EXISTS (SELECT 1 FROM rolebyte.service WHERE key = 'cfgdemo')
       OR (SELECT name FROM rolebyte.tenant WHERE id = v_tenant) <> 'Config demo'
       OR (SELECT count(*) FROM rolebyte.event) <> v_events THEN
        RAISE EXCEPTION 'a preview wrote something';
    END IF;

    -- 4. An apply naming no version, or a version the section has moved past, is
    --    refused and writes nothing.
    CALL rolebyte.config_apply(jsonb_build_object('tenantId', v_tenant, 'actor', 'config-test', 'section', v_doc), v);
    IF v->>'code' IS DISTINCT FROM 'membership:config_version_required' THEN
        RAISE EXCEPTION 'an apply naming no version should be refused: %', v;
    END IF;
    CALL rolebyte.config_apply(jsonb_build_object('tenantId', v_tenant, 'actor', 'config-test', 'section', v_doc,
        'expectedVersion', v_other0), v);
    IF v->>'code' IS DISTINCT FROM 'membership:config_version_moved' THEN
        RAISE EXCEPTION 'an apply naming another version should be refused: %', v;
    END IF;
    IF EXISTS (SELECT 1 FROM rolebyte.service WHERE key = 'cfgdemo') OR (SELECT count(*) FROM rolebyte.event) <> v_events THEN
        RAISE EXCEPTION 'a refused apply wrote something';
    END IF;

    -- 5. The apply reports what the preview reported, writes neither the list
    --    nor the name, and leaves one line naming the counts, the part and the
    --    document it arrived in. The version stays: nothing it covers moved.
    CALL rolebyte.config_apply(jsonb_build_object('tenantId', v_tenant, 'actor', 'config-test', 'section', v_doc,
        'expectedVersion', v0, 'partHash', v_part, 'documentHash', v_file), v);
    IF v->>'result' IS DISTINCT FROM 'success' OR (v->'data'->>'applied')::boolean IS NOT TRUE
       OR (v->'data'->>'dryRun')::boolean OR (v->'data'->>'refused')::boolean THEN
        RAISE EXCEPTION 'the apply failed: %', v;
    END IF;
    IF (v->'data') - 'dryRun' - 'applied' - 'version' IS DISTINCT FROM v_pre - 'dryRun' - 'applied' - 'version' THEN
        RAISE EXCEPTION 'the apply reported other than its preview: % vs %', v->'data', v_pre;
    END IF;
    v1 := v->'data'->>'version';
    IF v1 IS DISTINCT FROM v0 THEN
        RAISE EXCEPTION 'an import that writes nothing the section carries must not move its version: % %', v0, v1;
    END IF;
    IF (SELECT name FROM rolebyte.tenant WHERE id = v_tenant) <> 'Config demo'
       OR EXISTS (SELECT 1 FROM rolebyte.service WHERE key = 'cfgdemo')
       OR EXISTS (SELECT 1 FROM rolebyte.role_definition WHERE service_key = 'cfgdemo')
       OR EXISTS (SELECT 1 FROM rolebyte.service_permission WHERE service_key = 'cfgdemo') THEN
        RAISE EXCEPTION 'an import wrote the deployment''s list or the workspace''s name';
    END IF;
    IF (SELECT count(*) FROM rolebyte.event) <> v_events + 1 THEN
        RAISE EXCEPTION 'an import writes one line and nothing else';
    END IF;
    SELECT payload INTO v_line FROM rolebyte.event
     WHERE tenant_id = v_tenant AND kind = 'configApplied' ORDER BY at DESC, id DESC LIMIT 1;
    IF v_line->>'partHash' IS DISTINCT FROM v_part OR v_line->>'documentHash' IS DISTINCT FROM v_file
       OR (v_line->'services'->>'skipped')::int IS DISTINCT FROM 1
       OR (v_line->'roles'->>'skipped')::int IS DISTINCT FROM 2
       OR (v_line->'permissions'->>'skipped')::int IS DISTINCT FROM 1
       OR (v_line->'permissions'->>'added')::int IS DISTINCT FROM 0 THEN
        RAISE EXCEPTION 'the import line should carry the counts, the part''s hash and the document''s: %', v_line;
    END IF;
    IF EXISTS (SELECT 1 FROM rolebyte.event WHERE tenant_id = v_other AND kind = 'configApplied') THEN
        RAISE EXCEPTION 'an import left a line in another tenant''s history';
    END IF;
    CALL rolebyte.config_version(jsonb_build_object('tenantId', v_other), v);
    IF v->'data'->>'version' IS DISTINCT FROM v_other0 THEN
        RAISE EXCEPTION 'one tenant''s import moved another tenant''s version';
    END IF;

    -- 5b. The corporate login a file names is never attached, and the one the
    --     workspace has stays.
    v_issuer := 'https://login.example.test/' || v_tenant || '/v2.0';
    UPDATE rolebyte.tenant SET directory_issuer = v_issuer WHERE id = v_tenant;
    CALL rolebyte.config_apply(jsonb_build_object('tenantId', v_tenant, 'actor', 'config-test', 'dryRun', false,
        'expectedVersion', v1, 'section', jsonb_build_object('schema', 'rolebyte-config/1',
            'tenant', jsonb_build_object('directory', jsonb_build_object('issuer', 'https://elsewhere.example.test/v2.0')))), v);
    IF v->>'result' IS DISTINCT FROM 'success' OR (v->'data'->>'applied')::boolean IS NOT TRUE
       OR (SELECT string_agg(e->>'key' || '=' || (e->>'status'), ',') FROM jsonb_array_elements(v->'data'->'workspace') e)
           IS DISTINCT FROM 'directory=skipped'
       OR v->'data'->'workspace'->0->>'detail' NOT LIKE '%keeps its own corporate login%' THEN
        RAISE EXCEPTION 'a file naming a corporate login is told the workspace keeps its own: %', v;
    END IF;
    IF (SELECT directory_issuer FROM rolebyte.tenant WHERE id = v_tenant) IS DISTINCT FROM v_issuer THEN
        RAISE EXCEPTION 'an import replaced the workspace''s corporate login';
    END IF;
    -- A tenant member of any other shape is not read at all.
    CALL rolebyte.config_apply(jsonb_build_object('tenantId', v_tenant, 'actor', 'config-test', 'dryRun', true,
        'section', '{"schema":"rolebyte-config/1","tenant":"Somebody else"}'::jsonb), v);
    IF v->>'result' IS DISTINCT FROM 'success' OR (v->'data'->>'refused')::boolean OR v->'data' ? 'workspace' THEN
        RAISE EXCEPTION 'a tenant member that is not an object is ignored: %', v;
    END IF;

    -- 6. The round trip: the section read back re-applies as all-unchanged,
    --    moves nothing, keeps the seeds, and still leaves its one line.
    CALL rolebyte.config_get(jsonb_build_object('tenantId', v_tenant), v);
    v_section := v->'data'->'section';
    SELECT count(*) INTO v_defs FROM rolebyte.role_definition;
    SELECT count(*) INTO v_imports FROM rolebyte.event WHERE tenant_id = v_tenant AND kind = 'configApplied';
    CALL rolebyte.config_apply(jsonb_build_object('tenantId', v_tenant, 'actor', 'config-test',
        'section', v_section, 'expectedVersion', v1), v);
    IF v->>'result' IS DISTINCT FROM 'success' OR (v->'data'->>'applied')::boolean IS NOT TRUE THEN
        RAISE EXCEPTION 'the round trip failed: %', v;
    END IF;
    IF EXISTS (SELECT 1 FROM jsonb_array_elements((v->'data'->'services') || (v->'data'->'roles') || (v->'data'->'permissions')) e
                WHERE e->>'status' <> 'unchanged')
       OR NOT EXISTS (SELECT 1 FROM jsonb_array_elements(v->'data'->'permissions') e WHERE e->>'key' = 'cfgseed/thing:view')
       OR v->'data' ? 'workspace' THEN
        RAISE EXCEPTION 'the round trip should report every entry unchanged: %', v;
    END IF;
    IF v->'data'->>'version' IS DISTINCT FROM v1 THEN
        RAISE EXCEPTION 'an unchanged apply moved the version';
    END IF;
    IF (SELECT seeds FROM rolebyte.service_permission WHERE service_key = 'cfgseed' AND act = 'view')
       IS DISTINCT FROM '{manager,worker}'::text[] THEN
        RAISE EXCEPTION 'reading the section back took a permission''s seeds away';
    END IF;
    IF (SELECT count(*) FROM rolebyte.role_definition) <> v_defs THEN
        RAISE EXCEPTION 'an apply must never remove a definition';
    END IF;
    IF (SELECT count(*) FROM rolebyte.event WHERE tenant_id = v_tenant AND kind = 'configApplied') <> v_imports + 1 THEN
        RAISE EXCEPTION 'an apply that changed nothing should still leave exactly one line';
    END IF;
    SELECT payload INTO v_line FROM rolebyte.event
     WHERE tenant_id = v_tenant AND kind = 'configApplied' ORDER BY at DESC, id DESC LIMIT 1;
    IF v_line ? 'partHash' OR v_line ? 'documentHash' THEN
        RAISE EXCEPTION 'a line names no hash its apply did not name: %', v_line;
    END IF;

    -- 7. A permission the list holds with other words is skipped, naming the
    --    members that differ; one it holds with another class is skipped too,
    --    and neither is written.
    v_doc := jsonb_build_object('schema', 'rolebyte-config/1', 'services', '[{"key":"cfgseed","permissions":[
        {"feature":"thing","act":"view","description":"See any thing","class":"ordinary","plane":"object",
         "labels":{"lv":"Redzēt jebkuru lietu"},"seeds":["worker","manager"]}]}]'::jsonb);
    CALL rolebyte.config_apply(jsonb_build_object('tenantId', v_tenant, 'actor', 'config-test',
        'section', v_doc, 'dryRun', 'true'), v);
    IF v->'data'->'permissions'->0->>'key' IS DISTINCT FROM 'cfgseed/thing:view'
       OR v->'data'->'permissions'->0->>'status' IS DISTINCT FROM 'skipped'
       OR v->'data'->'permissions'->0->>'detail' NOT LIKE '%says otherwise (description, labels)%' THEN
        RAISE EXCEPTION 'a permission held with other words is skipped, naming its members: %', v;
    END IF;
    v_doc := jsonb_build_object('schema', 'rolebyte-config/1', 'services', '[{"key":"cfgseed","permissions":[
        {"feature":"thing","act":"view","class":"tenantConfiguration","plane":"tenant"}]}]'::jsonb);
    CALL rolebyte.config_apply(jsonb_build_object('tenantId', v_tenant, 'actor', 'config-test',
        'section', v_doc, 'expectedVersion', v1), v);
    IF (v->'data'->>'refused')::boolean OR (v->'data'->>'applied')::boolean IS NOT TRUE
       OR v->'data'->'permissions'->0->>'status' IS DISTINCT FROM 'skipped'
       OR v->'data'->'permissions'->0->>'detail' NOT LIKE '%class never changes%' THEN
        RAISE EXCEPTION 'a permission held with another class is skipped, not refused: %', v;
    END IF;
    IF (SELECT description || '/' || class FROM rolebyte.service_permission WHERE service_key = 'cfgseed' AND act = 'view')
       IS DISTINCT FROM 'See a thing/ordinary' THEN
        RAISE EXCEPTION 'an import changed a permission on the deployment''s list';
    END IF;

    -- 8. A document with an entry that cannot be read: the preview and the
    --    apply report the same, nothing is written, the version stays and no
    --    line is left.
    v_doc := jsonb_build_object('schema', 'rolebyte-config/1', 'services', '[
        {"key":"cfgbeside","displayName":"Should not survive","roles":[]},
        {"displayName":"No key at all"}]'::jsonb);
    CALL rolebyte.config_apply(jsonb_build_object('tenantId', v_tenant, 'actor', 'config-test',
        'section', v_doc, 'dryRun', true), v);
    v_pre := v->'data';
    IF (v_pre->>'refused')::boolean IS NOT TRUE
       OR NOT EXISTS (SELECT 1 FROM jsonb_array_elements(v_pre->'services') e
                       WHERE e->>'key' = 'cfgbeside' AND e->>'status' = 'skipped')
       OR NOT EXISTS (SELECT 1 FROM jsonb_array_elements(v_pre->'services') e
                       WHERE e->>'key' = '' AND e->>'status' = 'refused' AND e->>'reason' = 'config_bad_document') THEN
        RAISE EXCEPTION 'the preview should refuse the keyless service beside the skipped one: %', v_pre;
    END IF;
    SELECT count(*) INTO v_imports FROM rolebyte.event WHERE tenant_id = v_tenant AND kind = 'configApplied';
    CALL rolebyte.config_apply(jsonb_build_object('tenantId', v_tenant, 'actor', 'config-test',
        'section', v_doc, 'expectedVersion', v1), v);
    IF v->>'result' IS DISTINCT FROM 'success' OR (v->'data'->>'applied')::boolean OR (v->'data'->>'refused')::boolean IS NOT TRUE THEN
        RAISE EXCEPTION 'a refused document is a report, not applied: %', v;
    END IF;
    IF (v->'data') - 'dryRun' IS DISTINCT FROM v_pre - 'dryRun' THEN
        RAISE EXCEPTION 'the preview and the apply disagree: % vs %', v->'data', v_pre;
    END IF;
    IF EXISTS (SELECT 1 FROM rolebyte.service WHERE key = 'cfgbeside') THEN
        RAISE EXCEPTION 'a refused document wrote something';
    END IF;
    CALL rolebyte.config_version(jsonb_build_object('tenantId', v_tenant), v);
    IF v->'data'->>'version' IS DISTINCT FROM v1 THEN
        RAISE EXCEPTION 'a refused document moved the version';
    END IF;
    IF (SELECT count(*) FROM rolebyte.event WHERE tenant_id = v_tenant AND kind = 'configApplied') <> v_imports THEN
        RAISE EXCEPTION 'a refused document left an import line';
    END IF;

    -- 9. A document that is not this section is refused whole.
    CALL rolebyte.config_apply(jsonb_build_object('tenantId', v_tenant, 'actor', 'config-test', 'dryRun', true,
        'section', '{"schema":"another-rolebyte-config/1"}'::jsonb), v);
    IF v->>'code' IS DISTINCT FROM 'membership:config_bad_document' THEN
        RAISE EXCEPTION 'another schema should be refused: %', v;
    END IF;
    CALL rolebyte.config_apply(jsonb_build_object('tenantId', v_tenant, 'actor', 'config-test', 'dryRun', true,
        'section', '{"services":[]}'::jsonb), v);
    IF v->>'code' IS DISTINCT FROM 'membership:config_bad_document' THEN
        RAISE EXCEPTION 'a section naming no schema should be refused: %', v;
    END IF;
    CALL rolebyte.config_apply(jsonb_build_object('tenantId', v_tenant, 'actor', 'config-test', 'dryRun', true,
        'section', '{"schema":"rolebyte-config/1","services":{"key":"x"}}'::jsonb), v);
    IF v->>'code' IS DISTINCT FROM 'membership:config_bad_document' THEN
        RAISE EXCEPTION 'services that are not a list should be refused: %', v;
    END IF;
    CALL rolebyte.config_apply(jsonb_build_object('tenantId', v_tenant, 'actor', 'config-test', 'dryRun', true,
        'section', '{"schema":"rolebyte-config/1"}'::jsonb, 'partHash', 'sha256:nothex'), v);
    IF v->>'code' IS DISTINCT FROM 'membership:config_bad_document' THEN
        RAISE EXCEPTION 'a part hash out of shape should be refused: %', v;
    END IF;

    -- 10. An export leaves one line naming who took the part and its hash.
    CALL rolebyte.config_exported(jsonb_build_object('tenantId', v_tenant, 'actor', 'config-test', 'partHash', v_part), v);
    IF v->>'result' IS DISTINCT FROM 'success'
       OR NOT EXISTS (SELECT 1 FROM rolebyte.event WHERE tenant_id = v_tenant AND kind = 'configExported'
                        AND actor = 'config-test' AND payload->>'partHash' = v_part) THEN
        RAISE EXCEPTION 'an export should leave its line: %', v;
    END IF;
    CALL rolebyte.config_exported(jsonb_build_object('tenantId', v_tenant, 'actor', 'config-test', 'partHash', 'nope'), v);
    IF v->>'code' IS DISTINCT FROM 'membership:invalid' THEN
        RAISE EXCEPTION 'an export naming no hash should be refused: %', v;
    END IF;

    -- 11. The deployment's registration: additive, idempotent, no tenant and
    --     no import line; one refused entry writes nothing and names it.
    SELECT count(*) INTO v_imports FROM rolebyte.event WHERE kind = 'configApplied';
    CALL rolebyte.permissions_register(jsonb_build_object('actor', 'config-test', 'section', '{
      "services":[{"key":"cfgseed","displayName":"Seeded demo","permissions":[
        {"feature":"thing","act":"view","description":"See a thing","class":"ordinary","plane":"object",
         "labels":{"lv":"Redzēt lietu"},"seeds":["worker","manager"]}]}]}'::jsonb), v);
    IF v->'data'->'permissions'->0->>'status' IS DISTINCT FROM 'unchanged' THEN
        RAISE EXCEPTION 'a second registration should report the permission unchanged: %', v;
    END IF;
    BEGIN
        CALL rolebyte.permissions_register(jsonb_build_object('actor', 'config-test', 'section', '{
          "services":[{"key":"cfgregpoison","displayName":"Should not survive","permissions":[]},
                      {"key":"cfgseed","permissions":[{"feature":"thing","act":"view","class":"roleManagement","plane":"tenant"}]}]}'::jsonb), v);
        RAISE EXCEPTION 'a re-classing registration should have been refused';
    EXCEPTION WHEN sqlstate 'P0001' THEN
        IF SQLERRM NOT LIKE '%membership:config_key_conflict%' OR SQLERRM NOT LIKE '%cfgseed/thing:view%' THEN
            RAISE EXCEPTION 'the refused registration raised the wrong error: %', SQLERRM;
        END IF;
    END;
    IF EXISTS (SELECT 1 FROM rolebyte.service WHERE key = 'cfgregpoison') THEN
        RAISE EXCEPTION 'a refused registration wrote something';
    END IF;
    IF (SELECT count(*) FROM rolebyte.event WHERE kind = 'configApplied') <> v_imports THEN
        RAISE EXCEPTION 'a registration left an import line';
    END IF;

    -- 12. An unknown tenant is refused.
    CALL rolebyte.config_get('{"tenantId":"no-such"}'::jsonb, v);
    IF v->>'code' IS DISTINCT FROM 'membership:not_found' THEN
        RAISE EXCEPTION 'unknown tenant should refuse not_found: %', v;
    END IF;
    CALL rolebyte.config_version('{"tenantId":"no-such"}'::jsonb, v);
    IF v->>'code' IS DISTINCT FROM 'membership:not_found' THEN
        RAISE EXCEPTION 'unknown tenant should refuse not_found on the version: %', v;
    END IF;

    RAISE EXCEPTION 'unit.rolebyte_config: undo what the test wrote' USING ERRCODE = 'RBT01';
    EXCEPTION
        WHEN sqlstate 'RBT01' THEN NULL;
    END;
    IF EXISTS (SELECT 1 FROM rolebyte.service WHERE key IN ('cfgseed', 'cfgdemo')) THEN
        RAISE EXCEPTION 'the test left its services behind';
    END IF;

    RAISE NOTICE 'unit.rolebyte_config: all assertions passed';
END $$;

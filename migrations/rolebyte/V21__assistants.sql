-- V21: assistants — what V20 called a helper is an assistant, and an assistant
-- is one person's own.
--
-- A person connects their AI app by signing in and choosing one of their own
-- assistants, so an assistant belongs to exactly one person, made for them by an
-- administrator; a person may have several. V20 kept a list of people per helper;
-- that list becomes the one person:
--
-- * helper_user becomes assistant_person, keyed by the assistant alone. A helper
--   whose list named exactly one person keeps that person. One whose list named
--   several keeps none, so no assistant is given to a person nobody chose for it;
--   an administrator gives it to one person, and until then it serves nobody.
-- * the seed `helper` becomes `assistant`, in what the services declared and on
--   the tenants' roles; a tenant's seeded role still named Helper (lv Palīgs) is
--   named Assistant (lv Asistents) where no other role of the tenant reads so.
-- * the routines that carried the old name are dropped here, so the repeatable
--   file recreates them under the new one; renaming them in place would leave the
--   old names callable.
--
-- Guarded so a replay against a database that already carries the new names is a
-- no-op rather than a failure.

DO $$
DECLARE
    r record;
BEGIN
    IF EXISTS (SELECT 1 FROM pg_tables WHERE schemaname = 'rolebyte' AND tablename = 'helper_user') THEN
        ALTER TABLE rolebyte.helper_user RENAME TO assistant_person;
    END IF;
    IF EXISTS (SELECT 1 FROM information_schema.columns
               WHERE table_schema = 'rolebyte' AND table_name = 'assistant_person' AND column_name = 'helper_id') THEN
        ALTER TABLE rolebyte.assistant_person RENAME COLUMN helper_id TO assistant_id;
    END IF;

    -- Constraints first (renaming a primary-key constraint renames its index with
    -- it), then whatever indexes still carry the old word.
    FOR r IN
        SELECT c.conname, c.conrelid::regclass AS tbl
          FROM pg_constraint c JOIN pg_namespace n ON n.oid = c.connamespace
         WHERE n.nspname = 'rolebyte' AND c.conname LIKE '%helper%'
    LOOP
        EXECUTE format('ALTER TABLE %s RENAME CONSTRAINT %I TO %I', r.tbl, r.conname,
                       replace(replace(r.conname, 'helper_user', 'assistant_person'), 'helper', 'assistant'));
    END LOOP;
    FOR r IN
        SELECT i.relname
          FROM pg_class i JOIN pg_namespace n ON n.oid = i.relnamespace
         WHERE n.nspname = 'rolebyte' AND i.relkind = 'i' AND i.relname LIKE '%helper%'
    LOOP
        EXECUTE format('ALTER INDEX rolebyte.%I RENAME TO %I', r.relname,
                       replace(replace(r.relname, 'helper_user', 'assistant_person'), 'helper', 'assistant'));
    END LOOP;
END $$;

-- One person per assistant: a list of several keeps none.
DELETE FROM rolebyte.assistant_person a
 WHERE (SELECT count(*) FROM rolebyte.assistant_person b WHERE b.assistant_id = a.assistant_id) > 1;

DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM pg_constraint
                WHERE conname = 'assistant_person_pkey' AND conrelid = 'rolebyte.assistant_person'::regclass
                  AND array_length(conkey, 1) = 2) THEN
        ALTER TABLE rolebyte.assistant_person DROP CONSTRAINT assistant_person_pkey;
    END IF;
    IF NOT EXISTS (SELECT 1 FROM pg_constraint
                    WHERE conname = 'assistant_person_pkey' AND conrelid = 'rolebyte.assistant_person'::regclass) THEN
        ALTER TABLE rolebyte.assistant_person ADD CONSTRAINT assistant_person_pkey PRIMARY KEY (assistant_id);
    END IF;
END $$;

-- The seed, in what the services declared and on the tenants' roles.
UPDATE rolebyte.service_permission SET seeds = array_replace(seeds, 'helper', 'assistant')
 WHERE 'helper' = ANY (seeds);

UPDATE rolebyte.tenant_role r SET seed = 'assistant'
 WHERE r.seed = 'helper';

UPDATE rolebyte.tenant_role r SET name = 'Assistant'
 WHERE r.seed = 'assistant' AND r.name = 'Helper'
   AND NOT EXISTS (SELECT 1 FROM rolebyte.tenant_role o
                    WHERE o.tenant_id = r.tenant_id AND o.id <> r.id AND lower(o.name) = 'assistant');

UPDATE rolebyte.tenant_role r SET labels = jsonb_set(r.labels, '{lv}', '"Asistents"')
 WHERE r.seed = 'assistant' AND r.labels->>'lv' = 'Palīgs'
   AND NOT EXISTS (SELECT 1 FROM rolebyte.tenant_role o
                    WHERE o.tenant_id = r.tenant_id AND o.id <> r.id
                      AND (lower(o.name) = 'asistents' OR lower(o.labels->>'lv') = 'asistents'));

UPDATE rolebyte.tenant_role r
   SET description = 'What an assistant starts with: sees projects and tasks, adds and edits tasks, moves its person''s own, comments.'
 WHERE r.seed = 'assistant'
   AND r.description = 'What a helper starts with: sees projects and tasks, adds and edits tasks, moves its person''s own, comments.';

-- The routines that carried the old name.
DROP PROCEDURE IF EXISTS rolebyte.helper_create(jsonb, jsonb);
DROP PROCEDURE IF EXISTS rolebyte.helper_rename(jsonb, jsonb);
DROP PROCEDURE IF EXISTS rolebyte.helper_users_set(jsonb, jsonb);
DROP PROCEDURE IF EXISTS rolebyte.helper_list(jsonb, jsonb);
DROP PROCEDURE IF EXISTS rolebyte.helper_memberships(jsonb, jsonb);
DROP FUNCTION IF EXISTS rolebyte.helper_role(text, text);
DROP FUNCTION IF EXISTS rolebyte.helper_json(rolebyte.user_account);
DROP FUNCTION IF EXISTS rolebyte.helper_name_taken(text, text, text);

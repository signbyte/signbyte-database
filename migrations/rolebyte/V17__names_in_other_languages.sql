-- V17: a tenant role's, a user type's and a chart position's names in the other
-- languages the app speaks.
--
-- Each keeps one name as the administrator typed it, in the workspace's
-- language, and gains `labels`: a map of its names in the app's other
-- languages, keyed by language. A reader sees the name in their language where
-- one was given, and the name as entered otherwise. Empty for every existing
-- one, so nothing anybody reads changes until a name is given.
--
-- What a name in another language may look like (the same as the name itself,
-- one line of 1 to 100 characters) and that two roles, or two user types, never
-- read alike in any of those languages are the procedures' to keep: which
-- languages the app speaks is decided in one place, and a constraint here would
-- have to repeat it.
ALTER TABLE rolebyte.tenant_role    ADD COLUMN IF NOT EXISTS labels jsonb NOT NULL DEFAULT '{}'::jsonb;
ALTER TABLE rolebyte.user_type      ADD COLUMN IF NOT EXISTS labels jsonb NOT NULL DEFAULT '{}'::jsonb;
ALTER TABLE rolebyte.chart_position ADD COLUMN IF NOT EXISTS labels jsonb NOT NULL DEFAULT '{}'::jsonb;

-- Guarded for replay.
DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_constraint
                    WHERE conname = 'tenant_role_labels_check' AND conrelid = 'rolebyte.tenant_role'::regclass) THEN
        ALTER TABLE rolebyte.tenant_role ADD CONSTRAINT tenant_role_labels_check
            CHECK (jsonb_typeof(labels) = 'object');
    END IF;
    IF NOT EXISTS (SELECT 1 FROM pg_constraint
                    WHERE conname = 'user_type_labels_check' AND conrelid = 'rolebyte.user_type'::regclass) THEN
        ALTER TABLE rolebyte.user_type ADD CONSTRAINT user_type_labels_check
            CHECK (jsonb_typeof(labels) = 'object');
    END IF;
    IF NOT EXISTS (SELECT 1 FROM pg_constraint
                    WHERE conname = 'chart_position_labels_check' AND conrelid = 'rolebyte.chart_position'::regclass) THEN
        ALTER TABLE rolebyte.chart_position ADD CONSTRAINT chart_position_labels_check
            CHECK (jsonb_typeof(labels) = 'object');
    END IF;
END $$;

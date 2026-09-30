-- V6: a service declares the permissions it enforces, as data beside its roles.
--
-- A role today is a service-declared (group, level) pair — one rung of a ladder
-- the service chose. A permission is a finer thing: one act on one feature of the
-- service, such as removing a file somebody else attached to a task. A service
-- declares every act its checks enforce, grouped by feature, exactly as it
-- declares its roles: the catalog is identical on every deployment, it only ever
-- grows, and this register holds no service's list in its own source — it learns
-- each permission by declaration.
--
-- On the wire a permission is `<service>/<feature path>:<act>`, for example
-- `projects/task/attachment:deleteAny`. The feature path may nest (`task`, then
-- `task/attachment`), and nesting grants nothing: holding an act on a feature
-- says nothing about any feature below or beside it. The whole path is the
-- scope's group and the act its level, so a check is one exact match.
--
-- `class` says whether a permission can change permissions: `roleManagement`
-- (who holds which role) and `tenantConfiguration` (the tenant's own setup) are
-- the two kinds that let their holder change what others may do, and the rule
-- for who may hand a role out is computed from them. Only the declaring service
-- knows which of its acts they are, so the class is part of the declaration and
-- never changes afterwards — re-classing a permission would change who may
-- grant it.
--
-- Declaring changes nothing that anybody holds: no role carries a permission and
-- no token contains one until a later step resolves them.
CREATE TABLE IF NOT EXISTS rolebyte.service_permission (
    id          text        NOT NULL PRIMARY KEY,
    service_key text        NOT NULL REFERENCES rolebyte.service (key),
    feature_key text        NOT NULL,
    act         text        NOT NULL,
    description text        NOT NULL DEFAULT '',
    class       text        NOT NULL,
    created_at  timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT service_permission_unique UNIQUE (service_key, feature_key, act),
    CONSTRAINT service_permission_class_check
        CHECK (class IN ('ordinary', 'tenantConfiguration', 'roleManagement'))
);

-- The ONE home of what a feature path and an act may look like: a feature is one
-- or more lower-camel segments joined by `/`, an act is one lower-camel word.
-- Nothing else can appear, which keeps a permission free of the characters that
-- separate scopes on the way to a token (a space, a comma) and of the `:` that
-- separates a scope's group from its level. Called from the constraints below
-- and from the declaring procedure, so a widening is one edit.
CREATE OR REPLACE FUNCTION rolebyte.is_permission_feature(p_feature text)
RETURNS boolean
LANGUAGE sql
IMMUTABLE
RETURNS NULL ON NULL INPUT
SET search_path = pg_temp
AS $$
    SELECT length(p_feature) <= 128
       AND p_feature ~ '^[a-z][a-zA-Z0-9]*(/[a-z][a-zA-Z0-9]*)*$';
$$;

CREATE OR REPLACE FUNCTION rolebyte.is_permission_act(p_act text)
RETURNS boolean
LANGUAGE sql
IMMUTABLE
RETURNS NULL ON NULL INPUT
SET search_path = pg_temp
AS $$
    SELECT length(p_act) <= 64
       AND p_act ~ '^[a-z][a-zA-Z0-9]*$';
$$;

-- The service's key opens the permission, so only a service whose key carries
-- none of those separators may declare one. Service keys are older than
-- permissions and are not constrained themselves; the declaring procedure asks.
CREATE OR REPLACE FUNCTION rolebyte.is_permission_service(p_service text)
RETURNS boolean
LANGUAGE sql
IMMUTABLE
RETURNS NULL ON NULL INPUT
SET search_path = pg_temp
AS $$
    SELECT length(p_service) <= 64
       AND p_service ~ '^[a-z][a-z0-9-]*$';
$$;

-- Least privilege: called only inside the SECURITY DEFINER procedures and the
-- constraints, which run as the owner, so the register's role needs no grant.
REVOKE ALL ON FUNCTION rolebyte.is_permission_feature(text) FROM PUBLIC;
REVOKE ALL ON FUNCTION rolebyte.is_permission_act(text) FROM PUBLIC;
REVOKE ALL ON FUNCTION rolebyte.is_permission_service(text) FROM PUBLIC;

-- Guarded for replay.
DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_constraint
         WHERE conname = 'service_permission_feature_shape'
           AND conrelid = 'rolebyte.service_permission'::regclass
    ) THEN
        ALTER TABLE rolebyte.service_permission
            ADD CONSTRAINT service_permission_feature_shape
            CHECK (rolebyte.is_permission_feature(feature_key));
    END IF;
    IF NOT EXISTS (
        SELECT 1 FROM pg_constraint
         WHERE conname = 'service_permission_act_shape'
           AND conrelid = 'rolebyte.service_permission'::regclass
    ) THEN
        ALTER TABLE rolebyte.service_permission
            ADD CONSTRAINT service_permission_act_shape
            CHECK (rolebyte.is_permission_act(act));
    END IF;
END $$;

-- A role's group can no longer contain `/`. That character now marks a
-- permission, so a role and a permission can never be spelled as the same scope
-- — a role granting `projects/task:edit` would hand out a permission without
-- anybody having declared or ticked it. No existing group contains one; the
-- constraint is added only if that holds, so a deployment that somehow does is
-- told at migration time rather than having its data rewritten.
DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_constraint
         WHERE conname = 'role_definition_group_not_a_permission'
           AND conrelid = 'rolebyte.role_definition'::regclass
    ) THEN
        IF EXISTS (SELECT 1 FROM rolebyte.role_definition WHERE position('/' IN role_group) > 0) THEN
            RAISE EXCEPTION 'a role group contains "/", which now marks a permission; rename it before this migration';
        END IF;
        ALTER TABLE rolebyte.role_definition
            ADD CONSTRAINT role_definition_group_not_a_permission
            CHECK (position('/' IN role_group) = 0);
    END IF;
END $$;

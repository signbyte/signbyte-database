-- V11: a declared permission says where it may be granted, carries its label in
-- each language, and can be retired.
--
-- Plane. A grant sits either on the tenant as a whole or on one object the
-- declaring service owns (a project, a register), and a permission belongs to
-- exactly one of the two: registering a new project can only be granted
-- tenant-wide, while commenting on a task only means something inside the object
-- that holds the task. The declaring service knows which, so the plane is part of
-- the declaration. Like the class, it never changes once declared: moving a
-- permission between planes would silently move a right between the grants a
-- tenant hands out tenant-wide and the ones it places on objects. Permissions
-- declared before this migration carry no plane until their service declares
-- them again, which sets it once.
--
-- Labels. The description is one operator-facing sentence in English. A screen
-- that shows a role's permissions shows them in the viewer's language, and holds
-- no product's words of its own, so the declaration carries a label per language
-- (`{"lv": "…"}`) and the register keeps them. A language without a label falls
-- back to the description.
--
-- Retired. A permission is never removed: roles tick it by id, and the event
-- stream names it. When a service stops using one, it declares it retired. A
-- retired permission stays in the register and keeps working for every role that
-- already ticks it, and no role can be given it again. Declaring it without the
-- retired mark brings it back.

ALTER TABLE rolebyte.service_permission
    ADD COLUMN IF NOT EXISTS plane      text        NULL,
    ADD COLUMN IF NOT EXISTS labels     jsonb       NOT NULL DEFAULT '{}'::jsonb,
    ADD COLUMN IF NOT EXISTS retired_at timestamptz NULL;

-- A label map: an object whose keys are language tags (`lv`, `en`, `pt-BR`) and
-- whose values are non-empty text. The ONE home of that shape, called from the
-- constraint below and from the declaring procedure.
CREATE OR REPLACE FUNCTION rolebyte.is_permission_labels(p_labels jsonb)
RETURNS boolean
LANGUAGE sql
IMMUTABLE
RETURNS NULL ON NULL INPUT
SET search_path = pg_temp
AS $$
    SELECT jsonb_typeof(p_labels) = 'object'
       AND NOT EXISTS (
           SELECT 1
             FROM jsonb_each(p_labels) AS l(lang, label)
            WHERE lang !~ '^[a-z]{2,3}(-[A-Za-z0-9]{2,8})*$'
               OR jsonb_typeof(label) IS DISTINCT FROM 'string'
               OR btrim(label #>> '{}') = ''
               OR length(label #>> '{}') > 256);
$$;

REVOKE ALL ON FUNCTION rolebyte.is_permission_labels(jsonb) FROM PUBLIC;

-- Guarded for replay.
DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_constraint
         WHERE conname = 'service_permission_plane_check'
           AND conrelid = 'rolebyte.service_permission'::regclass
    ) THEN
        ALTER TABLE rolebyte.service_permission
            ADD CONSTRAINT service_permission_plane_check
            CHECK (plane IS NULL OR plane IN ('tenant', 'object'));
    END IF;
    IF NOT EXISTS (
        SELECT 1 FROM pg_constraint
         WHERE conname = 'service_permission_labels_shape'
           AND conrelid = 'rolebyte.service_permission'::regclass
    ) THEN
        ALTER TABLE rolebyte.service_permission
            ADD CONSTRAINT service_permission_labels_shape
            CHECK (rolebyte.is_permission_labels(labels));
    END IF;
END $$;

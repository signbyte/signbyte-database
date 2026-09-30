-- V13: a family of permissions, one per field.
--
-- A service whose tenants add fields of their own lets a tenant choose which
-- roles see a field's values. It cannot declare a permission per field — the
-- fields are the tenant's data, not the service's code — so it declares one
-- family per kind of field, of the class `perField` (`projects/task:viewField`),
-- and one field's permission is the family, `@`, the field's key and a
-- generation the field counts up each time it is restricted:
-- `projects/task:viewField@rate.2`. The register keeps only the family as a
-- declaration; which fields exist, and which of them are restricted, is the
-- declaring service's to know.
--
-- A tick of one field's permission is a tick of the family with the part after
-- `@` beside it, so a role holds as many fields of one family as the tenant
-- ticked. The bare family is never ticked: it means every field of the kind, and
-- it is the administrators', who hold every declared permission. Neither reaches
-- any other token: a field's permission is read by the services that place the
-- tenant's roles on their own objects, from the roles they copy.

-- The class. Guarded for replay: the check is replaced only while it still has
-- its first shape.
DO $$
BEGIN
    IF EXISTS (
        SELECT 1 FROM pg_constraint
         WHERE conname = 'service_permission_class_check'
           AND conrelid = 'rolebyte.service_permission'::regclass
           AND pg_get_constraintdef(oid) NOT LIKE '%perField%'
    ) THEN
        ALTER TABLE rolebyte.service_permission DROP CONSTRAINT service_permission_class_check;
    END IF;
    IF NOT EXISTS (
        SELECT 1 FROM pg_constraint
         WHERE conname = 'service_permission_class_check'
           AND conrelid = 'rolebyte.service_permission'::regclass
    ) THEN
        ALTER TABLE rolebyte.service_permission
            ADD CONSTRAINT service_permission_class_check
            CHECK (class IN ('ordinary', 'tenantConfiguration', 'roleManagement', 'perField'));
    END IF;

    -- A field's permission is held where a role is placed, on one of the
    -- service's objects, so a family is declared on the object plane.
    IF NOT EXISTS (
        SELECT 1 FROM pg_constraint
         WHERE conname = 'service_permission_per_field_on_objects'
           AND conrelid = 'rolebyte.service_permission'::regclass
    ) THEN
        ALTER TABLE rolebyte.service_permission
            ADD CONSTRAINT service_permission_per_field_on_objects
            CHECK (class <> 'perField' OR plane = 'object');
    END IF;
END $$;

-- The ONE home of what the part after `@` may look like: the field's key, as the
-- slug of its label reads (a lower-case letter or a digit, then letters and
-- digits, at most 64), a `.`, and the generation, a whole number from 1. Nothing
-- else, so a field's permission carries none of the characters that separate
-- scopes or a scope's parts. Called from the constraint below and from the
-- procedures, so a widening is one edit.
CREATE OR REPLACE FUNCTION rolebyte.is_permission_param(p_param text)
RETURNS boolean
LANGUAGE sql
IMMUTABLE
RETURNS NULL ON NULL INPUT
SET search_path = pg_temp
AS $$
    SELECT p_param ~ '^[a-z0-9][a-zA-Z0-9]{0,63}\.[1-9][0-9]{0,8}$';
$$;

-- Least privilege: called only inside the SECURITY DEFINER procedures and the
-- constraint, which run as the owner, so the register's role needs no grant.
REVOKE ALL ON FUNCTION rolebyte.is_permission_param(text) FROM PUBLIC;

-- The tick's field part: NULL for every permission that is not a family, one
-- field's key and generation for a family. It is part of what makes a tick one
-- tick, so the key moves from the primary key to a unique key that treats two
-- NULLs as the same (a role ticks an ordinary permission once).
ALTER TABLE rolebyte.tenant_role_permission
    ADD COLUMN IF NOT EXISTS param text NULL;

DO $$
BEGIN
    IF EXISTS (
        SELECT 1 FROM pg_constraint
         WHERE conname = 'tenant_role_permission_pkey'
           AND conrelid = 'rolebyte.tenant_role_permission'::regclass
    ) THEN
        ALTER TABLE rolebyte.tenant_role_permission DROP CONSTRAINT tenant_role_permission_pkey;
    END IF;
    IF NOT EXISTS (
        SELECT 1 FROM pg_constraint
         WHERE conname = 'tenant_role_permission_unique'
           AND conrelid = 'rolebyte.tenant_role_permission'::regclass
    ) THEN
        ALTER TABLE rolebyte.tenant_role_permission
            ADD CONSTRAINT tenant_role_permission_unique
            UNIQUE NULLS NOT DISTINCT (tenant_role_id, permission_id, param);
    END IF;
    IF NOT EXISTS (
        SELECT 1 FROM pg_constraint
         WHERE conname = 'tenant_role_permission_param_shape'
           AND conrelid = 'rolebyte.tenant_role_permission'::regclass
    ) THEN
        ALTER TABLE rolebyte.tenant_role_permission
            ADD CONSTRAINT tenant_role_permission_param_shape
            CHECK (param IS NULL OR rolebyte.is_permission_param(param));
    END IF;
END $$;

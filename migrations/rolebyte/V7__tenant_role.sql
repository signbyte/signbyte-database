-- V7: a tenant defines its own roles.
--
-- Until now every role was a service's: a (group, level) pair it declared, the
-- same on every tenant of a deployment. A tenant role is the tenant's own — a
-- workshop may hold three, another twenty-one, each named as that tenant names
-- it — and it is made of ticks over the permissions services declare.
--
-- A tenant role is identified by its id. Its name is a label the tenant may
-- change at will, so nothing may key on it; it is unique per tenant, ignoring
-- case, only so that a list of roles never shows two nobody can tell apart.
--
-- A tenant role belongs to no service. One role holds ticks from as many
-- services as the tenant uses — the same person manages the projects and the
-- people register — and each tick names a declared permission, which already
-- says which service enforces it.
--
-- A grant of a tenant role is its own row, beside the grants of service roles
-- rather than among them, so nothing that reads those grants changes. What a
-- tenant role holds does not reach any token here: resolving it is a later step.
CREATE TABLE IF NOT EXISTS rolebyte.tenant_role (
    id          text        NOT NULL PRIMARY KEY,
    tenant_id   text        NOT NULL REFERENCES rolebyte.tenant (id),
    name        text        NOT NULL,
    description text        NOT NULL DEFAULT '',
    created_at  timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT tenant_role_in_tenant UNIQUE (tenant_id, id)
);

CREATE UNIQUE INDEX IF NOT EXISTS tenant_role_name_per_tenant
    ON rolebyte.tenant_role (tenant_id, lower(name));

-- A tick: this role holds this declared permission. Declared permissions are
-- never removed, so a tick can never be left naming nothing.
CREATE TABLE IF NOT EXISTS rolebyte.tenant_role_permission (
    tenant_role_id text NOT NULL REFERENCES rolebyte.tenant_role (id),
    permission_id  text NOT NULL REFERENCES rolebyte.service_permission (id),
    CONSTRAINT tenant_role_permission_pkey PRIMARY KEY (tenant_role_id, permission_id)
);

-- A person's grant of a tenant role. Current state, derived from the event
-- stream exactly as the grants of service roles are: re-granting a revoked
-- role flips the row back and the events keep both moments.
--
-- The tenant is part of both references, so a person and a role from two
-- different tenants cannot be joined by a grant on any code path — the
-- procedures check it first, and this is the layer that holds even if one of
-- them is ever wrong.
CREATE TABLE IF NOT EXISTS rolebyte.tenant_role_assignment (
    id             text        NOT NULL PRIMARY KEY,
    tenant_id      text        NOT NULL,
    user_id        text        NOT NULL,
    tenant_role_id text        NOT NULL,
    state          text        NOT NULL DEFAULT 'granted',
    granted_at     timestamptz NOT NULL DEFAULT now(),
    revoked_at     timestamptz NULL,
    CONSTRAINT tenant_role_assignment_state_check CHECK (state IN ('granted', 'revoked')),
    CONSTRAINT tenant_role_assignment_unique UNIQUE (user_id, tenant_role_id)
);

CREATE INDEX IF NOT EXISTS tenant_role_assignment_role_idx
    ON rolebyte.tenant_role_assignment (tenant_role_id);

-- The ONE home of what a role's name may look like: 1 to 100 characters, with
-- no space at either end and no control character anywhere (a name is one line
-- on a screen). Called from the constraint below and from the procedures, so a
-- change is one edit.
CREATE OR REPLACE FUNCTION rolebyte.is_tenant_role_name(p_name text)
RETURNS boolean
LANGUAGE sql
IMMUTABLE
RETURNS NULL ON NULL INPUT
SET search_path = pg_temp
AS $$
    SELECT length(p_name) BETWEEN 1 AND 100
       AND p_name = btrim(p_name)
       AND p_name !~ '[[:cntrl:]]';
$$;

-- Least privilege: called only inside the SECURITY DEFINER procedures and the
-- constraint, which run as the owner, so the register's role needs no grant.
REVOKE ALL ON FUNCTION rolebyte.is_tenant_role_name(text) FROM PUBLIC;

-- Guarded for replay.
DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_constraint
         WHERE conname = 'tenant_role_name_shape'
           AND conrelid = 'rolebyte.tenant_role'::regclass
    ) THEN
        ALTER TABLE rolebyte.tenant_role
            ADD CONSTRAINT tenant_role_name_shape
            CHECK (rolebyte.is_tenant_role_name(name));
    END IF;
    IF NOT EXISTS (
        SELECT 1 FROM pg_constraint
         WHERE conname = 'tenant_role_description_length'
           AND conrelid = 'rolebyte.tenant_role'::regclass
    ) THEN
        ALTER TABLE rolebyte.tenant_role
            ADD CONSTRAINT tenant_role_description_length
            CHECK (length(description) <= 1000);
    END IF;

    -- A person is addressed together with their tenant. The id alone is already
    -- unique, so this refuses nothing that exists; it is what the grant below
    -- references.
    IF NOT EXISTS (
        SELECT 1 FROM pg_constraint
         WHERE conname = 'user_account_in_tenant'
           AND conrelid = 'rolebyte.user_account'::regclass
    ) THEN
        ALTER TABLE rolebyte.user_account
            ADD CONSTRAINT user_account_in_tenant UNIQUE (tenant_id, id);
    END IF;

    IF NOT EXISTS (
        SELECT 1 FROM pg_constraint
         WHERE conname = 'tenant_role_assignment_user'
           AND conrelid = 'rolebyte.tenant_role_assignment'::regclass
    ) THEN
        ALTER TABLE rolebyte.tenant_role_assignment
            ADD CONSTRAINT tenant_role_assignment_user
            FOREIGN KEY (tenant_id, user_id) REFERENCES rolebyte.user_account (tenant_id, id);
    END IF;
    IF NOT EXISTS (
        SELECT 1 FROM pg_constraint
         WHERE conname = 'tenant_role_assignment_role'
           AND conrelid = 'rolebyte.tenant_role_assignment'::regclass
    ) THEN
        ALTER TABLE rolebyte.tenant_role_assignment
            ADD CONSTRAINT tenant_role_assignment_role
            FOREIGN KEY (tenant_id, tenant_role_id) REFERENCES rolebyte.tenant_role (tenant_id, id);
    END IF;
END $$;

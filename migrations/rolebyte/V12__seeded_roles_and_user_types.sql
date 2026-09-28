-- V12: the roles a new tenant starts with, and user types.
--
-- A service may say, beside each permission it declares, which of the roles
-- the register creates with every new tenant hold it — a worker, a manager —
-- so a tenant opened today has roles that work before anybody makes one. Such
-- a role remembers which it was (its seed), so a service choosing a default
-- role picks it by seed and never by a name the tenant may change.
--
-- A user type is a named set of the tenant's own tenant-wide permissions —
-- registering a project, say — given to a person across the whole tenant. It
-- never carries a permission placed on an object, so it never gives sight of
-- anybody's work. A person holds at most one, and the register records where it
-- came from: an administrator set it, or the tenant's default for people who
-- arrive through its corporate login gave it at their first sign-in.

-- ---------------------------------------------------------------------------
-- Seeds.
-- ---------------------------------------------------------------------------
ALTER TABLE rolebyte.service_permission
    ADD COLUMN IF NOT EXISTS seeds text[] NOT NULL DEFAULT '{}';

-- Only an ordinary permission on the object plane goes to a seeded role:
-- setup is the administrator's, and a tenant-wide grant is a user type's.
DO $$ BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_constraint
                    WHERE conname = 'service_permission_seeds_placed'
                      AND conrelid = 'rolebyte.service_permission'::regclass) THEN
        ALTER TABLE rolebyte.service_permission ADD CONSTRAINT service_permission_seeds_placed
            CHECK (seeds = '{}' OR (plane = 'object' AND class = 'ordinary'));
    END IF;
END $$;

ALTER TABLE rolebyte.tenant_role
    ADD COLUMN IF NOT EXISTS seed text NOT NULL DEFAULT '';

-- One role per seed per tenant; a role the tenant made has none.
CREATE UNIQUE INDEX IF NOT EXISTS tenant_role_seed_per_tenant
    ON rolebyte.tenant_role (tenant_id, seed) WHERE seed <> '';

-- ---------------------------------------------------------------------------
-- User types.
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS rolebyte.user_type (
    id          text        NOT NULL PRIMARY KEY,
    tenant_id   text        NOT NULL REFERENCES rolebyte.tenant (id),
    name        text        NOT NULL,
    description text        NOT NULL DEFAULT '',
    created_at  timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT user_type_in_tenant UNIQUE (tenant_id, id)
);

CREATE UNIQUE INDEX IF NOT EXISTS user_type_name_per_tenant
    ON rolebyte.user_type (tenant_id, lower(name));

DO $$ BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_constraint
                    WHERE conname = 'user_type_name_shape' AND conrelid = 'rolebyte.user_type'::regclass) THEN
        ALTER TABLE rolebyte.user_type ADD CONSTRAINT user_type_name_shape
            CHECK (rolebyte.is_tenant_role_name(name));
    END IF;
END $$;

-- A tick: this user type holds this declared permission. The procedures refuse
-- anything but an ordinary tenant-wide permission.
CREATE TABLE IF NOT EXISTS rolebyte.user_type_permission (
    user_type_id  text NOT NULL REFERENCES rolebyte.user_type (id),
    permission_id text NOT NULL REFERENCES rolebyte.service_permission (id),
    CONSTRAINT user_type_permission_pkey PRIMARY KEY (user_type_id, permission_id)
);

-- A person's user type, and where it came from.
ALTER TABLE rolebyte.user_account
    ADD COLUMN IF NOT EXISTS user_type_id text NULL,
    ADD COLUMN IF NOT EXISTS user_type_source text NULL;

DO $$ BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_constraint
                    WHERE conname = 'user_account_user_type_fk' AND conrelid = 'rolebyte.user_account'::regclass) THEN
        -- The tenant is part of the reference, so a person and a user type of
        -- two different tenants can never be joined.
        ALTER TABLE rolebyte.user_account ADD CONSTRAINT user_account_user_type_fk
            FOREIGN KEY (tenant_id, user_type_id) REFERENCES rolebyte.user_type (tenant_id, id);
    END IF;
    IF NOT EXISTS (SELECT 1 FROM pg_constraint
                    WHERE conname = 'user_account_user_type_source' AND conrelid = 'rolebyte.user_account'::regclass) THEN
        ALTER TABLE rolebyte.user_account ADD CONSTRAINT user_account_user_type_source
            CHECK ((user_type_id IS NULL AND user_type_source IS NULL)
                   OR (user_type_id IS NOT NULL AND user_type_source IN ('administrator', 'corporateLoginDefault')));
    END IF;
END $$;

-- The user type a person arriving through the tenant's corporate login receives
-- at their first sign-in. Empty: they arrive holding nothing, and an
-- administrator sets each one.
ALTER TABLE rolebyte.tenant
    ADD COLUMN IF NOT EXISTS corporate_login_user_type_id text NULL;

DO $$ BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_constraint
                    WHERE conname = 'tenant_corporate_login_user_type_fk' AND conrelid = 'rolebyte.tenant'::regclass) THEN
        ALTER TABLE rolebyte.tenant ADD CONSTRAINT tenant_corporate_login_user_type_fk
            FOREIGN KEY (id, corporate_login_user_type_id) REFERENCES rolebyte.user_type (tenant_id, id);
    END IF;
END $$;

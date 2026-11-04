-- V14: the tenant's chart of authority, and a user type for every member.
--
-- The chart. A tenant draws a tree of positions and puts its people in them. A
-- position carries boxes of its own, granted relative to the tree ("the
-- projects of the people below me"), and may name the user type of whoever sits
-- in it. Nothing here is ticked on a role or a user type: a third plane,
-- `chart`, holds the boxes a position may carry, and the procedures that hand
-- out roles and user types refuse them. The boxes are declared under a service
-- key of their own, so a tenant has the chart only while it is entitled to that
-- key; positions, people and boxes stay when the entitlement lapses and return
-- as they were left.
--
-- One tree: a tenant has exactly one position without a parent. A person sits
-- in at most one position, since a position names one user type and a person
-- holds one. A position holds any number of people and may hold none.
--
-- The user type. Every member holds one: a tenant starts with a default,
-- named in its language and holding nothing, every arrival on every lane
-- receives it, and a person's type is never set to nothing. The default cannot
-- be deleted, and neither can a type somebody holds or a position names.

-- ---------------------------------------------------------------------------
-- The third plane.
-- ---------------------------------------------------------------------------
ALTER TABLE rolebyte.service_permission DROP CONSTRAINT IF EXISTS service_permission_plane_check;
ALTER TABLE rolebyte.service_permission
    ADD CONSTRAINT service_permission_plane_check
    CHECK (plane IS NULL OR plane IN ('tenant', 'object', 'chart'));

-- ---------------------------------------------------------------------------
-- The chart.
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS rolebyte.chart_position (
    id           text        NOT NULL PRIMARY KEY,
    tenant_id    text        NOT NULL REFERENCES rolebyte.tenant (id),
    parent_id    text        NULL,
    name         text        NOT NULL,
    user_type_id text        NULL,
    created_at   timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT chart_position_in_tenant UNIQUE (tenant_id, id),
    -- The tenant is part of every reference, so a position can never be placed
    -- under, or name the user type of, another tenant.
    CONSTRAINT chart_position_parent_fk
        FOREIGN KEY (tenant_id, parent_id) REFERENCES rolebyte.chart_position (tenant_id, id),
    CONSTRAINT chart_position_user_type_fk
        FOREIGN KEY (tenant_id, user_type_id) REFERENCES rolebyte.user_type (tenant_id, id),
    CONSTRAINT chart_position_name_shape CHECK (rolebyte.is_tenant_role_name(name)),
    CONSTRAINT chart_position_not_own_parent CHECK (parent_id IS DISTINCT FROM id)
);

-- One top position per tenant.
CREATE UNIQUE INDEX IF NOT EXISTS chart_position_one_top
    ON rolebyte.chart_position (tenant_id) WHERE parent_id IS NULL;
CREATE INDEX IF NOT EXISTS chart_position_parent_idx
    ON rolebyte.chart_position (tenant_id, parent_id);

-- A person in a position; at most one position per person.
CREATE TABLE IF NOT EXISTS rolebyte.chart_holder (
    tenant_id   text        NOT NULL,
    user_id     text        NOT NULL,
    position_id text        NOT NULL,
    placed_at   timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT chart_holder_pkey PRIMARY KEY (tenant_id, user_id),
    CONSTRAINT chart_holder_position_fk
        FOREIGN KEY (tenant_id, position_id) REFERENCES rolebyte.chart_position (tenant_id, id),
    CONSTRAINT chart_holder_user_fk
        FOREIGN KEY (tenant_id, user_id) REFERENCES rolebyte.user_account (tenant_id, id)
);
CREATE INDEX IF NOT EXISTS chart_holder_position_idx ON rolebyte.chart_holder (position_id);

-- A tick: this position carries this declared chart permission. The procedures
-- refuse anything that is not a chart permission.
CREATE TABLE IF NOT EXISTS rolebyte.chart_position_permission (
    position_id   text NOT NULL REFERENCES rolebyte.chart_position (id),
    permission_id text NOT NULL REFERENCES rolebyte.service_permission (id),
    CONSTRAINT chart_position_permission_pkey PRIMARY KEY (position_id, permission_id)
);

-- ---------------------------------------------------------------------------
-- A user type for every member.
-- ---------------------------------------------------------------------------
ALTER TABLE rolebyte.tenant
    ADD COLUMN IF NOT EXISTS default_user_type_id text NULL;

DO $$ BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_constraint
                    WHERE conname = 'tenant_default_user_type_fk' AND conrelid = 'rolebyte.tenant'::regclass) THEN
        ALTER TABLE rolebyte.tenant ADD CONSTRAINT tenant_default_user_type_fk
            FOREIGN KEY (id, default_user_type_id) REFERENCES rolebyte.user_type (tenant_id, id);
    END IF;
END $$;

-- The source gains a third value, workspaceDefault, so the check that allows only
-- the first two goes before any member is given the default; its replacement,
-- below, is added once every member holds a type.
ALTER TABLE rolebyte.user_account DROP CONSTRAINT IF EXISTS user_account_user_type_source;

-- Every tenant gets its default now; a member without a type receives it. The
-- procedures do the same for every tenant and arrival from here on.
DO $$
DECLARE
    v_tenant record;
    v_type   text;
BEGIN
    FOR v_tenant IN SELECT id FROM rolebyte.tenant WHERE default_user_type_id IS NULL LOOP
        SELECT id INTO v_type FROM rolebyte.user_type
         WHERE tenant_id = v_tenant.id AND lower(name) = 'member';
        IF v_type IS NULL THEN
            v_type := util.generate_ulid();
            INSERT INTO rolebyte.user_type (id, tenant_id, name, description)
            VALUES (v_type, v_tenant.id, 'Member', 'Holds nothing. What every member is until somebody gives them another.');
            INSERT INTO rolebyte.event (id, actor, tenant_id, kind, payload)
            VALUES (util.generate_ulid(), 'system:migration', v_tenant.id, 'userTypeDefined',
                    jsonb_build_object('userTypeId', v_type, 'name', 'Member',
                                       'description', 'Holds nothing. What every member is until somebody gives them another.',
                                       'permissions', '[]'::jsonb));
        END IF;
        UPDATE rolebyte.tenant SET default_user_type_id = v_type WHERE id = v_tenant.id;
        INSERT INTO rolebyte.event (id, actor, tenant_id, kind, payload)
        VALUES (util.generate_ulid(), 'system:migration', v_tenant.id, 'defaultUserTypeSet',
                jsonb_build_object('userTypeId', v_type, 'from', ''));
    END LOOP;

    INSERT INTO rolebyte.event (id, actor, tenant_id, user_id, kind, payload)
    SELECT util.generate_ulid(), 'system:migration', u.tenant_id, u.id, 'userTypeAssigned',
           jsonb_build_object('userTypeId', t.default_user_type_id, 'from', '', 'source', 'workspaceDefault')
      FROM rolebyte.user_account u
      JOIN rolebyte.tenant t ON t.id = u.tenant_id
     WHERE u.user_type_id IS NULL;

    UPDATE rolebyte.user_account u
       SET user_type_id = t.default_user_type_id, user_type_source = 'workspaceDefault'
      FROM rolebyte.tenant t
     WHERE t.id = u.tenant_id AND u.user_type_id IS NULL;
END $$;

-- A member always has a type and a source.
ALTER TABLE rolebyte.user_account
    ALTER COLUMN user_type_id SET NOT NULL,
    ALTER COLUMN user_type_source SET NOT NULL;
ALTER TABLE rolebyte.user_account
    ADD CONSTRAINT user_account_user_type_source
    CHECK (user_type_source IN ('administrator', 'corporateLoginDefault', 'workspaceDefault'));

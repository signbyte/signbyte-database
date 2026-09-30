-- V8: what a tenant has.
--
-- The permissions services declare are the same on every tenant of a
-- deployment. A tenant has only part of them: the features it was given when it
-- was registered, paid for or otherwise. A tenant's own roles may tick any
-- declared permission, but a tick reaches a token only while the tenant has the
-- permission's feature.
--
-- An entitlement names a whole service (the feature left empty) or one feature
-- of it, and a feature covers the features nested under it: `task` covers
-- `task/attachment`. Naming a whole service is what keeps a permission a later
-- release declares working from its first day, with nothing to add per tenant.
--
-- Taking an entitlement away deletes nothing a tenant configured. Its roles keep
-- every tick; the ticks simply stop reaching tokens, and come back unchanged when
-- the entitlement does.
--
-- Current state, derived from the event stream exactly as a grant is:
-- entitling again flips the row back and the events keep both moments.
--
-- Only the deployment's operator entitles a tenant. The procedures that write
-- this table are not executable by the register's own role, so no request a
-- tenant can make reaches them.
CREATE TABLE IF NOT EXISTS rolebyte.tenant_entitlement (
    id          text        NOT NULL PRIMARY KEY,
    tenant_id   text        NOT NULL REFERENCES rolebyte.tenant (id),
    service_key text        NOT NULL REFERENCES rolebyte.service (key),
    feature_key text        NOT NULL DEFAULT '',
    state       text        NOT NULL DEFAULT 'entitled',
    entitled_at timestamptz NOT NULL DEFAULT now(),
    revoked_at  timestamptz NULL,
    CONSTRAINT tenant_entitlement_state_check CHECK (state IN ('entitled', 'revoked')),
    CONSTRAINT tenant_entitlement_unique UNIQUE (tenant_id, service_key, feature_key)
);

-- Guarded for replay.
DO $$
BEGIN
    -- Empty, meaning the whole service, or a feature spelled as a declared
    -- permission spells one.
    IF NOT EXISTS (
        SELECT 1 FROM pg_constraint
         WHERE conname = 'tenant_entitlement_feature_shape'
           AND conrelid = 'rolebyte.tenant_entitlement'::regclass
    ) THEN
        ALTER TABLE rolebyte.tenant_entitlement
            ADD CONSTRAINT tenant_entitlement_feature_shape
            CHECK (feature_key = '' OR rolebyte.is_permission_feature(feature_key));
    END IF;
END $$;

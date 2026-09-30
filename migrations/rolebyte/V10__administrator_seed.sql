-- V10: the last administrator seed applied to each tenant.
--
-- A deployment the operator runs on the customer's own machines has no console
-- to recover a tenant whose only administrator has left. The way back is an
-- environment value naming the person who becomes an administrator, read when
-- the service starts.
--
-- A value in the environment is read on every start, so it must act once: the
-- same value on the next restart does nothing, while a new value makes its
-- person an administrator whatever anyone else's state. This table is how the
-- register tells the two apart. It holds one row per tenant, the value applied
-- last and when, replaced by the next new value. What happened is in the event
-- stream; this row only answers "was this value already applied here".
--
-- Nobody is ever removed by a seed. The new administrator removes the old one,
-- through the ordinary acts, which keep the tenant from being left without one.
CREATE TABLE IF NOT EXISTS rolebyte.administrator_seed (
    tenant_id   text        NOT NULL PRIMARY KEY REFERENCES rolebyte.tenant (id),
    subject_key text        NOT NULL,
    applied_at  timestamptz NOT NULL DEFAULT now()
);

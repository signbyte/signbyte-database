-- V20: helpers — named machine members through which a person works from an
-- assistant.
--
-- A helper is a member of the tenant keyed `svc:assistant-<ULID>`, made and
-- named by an administrator, holding roles as a person does. A person reaches
-- it only with a key of their own for it, and only while they are on its list
-- of who may use it; the sign-in service reads that list when it exchanges such
-- a key. A helper's name is how history names what it did, so two helpers of a
-- tenant are never named alike.
--
-- * helper_user — who may use a helper: one row per person, current state only;
--   the events keep each change. Both ends are members of the same tenant.
-- * a helper's name is unique in its tenant, ignoring case, among the helpers not
--   removed, so a removed helper's name may be given again.

CREATE TABLE IF NOT EXISTS rolebyte.helper_user (
    tenant_id text        NOT NULL,
    helper_id text        NOT NULL,
    user_id   text        NOT NULL,
    added_at  timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT helper_user_pkey PRIMARY KEY (helper_id, user_id),
    CONSTRAINT helper_user_helper_in_tenant FOREIGN KEY (tenant_id, helper_id)
        REFERENCES rolebyte.user_account (tenant_id, id),
    CONSTRAINT helper_user_user_in_tenant FOREIGN KEY (tenant_id, user_id)
        REFERENCES rolebyte.user_account (tenant_id, id)
);

CREATE INDEX IF NOT EXISTS helper_user_user_idx ON rolebyte.helper_user (user_id);

CREATE UNIQUE INDEX IF NOT EXISTS user_account_helper_name_per_tenant
    ON rolebyte.user_account (tenant_id, lower(display_name))
    WHERE subject_key LIKE 'svc:assistant-%' AND status <> 'revoked';

-- V25: the person the deployment's settings name, as last applied.
--
-- A deployment's settings can name one person who should administer it. The register
-- applies that value with `deployment_admin_apply`, and applies it once: so that a
-- restart with the same value does nothing, and an entry someone took off the list
-- by hand is not put back, the deployment's row remembers which person was applied
-- last, in which mode, and when. The three columns are empty until a value has been
-- applied, and each new value replaces the last one. The same person applied in
-- another mode is a new value.
--
-- The comment on the list of the deployment's administrators is written again so
-- that it names `deployment_admin_apply` among the procedures that write it.
-- Nothing else changes. The columns are written only by `deployment_admin_apply`,
-- and the register's own role has no access to the tables.

ALTER TABLE rolebyte.deployment
    ADD COLUMN IF NOT EXISTS admin_setting_subject_key text        NULL,
    ADD COLUMN IF NOT EXISTS admin_setting_applied_at  timestamptz NULL,
    ADD COLUMN IF NOT EXISTS admin_setting_mode        text        NULL;

COMMENT ON TABLE rolebyte.deployment IS
    'The deployment''s own record: at most one row, present only once a company is marked. Written only by rolebyte.deployment_company_mark, rolebyte.deployment_company_set and rolebyte.deployment_admin_apply.';
COMMENT ON COLUMN rolebyte.deployment.admin_setting_subject_key IS
    'The subject key of the person last applied from the deployment''s settings; empty until one has been applied.';
COMMENT ON COLUMN rolebyte.deployment.admin_setting_mode IS
    'The mode, saas or local, in which the person last applied from the deployment''s settings was applied; empty until one has been applied.';
COMMENT ON TABLE rolebyte.deployment_admin IS
    'The people who administer the whole deployment: one account each, in the deployment''s own company. Written only by rolebyte.deployment_admin_add, rolebyte.deployment_admin_remove, rolebyte.deployment_admin_apply and rolebyte.user_revoke.';
COMMENT ON COLUMN rolebyte.deployment.admin_setting_applied_at IS
    'When the person last applied from the deployment''s settings was applied; empty until one has been applied.';

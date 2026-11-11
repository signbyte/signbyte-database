-- V24: the deployment's own company and the people who administer the deployment.
--
-- A deployment is run by one company of its own. The register keeps which tenant that
-- is in a record that holds at most one row: it exists only once a company has been
-- marked, and a marked company is never replaced. Beside it sits a short list of
-- people who administer the whole deployment. Each entry is one person's account in
-- that company, so removing the person from the company (revoking the account) ends
-- the right at the next answer without anyone touching the list.
--
-- Nothing a tenant can do writes either table. They are written only by the
-- procedures `deployment_company_mark`, `deployment_company_set`,
-- `deployment_admin_add`, `deployment_admin_remove` and `user_revoke`, and the
-- register's own role has no access to the tables.

CREATE TABLE IF NOT EXISTS rolebyte.deployment (
    only_row          boolean     NOT NULL DEFAULT true PRIMARY KEY,
    company_tenant_id text        NOT NULL REFERENCES rolebyte.tenant (id),
    marked_at         timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT deployment_one_row CHECK (only_row)
);

COMMENT ON TABLE rolebyte.deployment IS
    'The deployment''s own record: at most one row, present only once a company is marked. Written only by rolebyte.deployment_company_mark and rolebyte.deployment_company_set.';
COMMENT ON COLUMN rolebyte.deployment.only_row IS
    'Always true; with the primary key it keeps the table to one row.';
COMMENT ON COLUMN rolebyte.deployment.company_tenant_id IS
    'The tenant that is the company running the deployment.';
COMMENT ON COLUMN rolebyte.deployment.marked_at IS
    'When the company was marked.';

CREATE TABLE IF NOT EXISTS rolebyte.deployment_admin (
    user_id    text        NOT NULL PRIMARY KEY REFERENCES rolebyte.user_account (id),
    added_by   text        NOT NULL,
    added_from text        NOT NULL,
    added_at   timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT deployment_admin_added_from_check CHECK (added_from IN ('settings', 'screen'))
);

COMMENT ON TABLE rolebyte.deployment_admin IS
    'The people who administer the whole deployment: one account each, in the deployment''s own company. Written only by rolebyte.deployment_admin_add, rolebyte.deployment_admin_remove and rolebyte.user_revoke.';
COMMENT ON COLUMN rolebyte.deployment_admin.user_id IS
    'The person''s account in the deployment''s own company.';
COMMENT ON COLUMN rolebyte.deployment_admin.added_by IS
    'Who made the entry, as the actor of the act.';
COMMENT ON COLUMN rolebyte.deployment_admin.added_from IS
    'Where the entry was made: settings (the deployment''s own settings) or screen (a person using the deployment''s screen).';
COMMENT ON COLUMN rolebyte.deployment_admin.added_at IS
    'When the entry was made.';

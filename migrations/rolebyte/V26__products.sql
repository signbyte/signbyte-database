-- V26: the products a deployment sells, and which of them each company has.
--
-- A product is a sold bundle: it gives a company some services (a whole service, or one
-- feature of it), may need other products to be had first, and owns the accounts of the
-- programs that serve it (`svc:<client id>`). A company has a product once the product is
-- ticked for it; ticking gives the entitlements the product carries and makes its service
-- accounts active members, and unticking takes them away again.
--
-- The four catalog tables (`product`, `product_entitlement`, `product_requirement` and
-- `product_account`) are written only by `rolebyte.products_register`, which is run as the
-- location's owner. `tenant_product` is written only by the procedures that tick and
-- untick. The register's own role has no access to any of them.
CREATE TABLE IF NOT EXISTS rolebyte.product (
    key           text        NOT NULL PRIMARY KEY,
    display_name  text        NOT NULL,
    registered_by text        NOT NULL,
    registered_at timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT product_key_check CHECK (key ~ '^[a-z][a-z0-9-]{0,63}$')
);
COMMENT ON TABLE rolebyte.product IS
    'The products a deployment sells. Written only by rolebyte.products_register.';
COMMENT ON COLUMN rolebyte.product.key IS
    'The product''s key: one lower-case word of letters, digits and hyphens.';
COMMENT ON COLUMN rolebyte.product.display_name IS
    'The name the product is shown under.';
COMMENT ON COLUMN rolebyte.product.registered_by IS
    'Who last added or changed the product, as the actor of the act.';
COMMENT ON COLUMN rolebyte.product.registered_at IS
    'When the product was added or last changed.';

CREATE TABLE IF NOT EXISTS rolebyte.product_entitlement (
    product_key text NOT NULL REFERENCES rolebyte.product (key) ON DELETE CASCADE,
    service_key text NOT NULL REFERENCES rolebyte.service (key),
    feature_key text NOT NULL DEFAULT '',
    PRIMARY KEY (product_key, service_key, feature_key)
);
COMMENT ON TABLE rolebyte.product_entitlement IS
    'What a product gives a company: a whole service (empty feature) or one feature of it. Written only by rolebyte.products_register.';
COMMENT ON COLUMN rolebyte.product_entitlement.feature_key IS
    'The feature given; empty for the whole service.';

CREATE TABLE IF NOT EXISTS rolebyte.product_requirement (
    product_key  text NOT NULL REFERENCES rolebyte.product (key) ON DELETE CASCADE,
    requires_key text NOT NULL REFERENCES rolebyte.product (key),
    PRIMARY KEY (product_key, requires_key),
    CONSTRAINT product_requirement_differ CHECK (product_key <> requires_key)
);
COMMENT ON TABLE rolebyte.product_requirement IS
    'The products a product needs: a company has the product only while it has these. Written only by rolebyte.products_register.';
COMMENT ON COLUMN rolebyte.product_requirement.requires_key IS
    'The product that is needed.';

CREATE TABLE IF NOT EXISTS rolebyte.product_account (
    product_key  text  NOT NULL REFERENCES rolebyte.product (key) ON DELETE CASCADE,
    subject_key  text  NOT NULL,
    display_name text  NOT NULL,
    roles        jsonb NOT NULL DEFAULT '[]'::jsonb,
    PRIMARY KEY (product_key, subject_key),
    CONSTRAINT product_account_subject_key_check CHECK (starts_with(subject_key, 'svc:'))
);
COMMENT ON TABLE rolebyte.product_account IS
    'The service accounts of each product: the members a company that has the product gets. A subject key may be listed under several products. Written only by rolebyte.products_register.';
COMMENT ON COLUMN rolebyte.product_account.subject_key IS
    'The account''s subject key, svc:<client id>.';
COMMENT ON COLUMN rolebyte.product_account.display_name IS
    'The name the account is shown under in a company.';
COMMENT ON COLUMN rolebyte.product_account.roles IS
    'The levels the account holds in a company that has the product: an array of {service, group, level}.';

CREATE TABLE IF NOT EXISTS rolebyte.tenant_product (
    tenant_id   text        NOT NULL REFERENCES rolebyte.tenant (id),
    product_key text        NOT NULL REFERENCES rolebyte.product (key),
    state       text        NOT NULL DEFAULT 'ticked',
    ticked_at   timestamptz NOT NULL DEFAULT now(),
    unticked_at timestamptz NULL,
    PRIMARY KEY (tenant_id, product_key),
    CONSTRAINT tenant_product_state_check CHECK (state IN ('ticked', 'unticked'))
);
COMMENT ON TABLE rolebyte.tenant_product IS
    'Which products each company has. Written only by the procedures that tick and untick a product.';
COMMENT ON COLUMN rolebyte.tenant_product.state IS
    'ticked while the company has the product, unticked after it was taken away.';
COMMENT ON COLUMN rolebyte.tenant_product.ticked_at IS
    'When the product was last ticked for the company.';
COMMENT ON COLUMN rolebyte.tenant_product.unticked_at IS
    'When the product was last unticked for the company; empty while it has never been.';

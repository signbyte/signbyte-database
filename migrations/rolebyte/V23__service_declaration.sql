-- V23: which client declared which service, and when.
--
-- A service may describe itself to the register: its levels and the permissions
-- it enforces. This table remembers, for each service key and each declaring
-- client, the first and the latest time such a declaration was accepted. A
-- service key can be declared by more than one client, so the pair is the key.
-- `declared_by` is the declaring client's service subject (`svc:<client id>`).
--
-- Nothing reads it yet beyond the deployment's own screens. It is written only
-- by `rolebyte.service_declare`; the register's own role has no access to the
-- table, as with every other table of this location.
CREATE TABLE IF NOT EXISTS rolebyte.service_declaration (
    service_key       text        NOT NULL REFERENCES rolebyte.service (key),
    declared_by       text        NOT NULL,
    first_declared_at timestamptz NOT NULL DEFAULT now(),
    last_declared_at  timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (service_key, declared_by)
);

COMMENT ON TABLE rolebyte.service_declaration IS
    'Per service key and declaring client: when a declaration of the service was first and last accepted. Written only by rolebyte.service_declare.';
COMMENT ON COLUMN rolebyte.service_declaration.declared_by IS
    'The declaring client''s service subject, svc:<client id>.';

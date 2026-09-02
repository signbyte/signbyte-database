-- V1: identity store for the authentication service — PERSON + CREDENTIALS model.
--
-- A natural person is identified by the eIDAS unique identifier (national id,
-- e.g. PNOLV-321846-14724). The SAME person may authenticate through several
-- methods (eParaksts Mobile, Web eID card, eID-scan) — each method hands the auth
-- service a DIFFERENT `idp_sub` (eParaksts returns an opaque hash; Web eID returns
-- the national id). Keying the identity on `idp_sub` therefore produced duplicate
-- identities for one human. This schema fixes that:
--
--   * `identity.person`     — the natural person, keyed on the national id.
--   * `identity.credential` — one row per auth-method handle (`idp_sub`),
--                             linking to its person. One person ↔ many credentials.
--
-- The internal subject returned to the rest of the platform is the PERSON id, so
-- a person resolves to ONE stable subject regardless of how they logged in.
--
-- Implements the data-layer model: per-domain `identity` schema, ULID primary
-- keys, owner/service-role split. The service NEVER touches tables directly —
-- only the SECURITY DEFINER procedures, invoked by the EXECUTE-only role
-- `authbyte_public`. The schema is owned by the migrating role (the DB owner).

CREATE SCHEMA IF NOT EXISTS identity;

-- identity.person — the natural person, keyed on the eIDAS national id.
-- `tenant_id` is nullable from day one for a later multi-tenant (B2B) move.
CREATE TABLE IF NOT EXISTS identity.person (
    person_sub    text        PRIMARY KEY DEFAULT util.generate_ulid(),
    national_id   text        NOT NULL UNIQUE,   -- eIDAS unique id (== serial_number)
    tenant_id     text        NULL,
    name          text        NOT NULL DEFAULT '',
    given_name    text        NOT NULL DEFAULT '',
    family_name   text        NOT NULL DEFAULT '',
    created_at    timestamptz NOT NULL DEFAULT now(),
    updated_at    timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_person_tenant ON identity.person (tenant_id) WHERE tenant_id IS NOT NULL;

-- identity.credential — one IdP/method handle (idp_sub) per row, linked to a
-- person. login_method records which method this handle came from (audit / step-up).
CREATE TABLE IF NOT EXISTS identity.credential (
    idp_sub      text        PRIMARY KEY,
    person_sub   text        NOT NULL REFERENCES identity.person(person_sub) ON DELETE CASCADE,
    login_method text        NOT NULL DEFAULT '',
    created_at   timestamptz NOT NULL DEFAULT now(),
    updated_at   timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_credential_person ON identity.credential (person_sub);

-- ---------------------------------------------------------------------------
-- Service role + least-privilege grants.
-- ---------------------------------------------------------------------------
-- `authbyte_public` is the ONLY role the running auth service uses (its DSN). It
-- can connect + EXECUTE the schema's procedures and has NO table/sequence
-- privileges. Separation of duty: the owner runs migrations; `authbyte_public`
-- runs the service. (Human/operator read is a separate axis — the per-schema
-- identity_read_role, which reaches this PII schema and no other; admins are
-- superusers.) The role itself is
-- created (with its password) outside the migrations by provision-roles.sh from
-- the environment, keeping credentials out of versioned migrations. This
-- migration only assigns its privileges below.

REVOKE ALL ON SCHEMA identity FROM PUBLIC;
REVOKE ALL ON ALL TABLES IN SCHEMA identity FROM PUBLIC;
REVOKE ALL ON identity.person     FROM authbyte_public;
REVOKE ALL ON identity.credential FROM authbyte_public;

GRANT USAGE ON SCHEMA identity TO authbyte_public;

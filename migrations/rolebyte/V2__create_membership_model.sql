-- V2: the membership model — tenants, users, per-service role definitions,
-- assignments, and the append-only event stream.
--
-- Design intent, in one paragraph: current state lives in small mutable
-- tables (tenant / user_account / assignment) for fast reads, but every
-- change that produced it is FIRST an attributed, timestamped event. The
-- event stream is the source of truth for "who could do what, when" — the
-- seat-count/audit query a billing consumer runs later — so it is
-- append-only at the database level: no procedure mutates it AND a guard
-- trigger raises on UPDATE/DELETE, so even owner-privileged code paths
-- cannot rewrite history by accident.
--
-- Naming notes: the spec entity `user` is stored as `user_account` and the
-- role coordinates as `role_group`/`role_level` (USER and GROUP are reserved
-- words; quoting them forever is a tax on every query).

-- The paying organisation.
CREATE TABLE IF NOT EXISTS rolebyte.tenant (
    id         text        NOT NULL PRIMARY KEY,
    name       text        NOT NULL,
    status     text        NOT NULL DEFAULT 'active',
    created_at timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT tenant_status_check CHECK (status IN ('active', 'suspended'))
);

-- The person, per tenant. `subject_key` is TYPED (e.g. `pno:<national-code>`
-- now; `oidc:<issuer>:<subject>` or `invite:<email>` later) so the model
-- never bakes in one identity scheme — a new credential type is a new key
-- prefix, not a migration. `anonymised_at` exists from day one so a future
-- data-retention ruling is a data change, not a schema change.
CREATE TABLE IF NOT EXISTS rolebyte.user_account (
    id            text        NOT NULL PRIMARY KEY,
    tenant_id     text        NOT NULL REFERENCES rolebyte.tenant (id),
    subject_key   text        NOT NULL,
    display_name  text        NOT NULL,
    status        text        NOT NULL DEFAULT 'invited',
    anonymised_at timestamptz NULL,
    created_at    timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT user_account_status_check CHECK (status IN ('invited', 'active', 'revoked')),
    CONSTRAINT user_account_subject_per_tenant UNIQUE (tenant_id, subject_key)
);

CREATE INDEX IF NOT EXISTS user_account_subject_idx ON rolebyte.user_account (subject_key);
CREATE INDEX IF NOT EXISTS user_account_tenant_idx  ON rolebyte.user_account (tenant_id);

-- A consumer service registering itself. Roles are DATA, defined per
-- service — this is what makes this a role service and not a user table.
CREATE TABLE IF NOT EXISTS rolebyte.service (
    key          text        NOT NULL PRIMARY KEY,
    display_name text        NOT NULL,
    created_at   timestamptz NOT NULL DEFAULT now()
);

-- One role a service defines: the (group, level) pair its routes gate on.
CREATE TABLE IF NOT EXISTS rolebyte.role_definition (
    id          text        NOT NULL PRIMARY KEY,
    service_key text        NOT NULL REFERENCES rolebyte.service (key),
    role_group  text        NOT NULL,
    role_level  text        NOT NULL,
    description text        NOT NULL DEFAULT '',
    created_at  timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT role_definition_unique UNIQUE (service_key, role_group, role_level)
);

-- Current assignment state — a fast view DERIVED from the event stream (the
-- verify suite asserts the two never disagree). Re-granting a revoked pair
-- flips this row back; the events keep both moments.
CREATE TABLE IF NOT EXISTS rolebyte.assignment (
    id                 text        NOT NULL PRIMARY KEY,
    user_id            text        NOT NULL REFERENCES rolebyte.user_account (id),
    role_definition_id text        NOT NULL REFERENCES rolebyte.role_definition (id),
    state              text        NOT NULL DEFAULT 'granted',
    granted_at         timestamptz NOT NULL DEFAULT now(),
    revoked_at         timestamptz NULL,
    CONSTRAINT assignment_state_check CHECK (state IN ('granted', 'revoked')),
    CONSTRAINT assignment_unique UNIQUE (user_id, role_definition_id)
);

CREATE INDEX IF NOT EXISTS assignment_user_idx ON rolebyte.assignment (user_id);

-- The append-only history. Every membership/role change lands here with who
-- did it and when; `tenant_id` is NULL only for tenant-independent events
-- (service registration, role definition). No foreign keys by design: the
-- log must stay valid even if a future ruling anonymises or archives the
-- rows it refers to.
CREATE TABLE IF NOT EXISTS rolebyte.event (
    id        text        NOT NULL PRIMARY KEY,
    at        timestamptz NOT NULL DEFAULT now(),
    actor     text        NOT NULL,
    tenant_id text        NULL,
    user_id   text        NULL,
    kind      text        NOT NULL,
    payload   jsonb       NOT NULL DEFAULT '{}'::jsonb
);

CREATE INDEX IF NOT EXISTS event_tenant_at_idx ON rolebyte.event (tenant_id, at);
CREATE INDEX IF NOT EXISTS event_user_idx      ON rolebyte.event (user_id);

-- The guard: history cannot be rewritten, by anyone, on any code path.
-- Procedures never mutate `event`; this trigger is the second, independent
-- layer that raises even for owner-privileged sessions.
CREATE OR REPLACE FUNCTION rolebyte.event_append_only()
RETURNS trigger
LANGUAGE plpgsql
-- No schema object is resolved here; pinned for uniformity, pg_temp last.
SET search_path = pg_temp
AS $$
BEGIN
    RAISE EXCEPTION 'rolebyte.event is append-only: % is not allowed', TG_OP
        USING ERRCODE = 'raise_exception';
END;
$$;

DROP TRIGGER IF EXISTS event_append_only ON rolebyte.event;
CREATE TRIGGER event_append_only
    BEFORE UPDATE OR DELETE ON rolebyte.event
    FOR EACH ROW EXECUTE FUNCTION rolebyte.event_append_only();

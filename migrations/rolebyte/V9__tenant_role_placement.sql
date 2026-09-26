-- V9: how many times another service has placed a tenant's role.
--
-- A tenant's roles are granted here, across the whole tenant. A service that
-- owns its own objects may also place the same role on one of them — a person
-- is the manager of one project and a worker on another — and those placements
-- live with the objects, in that service, never here. This register does not
-- know what the objects are and does not learn it.
--
-- What it does learn is a count: how many placements of each role a service
-- holds. A role in use is not removed from under the people using it, so a
-- delete is refused while a role is held here OR placed elsewhere, and the
-- refusal can say how many.
--
-- The reporter is the service's own member row in the tenant: a service reaches
-- a tenant the way a person does, by being a member of it. So the count belongs
-- to whoever reported it, taken from the caller and never from what it sent, and
-- a service whose membership is revoked stops counting.
--
-- Current state only, replaced whole by each report. A count is derived from the
-- placements the service keeps, not an act anybody performed, so it writes no
-- history; the acts that change it are recorded where they happen.
CREATE TABLE IF NOT EXISTS rolebyte.tenant_role_placement (
    tenant_id      text        NOT NULL,
    tenant_role_id text        NOT NULL,
    reporter_id    text        NOT NULL,
    placements     integer     NOT NULL,
    reported_at    timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT tenant_role_placement_pkey PRIMARY KEY (tenant_role_id, reporter_id),
    -- Only roles in use have a row: a report of zero removes it.
    CONSTRAINT tenant_role_placement_count_check CHECK (placements > 0),
    -- The tenant is part of both references, as it is for a grant, so a count
    -- can never join a role of one tenant to a reporter of another.
    CONSTRAINT tenant_role_placement_role
        FOREIGN KEY (tenant_id, tenant_role_id) REFERENCES rolebyte.tenant_role (tenant_id, id),
    CONSTRAINT tenant_role_placement_reporter
        FOREIGN KEY (tenant_id, reporter_id) REFERENCES rolebyte.user_account (tenant_id, id)
);

CREATE INDEX IF NOT EXISTS tenant_role_placement_reporter_idx
    ON rolebyte.tenant_role_placement (tenant_id, reporter_id);

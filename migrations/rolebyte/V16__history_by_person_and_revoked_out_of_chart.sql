-- V16: a person's history read by who they are, and nobody who lost access left
-- sitting in the chart of authority.
--
-- A tenant's history is read a page at a time, newest first. Narrowed to one
-- person it keeps the lines that person wrote and the lines about them that no
-- person wrote — their arrival, the deployment's acts on them — so it is read
-- along two paths: by who acted, and by whom a line is about.
CREATE INDEX IF NOT EXISTS event_tenant_actor_at_idx
    ON rolebyte.event (tenant_id, actor, at DESC, id DESC);
CREATE INDEX IF NOT EXISTS event_tenant_user_at_idx
    ON rolebyte.event (tenant_id, user_id, at DESC, id DESC);

-- Taking a person's access away now takes them out of their position in the
-- same act. Before, the position kept them: the services' copy of the chart
-- already paired active people only, so nothing leaked, but the editor still
-- listed and counted them. Everyone already revoked leaves their position here,
-- with the line the act now writes, so the editor and the copy agree from the
-- first read after this migration.
WITH gone AS (
    DELETE FROM rolebyte.chart_holder h
     USING rolebyte.user_account u
     WHERE u.tenant_id = h.tenant_id
       AND u.id = h.user_id
       AND u.status = 'revoked'
    RETURNING h.tenant_id, h.user_id, h.position_id
)
INSERT INTO rolebyte.event (id, actor, tenant_id, user_id, kind, payload)
SELECT util.generate_ulid(), 'system:migration', g.tenant_id, g.user_id, 'chartPersonRemoved',
       jsonb_build_object('positionId', g.position_id, 'revoked', true)
  FROM gone g;

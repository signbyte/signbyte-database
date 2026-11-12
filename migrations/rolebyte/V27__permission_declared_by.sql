-- V27: a permission remembers the client that declared it, and the client that retired it.
--
-- When a service declares itself, each permission it names is stored with the
-- declaring client's service subject (`svc:<client id>`). Only that client may
-- later change the permission through a declaration; another client that names
-- the same key may repeat it unchanged but not alter it. The deployment's own
-- registration is not bound by this and never touches the column. A permission
-- no client has declared (one the deployment entered) holds null, and the first
-- client to declare it takes it over.
--
-- A permission also remembers who retired it. A declaration reinstates only a
-- retirement that a declaration of the same client made; a retirement the
-- deployment made (its own registration, or a change by hand) stays until the
-- deployment lifts it. So `retired_by` holds the client whose declaration retired
-- the permission, and is null while the permission is not retired and when the
-- deployment retired it.
ALTER TABLE rolebyte.service_permission ADD COLUMN IF NOT EXISTS declared_by text;
ALTER TABLE rolebyte.service_permission ADD COLUMN IF NOT EXISTS retired_by text;

COMMENT ON COLUMN rolebyte.service_permission.declared_by IS
    'The service subject, svc:<client id>, of the client that declared the permission; null while no client has. Only that client changes the permission through a declaration.';
COMMENT ON COLUMN rolebyte.service_permission.retired_by IS
    'The service subject, svc:<client id>, of the client whose declaration retired the permission; null while it is not retired and when the deployment retired it. A declaration reinstates only a retirement of its own client.';

-- Where the history knows who declared a permission, say so: a permission with no
-- declarer whose `permissionDeclared` line was written by a service subject
-- (the earliest such line when there are several) is that client's. A permission
-- the history does not show a client declaring stays without a declarer.
UPDATE rolebyte.service_permission sp
   SET declared_by = e.actor
  FROM (SELECT DISTINCT ON (payload->>'permission') payload->>'permission' AS permission, actor
          FROM rolebyte.event
         WHERE kind = 'permissionDeclared' AND left(actor, 4) = 'svc:'
         ORDER BY payload->>'permission', at, id) e
 WHERE sp.declared_by IS NULL
   AND e.permission = sp.service_key || '/' || sp.feature_key || ':' || sp.act;

-- The vocabulary function gains a third argument, the declaring client. A
-- function is found by its argument list, so the old two-argument form is
-- removed here; leaving it beside the new one would make a call with two
-- arguments ambiguous. The repeatable file creates the new form right after.
DROP FUNCTION IF EXISTS rolebyte.config_vocabulary(text, jsonb);

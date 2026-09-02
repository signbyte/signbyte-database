-- A chain root (an uploaded source) has at most ONE signed container. Each
-- signature co-signs into that single container, which keep-latest replaces in
-- place (same row), so the constraint holds for the container's whole life.
--
-- Without this, two parties who begin from the same source at the same moment
-- each create their own container — two divergent single-signature results for
-- what must be one shared, multi-signature document. This index makes the second
-- concurrent creation fail (the insert procedure turns that into a chain-advanced
-- signal), so the loser re-resolves the existing container and co-signs into it.
-- Scoped to live containers: a purged/superseded (deleted) container never blocks a
-- fresh one, matching the create-conflict and container-lookup paths (both ignore
-- deleted rows). This migration assumes at most one live container per chain already
-- holds; it does NOT collapse pre-existing duplicates (that would drop a real
-- signature — a merge, not a delete, and infeasible in SQL). The runtime guard this
-- index backs prevents new duplicates from arising.
CREATE UNIQUE INDEX IF NOT EXISTS uq_one_container_per_chain
    ON document.document (parent_id)
    WHERE kind = 'container' AND status <> 'deleted';

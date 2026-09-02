-- V6: what the retention sweep needs — the retention horizon, and its indexes.
--
-- `retention_until` is the instant the envelope's documents stop being downloadable,
-- recorded when the envelope reaches a terminal state. It is NOT derivable here: the
-- documents live in another service and their retention rolls forward every time a
-- signature lands, so the workflow service reads the final value at the transition
-- and pins it. The keep window is measured from THIS instant plus a grace, so a
-- tracking page cannot outlive its download or vanish before it.
--
-- NULL means the instant was never recorded — a terminal envelope whose read failed.
-- The sweep leaves those alone rather than guessing: waiting is recoverable, deleting
-- early is not.
--
-- The indexes serve the sweep's two delete stages, which each order by a timestamp
-- inside a narrow slice of statuses — an ordering the plain status index cannot
-- serve, so without them every pass sorts the largest schema in the database.
-- Partial, because only those slices are ever swept. (The stage that expires an
-- envelope past its own deadline is served by the existing expiry index.)

ALTER TABLE envelope.envelope
    ADD COLUMN IF NOT EXISTS retention_until timestamptz;

CREATE INDEX IF NOT EXISTS idx_envelope_terminal_retention
    ON envelope.envelope (retention_until)
    WHERE status IN ('completed', 'declined', 'cancelled', 'expired');

CREATE INDEX IF NOT EXISTS idx_envelope_draft_created
    ON envelope.envelope (created_at)
    WHERE status = 'draft';

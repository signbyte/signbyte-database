-- V5: drop the single-column status index — nothing reads it, every transition writes it.
--
-- No procedure filters envelopes by status on its own: status always appears together
-- with the owner or the caller's slot, where the owner/identity indexes do the work and
-- the status test is a cheap filter on the rows already found. A seven-value column is
-- also a poor index key by itself. Meanwhile every state transition rewrites this
-- index's entry for the envelope (two to three transitions per envelope in practice).
-- Cost without benefit, so it goes. The expiry index stays: whether envelopes expire
-- at all is a separate decision, and a sweep would be its reader.
DROP INDEX IF EXISTS envelope.idx_envelope_status;

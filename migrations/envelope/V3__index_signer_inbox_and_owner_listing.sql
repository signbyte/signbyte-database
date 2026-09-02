-- V3: index the two listing queries by the order they page in.
--
-- Both listings ask for the newest 50 rows of ONE person: the signer inbox
-- (list_signing_tasks — the slots bound to the caller's identity, newest envelope
-- first) and the owner's dashboard (list_envelopes — the owner's envelopes, newest
-- first). Neither had an index that starts with the person AND continues in the
-- paging order, so the planner walked the envelope primary key backwards, probing
-- slots on the way, until it had found 50 matches. That is quick for a person who is
-- on thousands of envelopes and slow for everybody else: with few matches the walk
-- covers most of the table, and the cost grows with the whole table rather than with
-- the caller's own rows (measured on a seeded copy: an ordinary signer's inbox went
-- from 1.5 ms at 2.5k envelopes to 160 ms at 640k; a heavy signer stayed under 10 ms).
--
-- With the person as the leading column and the paging key as the second, the
-- index already lists a caller's rows newest-first, so the query reads its 50 and
-- stops — the same cost for a signer with a dozen tasks and one with thousands
-- (measured: about 1 ms and 3 ms at 640k envelopes). A single-column index on the
-- identity alone is NOT equivalent: it fixes the ordinary signer but makes the heavy
-- one fetch and sort every row first (46–58 ms measured), so the composite is the fix.
--
-- signer_slot: partial, because the owner's own slot carries identity_ref NULL and the
-- inbox matches a concrete identity — those rows can never satisfy the query and would
-- only make the index bigger.
CREATE INDEX IF NOT EXISTS idx_slot_identity_envelope
    ON envelope.signer_slot (identity_ref, envelope_id DESC)
    WHERE identity_ref IS NOT NULL;

-- envelope: owner + id in paging order. This makes the single-column owner index
-- redundant — any lookup by owner alone is served by the leading column here — so it
-- is dropped rather than maintained twice on every write.
CREATE INDEX IF NOT EXISTS idx_envelope_owner_id
    ON envelope.envelope (owner, id DESC);
DROP INDEX IF EXISTS envelope.idx_envelope_owner;

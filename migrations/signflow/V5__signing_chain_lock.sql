-- V5: signing.chain_lock — a short-lived "one active signer per chain" gate.
--
-- A PAdES signature is an incremental update embedded IN the PDF (signature N+1 signs
-- signature N's bytes), so two signers co-signing the same PDF at the same time
-- produce two divergent single-signature PDFs that cannot be merged (unlike an ASiC-E
-- container, whose parallel XAdES signatures merge). To keep the concurrent case sane,
-- a PAdES co-sign takes a short lock on its chain at signing start: whoever acquires it
-- signs first; a second signer is told to try again in a moment and then signs the
-- now-current PDF (a clean incremental co-signature).
--
-- This is a UX gate, not the correctness floor: the document store's one-signed-PDF-
-- per-chain constraint remains the backstop. The lock is time-bounded (expires_at) so
-- an abandoned or crashed signing never wedges the chain — an expired lock is freely
-- taken over. Accessed ONLY via the SECURITY DEFINER acquire/release procedures
-- (R__signflow_procedures.sql); the EXECUTE-only signing_public role gets no table
-- privileges. No cross-schema FK — chain_key is a plain id (an envelope id).

CREATE TABLE IF NOT EXISTS signing.chain_lock (
    chain_key   text        PRIMARY KEY,   -- the co-sign chain (the envelope id)
    holder_slot text        NOT NULL,      -- the slot currently signing (the lock owner)
    holder_ref  text        NOT NULL,      -- the holding job/caller ref (observability only)
    expires_at  timestamptz NOT NULL       -- TTL backstop; an expired lock is freely taken over
);


REVOKE ALL ON signing.chain_lock FROM PUBLIC;
REVOKE ALL ON signing.chain_lock FROM signing_public;

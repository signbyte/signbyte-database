-- The co-sign download freeze: while a signing workflow over the chain is in
-- progress, the signed RESULT is not downloadable — it opens at the workflow's
-- terminal transition (the source/input stays downloadable throughout). The
-- flag lives on the CHAIN ROOT row, set and cleared by the workflow authority
-- (set at send, cleared at any terminal state); byte reads of non-source rows
-- refuse while it is set. Chain-level, same shape as legal_hold.
ALTER TABLE document.document ADD COLUMN IF NOT EXISTS result_frozen boolean NOT NULL DEFAULT false;

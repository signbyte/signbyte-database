-- V3: carry the login⇒signing binding on the durable records, and realign the
-- signing-flow vocabulary with the current method/flow names.
--
-- The login method that authenticated the session, together with the flow_used
-- already on signature_record, is the precise binding evidence ("authenticated via
-- X, signed via Y"). Only login_method + loa reach the orchestrator in the token
-- (no acr/amr); there is no coarse binding-identity class. Adding nullable text
-- columns with no default is the metadata-only path (no table rewrite).

ALTER TABLE signing.signing_job
    ADD COLUMN IF NOT EXISTS login_method text,
    ADD COLUMN IF NOT EXISTS loa          text;

ALTER TABLE signing.signature_record
    ADD COLUMN IF NOT EXISTS login_method text,
    ADD COLUMN IF NOT EXISTS loa          text;

-- Realign the flow CHECK to the current flow names. The names this table was
-- created with (eid / mobile / cloudEseal) predate the method/flow name alignment;
-- the service now uses webEid / eparakstsMobile / eparakstsMobileEseal. Drop + add
-- so the constraint matches the values the service actually writes.
ALTER TABLE signing.signing_job DROP CONSTRAINT IF EXISTS ck_signing_job_flow;
ALTER TABLE signing.signing_job
    ADD CONSTRAINT ck_signing_job_flow
    CHECK (flow IN ('webEid', 'eidScan', 'eparakstsMobile', 'eparakstsMobileEseal', 'csc'));

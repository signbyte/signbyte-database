-- V6: the CSC signing flow is two flows, named for how the eID card is read.
--
-- `cscEidScan` reads the card with a phone (eID Scan); `cscEidPlugin` reads it in a
-- card reader through the provider's own browser extension. The single `csc` they
-- replace never ran in a deployment, but development databases hold signing jobs
-- written with it, so it stays a legal STORED value: a job's history is never
-- rewritten. New writes are refused by the signing procedures, which list only the
-- current flows.

ALTER TABLE signing.signing_job DROP CONSTRAINT IF EXISTS ck_signing_job_flow;
ALTER TABLE signing.signing_job
    ADD CONSTRAINT ck_signing_job_flow
    CHECK (flow IN ('webEid', 'eidScan', 'eparakstsMobile', 'eparakstsMobileEseal', 'cscEidScan', 'cscEidPlugin',
                    'csc'));

-- V7: a signing job may use the `legacyEid` flow.
--
-- `legacyEid` signs with the eID card in the person's browser through the eParaksts
-- provider's own plugin, where `webEid` uses Web eID. The constraint is re-added with
-- the new name and every name it held before, `csc` among them: a job's history is
-- never rewritten. New writes are checked by the signing procedures, which list only
-- the current flows.

ALTER TABLE signing.signing_job DROP CONSTRAINT IF EXISTS ck_signing_job_flow;
ALTER TABLE signing.signing_job
    ADD CONSTRAINT ck_signing_job_flow
    CHECK (flow IN ('webEid', 'legacyEid', 'eidScan', 'eparakstsMobile', 'eparakstsMobileEseal', 'cscEidScan',
                    'cscEidPlugin', 'csc'));

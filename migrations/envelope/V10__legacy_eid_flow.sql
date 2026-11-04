-- V10: a signer slot may name the `legacyEid` flow.
--
-- `legacyEid` signs with the eID card in the person's browser through the eParaksts
-- provider's own plugin, where `webEid` uses Web eID. The constraint is re-added with
-- the new name and every name it held before, `csc` among them: nothing already
-- written is rewritten or refused. New writes are checked by `envelope.add_slot`,
-- which lists only the current flows.

ALTER TABLE envelope.signer_slot DROP CONSTRAINT IF EXISTS ck_slot_flow;
ALTER TABLE envelope.signer_slot
    ADD CONSTRAINT ck_slot_flow CHECK (flow IS NULL OR flow IN
      ('webEid', 'legacyEid', 'eidScan', 'eparakstsMobile', 'eparakstsMobileEseal', 'cscEidScan', 'cscEidPlugin',
       'csc'));

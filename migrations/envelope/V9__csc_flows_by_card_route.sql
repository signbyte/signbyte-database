-- V9: the CSC signing flow is two flows, named for how the eID card is read.
--
-- `cscEidScan` reads the card with a phone (eID Scan); `cscEidPlugin` reads it in a
-- card reader through the provider's own browser extension. The single `csc` they
-- replace never ran in a deployment, but development databases hold slots written
-- with it, so it stays a legal STORED value: nothing already written is rewritten or
-- refused. New writes are refused by `envelope.add_slot`, which lists only the
-- current flows.

ALTER TABLE envelope.signer_slot DROP CONSTRAINT IF EXISTS ck_slot_flow;
ALTER TABLE envelope.signer_slot
    ADD CONSTRAINT ck_slot_flow CHECK (flow IS NULL OR flow IN
      ('webEid', 'eidScan', 'eparakstsMobile', 'eparakstsMobileEseal', 'cscEidScan', 'cscEidPlugin',
       'csc'));

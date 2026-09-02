-- V2: signflow — the `validation` schema.
--
-- Backs the validation-answer half of signflow. The Orchestrator calls
-- eparaksts-signer's verbatim `validate`, NORMALIZES the DSS report to the portal's
-- normalized field set, and persists the normalized result here (the verbatim
-- report is never the evidence; eparaksts-signer stays DSS-faithful and stateless).
--
-- A separate schema from `signing`, but owned by the same service: the one
-- `signing_public` role gets USAGE here too. signature_id links to
-- signing.signature_record by PLAIN id (no cross-schema FK).
--
-- Prerequisite: `util` + its owner role and the `signing_public`
-- role (pg-roles init). Applied in the same `signflow` location as V1.

CREATE SCHEMA IF NOT EXISTS validation;

-- ---------------------------------------------------------------------------
-- Table `validation.report` — the Orchestrator-normalized validation result.
-- `result_s3_ref` points at the stored normalized artifact (the full field set);
-- the columns are the queryable projection. The verbatim DSS report is NOT stored
-- here — only the normalized answer.
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS validation.report (
    id            text         PRIMARY KEY DEFAULT util.generate_ulid(),
    signature_id  text         NOT NULL,                  -- → signing.signature_record.id (plain id)
    verdict       text         NOT NULL,                  -- PASSED | INDETERMINATE | FAILED
    format        text,                                   -- e.g. XAdES_BASELINE_LT (normalized label)
    level         text,                                   -- QES | AdES (legal-meaning label)
    result_s3_ref text,                                   -- normalized validation artifact ref
    validated_at  timestamptz  NOT NULL DEFAULT now(),
    CONSTRAINT ck_report_verdict CHECK (verdict IN ('PASSED', 'INDETERMINATE', 'FAILED'))
);


CREATE INDEX IF NOT EXISTS idx_report_signature ON validation.report (signature_id);

-- Least-privilege grants — the same `signing_public` service role (signflow owns
-- both schemas). USAGE here + EXECUTE on the procedure (granted in R__); no
-- table/sequence privileges.
REVOKE ALL ON SCHEMA validation FROM PUBLIC;
REVOKE ALL ON ALL TABLES IN SCHEMA validation FROM PUBLIC;
REVOKE ALL ON validation.report FROM signing_public;

GRANT USAGE ON SCHEMA validation TO signing_public;
-- Procedure EXECUTE grants live in the repeatable migration (R__).

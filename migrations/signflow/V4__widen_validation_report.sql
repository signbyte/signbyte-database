-- V4: signflow — widen `validation.report` to the full normalized field set.
--
-- The signature-details answer the portal renders grew from a thin slice
-- (verdict/format/level) to the full eIDAS validation verdict: the signing party
-- (name + serial/registration), the signing time, the revocation-data time, the
-- long-term-validity horizon, the container form, the signed-file list, and the
-- warnings/errors. signflow normalizes the verbatim provider report into this set
-- and now persists ALL of it, so the durable record is self-contained legal
-- evidence rather than only the verdict (the verbatim provider report is still
-- never stored — only the normalized answer).
--
-- All columns are nullable → metadata-only change, no table rewrite. The signing
-- party's serial/registration number is stored in the clear as the real normalized
-- value; masking is purely a presentation concern in the portal UI and the reveal
-- is never an audited disclosure, so nothing extra is recorded here.
--
-- Prerequisite: V2 (validation.report). Applied in the same `signflow`
-- location as V1–V3.

ALTER TABLE validation.report
    ADD COLUMN IF NOT EXISTS signer            text,        -- signing party display name
    ADD COLUMN IF NOT EXISTS signer_serial     text,        -- personal serial (person) or registration number (org)
    ADD COLUMN IF NOT EXISTS organization      text,        -- organisation name (org/seal only)
    ADD COLUMN IF NOT EXISTS container_form    text,        -- PDF | ASiC-E
    ADD COLUMN IF NOT EXISTS signing_time      timestamptz, -- when the signature was created
    ADD COLUMN IF NOT EXISTS revocation_time   timestamptz, -- revocation-data (OCSP) time
    ADD COLUMN IF NOT EXISTS max_validity_time timestamptz, -- long-term-validity horizon (may be null)
    ADD COLUMN IF NOT EXISTS signed_files      jsonb,       -- container data-object names (container forms only)
    ADD COLUMN IF NOT EXISTS warnings          jsonb,       -- validation warnings (text array; [] = none)
    ADD COLUMN IF NOT EXISTS errors            jsonb;       -- validation errors (text array; [] = none)

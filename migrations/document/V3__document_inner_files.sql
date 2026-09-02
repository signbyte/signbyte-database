-- V3: store the ASiC-E inner-file manifest as cheap metadata.
--
-- An ASiC-E container holds one or more data objects (the actual files). Their
-- names/types/sizes are captured ONCE — from go-asice Inspect — when the container
-- row is written, so the portal can show "what is inside" (and the signer can see
-- what they are signing) WITHOUT unzipping the encrypted blob on every read. The
-- bytes themselves are extracted only on demand (preview/download).
--
-- NULL for a plain `source` upload (no inner files). For a `container` it is a JSON
-- array of {name, mediaType, size}. It is metadata only — the authoritative bytes
-- remain in S3; this never drives an integrity decision.
ALTER TABLE document.document
    ADD COLUMN IF NOT EXISTS inner_files jsonb;

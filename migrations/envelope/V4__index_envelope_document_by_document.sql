-- V4: let "which envelopes carry this document" find its rows by the document.
--
-- envelope_document is keyed (envelope_id, document_id): perfect for "the documents of
-- one envelope", useless for the reverse question the document-centric view asks —
-- "the envelopes covering this document" (find_envelopes_for_document). With document_id
-- only the second key column, that lookup has to read the whole table: 44 ms over a
-- million rows on a seeded copy, growing with the table, for what is a handful of rows.
-- A single-column index on document_id makes it a direct lookup.
CREATE INDEX IF NOT EXISTS idx_envelope_document_document
    ON envelope.envelope_document (document_id);

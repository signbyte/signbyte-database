-- Whether a document actually carries signatures, recorded at creation rather than
-- proxied by kind. The `kind <> 'source'` proxy conflated "is a container" with "is
-- signed", so an UNSIGNED bundle (kind=container, built by the platform with no
-- signatures — now the at-rest form of any multi-file set and of a single non-PDF)
-- read as a pre-signed upload. bundle/rebundle set this FALSE explicitly; an ingested
-- upload leaves it NULL and the listing falls back to the kind proxy (an uploaded
-- ASiC-E / signed PDF still reads signed), so upload behaviour is unchanged. A
-- signature applied here is captured by signed_at, OR-ed in at listing time.
ALTER TABLE document.document ADD COLUMN IF NOT EXISTS has_signatures boolean;

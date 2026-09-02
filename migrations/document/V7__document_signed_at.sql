-- signed_at: the instant the PLATFORM applied a signature to this row in place
-- (the keep-latest replace) — NULL for uploads, including files that arrived
-- already signed. It distinguishes "signed here" from "signed elsewhere" for a
-- chain whose signed head is its own root (a multi-document bundle, or an
-- uploaded container/PDF later co-signed in place); a child head carries the
-- same fact through its parent link, so the pair (parent set OR signed_at set)
-- is the complete "platform signed" answer.
ALTER TABLE document.document ADD COLUMN IF NOT EXISTS signed_at timestamptz;

-- One-time backfill for rows signed before this column existed: a parent-less
-- signed head whose row mutated meaningfully after creation was signed in
-- place by the platform. An uploaded already-signed file only drifts
-- updated_at via retention/ACL touches, so the threshold keeps those NULL; a
-- false positive costs only a dashboard label, never an access or evidence
-- decision.
UPDATE document.document
   SET signed_at = updated_at
 WHERE signed_at IS NULL
   AND kind IN ('container', 'pdf')
   AND status = 'signed'
   AND NULLIF(parent_id, '') IS NULL
   AND updated_at > created_at + interval '30 seconds';

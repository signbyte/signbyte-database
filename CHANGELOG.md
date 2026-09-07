# Changelog

Notable changes to the signbyte database — the schema set and the migration image —
newest first, per release. Written for whoever applies the image to a database or
integrates against the procedures.

## v0.1.2

### Added — an envelope records where it came from, and each signer where to go back (`envelope` V7)

A document system can start an envelope for its own user and hand the signer to the portal by link. For the
portal to name the requester and offer the way back, `envelope.envelope` gains three nullable columns —
`origin_name` (the requester's registered display name), `origin_return_url` (the default return address) and
`origin_ref` (the requester's own reference) — and `envelope.signer_slot` gains a nullable `return_url`, a
per-signer override of the default. `create_envelope` accepts the three origin fields and `add_slot` accepts
`return_url`, all optional; every read that returns the row (`get_envelope`, the signer inbox's slot projection)
carries them back as stored. An envelope started in the portal has none of them and reads NULL. The shape rules
for a return address (https only, no credentials, no fragment, a registered destination) are the calling
service's; the database stores what was admitted.

**What a deployment must act on:** nothing beyond applying the image. `V7__origin_and_slot_return_url.sql` is
four `ADD COLUMN IF NOT EXISTS`, nullable with no default — a metadata-only change, no table rewrite, no lock
worth naming. No new location, role or grant. The procedure signatures only **gain optional keys**, so an older
envelope service keeps working against the new database; a newer envelope service (`v0.3.0`) against an older
database has its origin keys silently dropped — apply this image first or together with it.

**Verification:** `migrations/testing/tests/unit.envelope_origin.sql` — the three fields and the slot override
round-trip through `create_envelope` / `add_slot` / `get_envelope`; a slot without an override reads NULL; an
envelope without an origin reads NULL on all three; empty strings store as NULL. Carried by this repository's
gate from this release on.

## v0.1.1

### Changed — `document.replace_container_blob` records the preservation class in the same write; `document.set_preservation_class` dropped

An archive-timestamped refresh of a signed document used to be two calls from the document service: the
byte swap, then a separate owner-scoped write of the preservation class. Any party other than the uploader
could pass the first and not the second, which left the bytes replaced and the fact unrecorded. The swap
now takes an optional `preservation_class` in `pi_data` (`none | b_lt | preservation`, validated before
any write; absent or empty leaves the class alone) and applies it in the same `UPDATE` as the new bytes:
a refused class leaves the row untouched, swapped bytes always carry their class. The separate setter has
no caller left and is dropped by `V10__drop_set_preservation_class.sql`.

**What a deployment must act on:** apply this image before or together with document-store `v0.1.1`. An
older document-store against this database fails its archive-timestamp route after the swap (it calls the
dropped procedure); a newer document-store against an older database swaps the bytes without recording
the fact. No new location, no new role, no table touched.

**Verification:** `migrations/testing/tests/unit.document_archive.sql`, carried by this repository's gate
from this release on.

## v0.1.0

Initial code.

The signbyte data layer as first released: ten migration locations (`util` through
`grants`) covering identity, documents, signing and validation, envelopes, the three
append-only audit trails and the trust-anchor store; one migration image that applies
any signbyte database from an explicit `LOCATIONS` list and refuses an unknown
location before touching the database; `SECURITY DEFINER` procedures as the only
entry point, `EXECUTE`-only service roles with no table access. AGPL-3.0-only.

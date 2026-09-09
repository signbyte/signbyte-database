# Changelog

Notable changes to the signbyte database — the schema set and the migration image —
newest first, per release. Written for whoever applies the image to a database or
integrates against the procedures.

## v0.1.2

### Changed — an identity code is stored in one spelling, and every column that holds one refuses any other

A person's identity code reaches a deployment written several ways: with the identity type and country a
signing certificate or an identity provider puts on it (`PNOLV-123456-78901`), with the separator dropped
(`PNOLV-12345678901`), as a person writes their national code (`123456-78901`), or in the `LV/LV/…` shape a
cross-border login carries. Compared as text those are different people — so the same human arriving two ways
became two, and the documents signed under one spelling were unreachable from the other.

The `util` location, which every deployment applies first, gains the canonicaliser and the predicate the
constraints call: `canonical_identity()` (the one stored spelling — the identity type, the country, a hyphen,
and the code with separators removed, upper-cased), **`is_canonical_identity()`**, plus `identity_type()`,
`identity_body()` and `identity_display()`. Functions only — no table, no role, nothing to provision.

Four columns then convert what they hold and require the canonical form from there on:

| column | migration | constrained |
|---|---|---|
| `identity.person.national_id` | `identity/V2` | always |
| `envelope.signer_slot.identity_ref` | `envelope/V8` | when present (an owner's own slot has none) |
| `document.document_acl.principal_id` | `document/V11` | only where `principal_kind = 'serial'` |
| `rolebyte.user_account.subject_key` | `rolebyte/V3` | only for the typed `pno:` variety |

The last two are conditional by design, not by caution: `principal_id` holds an identity code only when the
principal is a serial (otherwise it is an internal subject), and a register key is an identity code only when
its type prefix says so — `svc:<client id>` is a service account and never an identity code. A constraint that
did not distinguish them would refuse every service account and every document its own creator uploaded.

The procedures canonicalise on both sides: what they store, and the caller's value before comparing it. So a
caller that holds a code correctly but spells it differently gets a **match** rather than a silent miss —
which is what an invited co-signer needs when their certificate spells the code one way and the invitation
spelled it another. `document.normalize_serial` now delegates to the shared implementation instead of carrying
its own.

**What a deployment must act on, in order of how much it costs you:**

- **A caller that sends a bare national code now gets a named error.** `identity.upsert`
  (`identity:invalid`), `envelope.add_slot` (`envelope:invalid`), `document.grant_acl` (`document:invalid`)
  and `rolebyte.user_invite` (`membership:invalid`) all refuse a code they cannot canonicalise, rather than
  storing it under a guessed country — a wrong identity key is the wrong person's documents. **The country
  must come from the calling service**, from the nearest fact about the person: the country chosen on the
  screen where they were invited, the country in their signing certificate, or the country recorded for the
  system that sent the request. **Deploy your services' country handling with or before this image, never
  after it.** The reverse order is safe: a service may send a fully-qualified code to a database that does not
  yet require one. Every refusal message is deliberately value-free, because it reaches logs and an identity
  code is personal data.
- **The migrations can stop, by design, on a database that already holds rows.** Each converts before it
  constrains. Where the column has a uniqueness key, two rows that canonicalise to the same value are one
  person recorded twice and the key stops the run — merging them is a decision about which record's rights,
  roles or history survive, and it must not happen silently inside a migration. A value that cannot be
  canonicalised at all is left as it was, and the constraint then refuses it, naming the row. On empty tables
  all of this is a no-op.
- **`ADD CONSTRAINT ... CHECK` validates every existing row under an `ACCESS EXCLUSIVE` lock** —
  imperceptible on a small or empty table, worth planning for on a large populated one.
- **Nothing else changed.** No `UNIQUE` key, no `ON CONFLICT` clause and no index was touched: with one
  spelling at rest, every match stays plain equality, and every other procedure's input and answer is as it
  was.

### Added — the membership register `rolebyte` joins the signbyte database

The image now applies the `rolebyte` location for a signbyte deployment: tenants, their members by typed
subject key, per-service role definitions, assignments and an append-only history of every membership change.
The platform needs it for **machine members** — a document system that integrates with the platform is a
service account, a member of its own tenant, and the authorization server checks that membership when it
mints the account's tenant-named token. People signing on the portal are not registered in it: the register
is consulted for machines, never for a signer, so nothing about signing in or signing changes.

**What a deployment must act on:** add `rolebyte` to `LOCATIONS` (after `util`, before `identity`) and
provision **one more service role before migrating: `rolebyte_public`** (`ROLEBYTE_PUBLIC_PW`) — a missing role
stops the run. First use creates the schema and its procedures; no existing table is touched. The
authorization server and the register service read the new location through the role; deploy the database
first or together with them.

**Verification:** `migrations/testing/roleleak.rolebyte.sql` (the register role is table-isolated, its history
append-only at the grant boundary, no cross-silo reads in either direction) and
`migrations/testing/tests/unit.rolebyte_config.sql` (the configuration transport), both carried by this
repository's gate from this release on.

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

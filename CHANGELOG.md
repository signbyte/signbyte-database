# Changelog

Notable changes to the signbyte database — the schema set and the migration image —
newest first, per release. Written for whoever applies the image to a database or
integrates against the procedures.

## v0.1.2

### Changed — a person may have no identity code: a login from an organisation's directory is admitted without one (`identity/V3`, `identity.upsert`)

`identity.person.national_id` is **nullable** from this release. Somebody who signs in through their
organisation's directory carries a name and the directory's identifiers, never a national identity code; until
now the identity store refused such a login (`identity:invalid`, *national_id is required*). The column keeps its
unique key (empty codes are not compared with each other) and its canonical-spelling check (it passes on an empty
code and still refuses a non-canonical one); no existing row is touched.

`identity.upsert` resolves a login **without** a code by its credential handle (`idp_sub`): a known handle lands
on its person and refreshes the profile, an unknown handle creates a person with no code and links the handle to
it. Nothing else is ever matched on — not a name, not an e-mail address — so a directory person and the same
human arriving with a card are two persons until linked by a deliberate act, which is not part of this release. A
login that carries no code never blanks a code the row already holds. A login **with** a code is handled exactly
as before. `identity.get` answers `"serial_number": null` for a codeless person.

```
CALL identity.upsert('{"idp_sub":"<directory handle>","login_method":"upstream","name":"…"}', po);
→ {"result":"success","data":{"internal_sub":"01J8X2K4M9N7P3Q5R6S8T0V1W2","created":true}}    the first login
→ {"result":"success","data":{"internal_sub":"01J8X2K4M9N7P3Q5R6S8T0V1W2","created":false}}   the same handle again
```

Still refused with `identity:invalid`: a missing `idp_sub`, and a code that cannot be canonicalised — a bad code
is not the absence of one.

**What a deployment must act on.** Apply this image **before** the authorization server release that sends
codeless logins; an older server keeps working unchanged against it, since it always sends a code. Nothing to
provision. The migration is a new versioned file (`identity/V3`), not an edit to an applied one.

### Changed — a member's register key is their platform subject, never their identity code (`rolebyte/V4`)

The `rolebyte` register keys a member by a typed `subject_key`. A person was keyed `pno:<national identity
code>`; from this release they are keyed **`sub:<person id>`** — the identifier `identity.person` keys the
person on, which is also the `sub` claim of every token the authorization server issues for them. A service
account stays `svc:<client id>`. The register no longer knows what an identity code is: the constraint and the
three helpers `rolebyte/V3` added are dropped, and one shape rule replaces them —
`user_account_subject_key_typed CHECK (rolebyte.is_typed_subject_key(subject_key))`, true for `svc:<non-empty>`
and for `sub:` followed by exactly 26 Crockford-base32 characters. `claim_attach` and `resolve` match on plain
equality; `user_invite` refuses any other kind with `membership:invalid` —
*"subjectKey must be a typed key: sub:<person id> for a person, svc:<client id> for a service account"*.

```
before:  {"subjectKey": "pno:PNOLV-XXXXXXXXXXX", ...}
after:   {"subjectKey": "sub:01J8X2K4M9N7P3Q5R6S8T0V1W2", ...}
```

**What a deployment must act on.** `V4` converts nothing: a `pno:` member has no platform subject to convert
to without the identity store, and a register that still holds such rows makes the migration **stop**,
reporting their count and tenants (never the keys). No deployed database holds any; one that does predates
this model and is recreated. Apply this image **before** the services that send `sub:` keys — an older
service's `pno:` keys are refused at every write door and resolve to nobody, and a newer service against the
older register is refused by the `V3` constraint. Neither combination runs; migrate first, then redeploy.

### Added — `identity.register`: a subject for a person before their first login

A new procedure in the `identity` location, granted to `authbyte_public`. Registering or inviting a person
creates the person row — canonical code plus whatever name is known — with a stable subject and **no
credential**, so a person the platform knows has a key to be registered under from the first act, and cannot
log in until a credential is attached.

```
CALL identity.register('{"national_id":"PNOLV-XXXXXX-XXXXX","name":"…"}', po);
→ {"result":"success","data":{"person_sub":"01J8X2K4M9N7P3Q5R6S8T0V1W2","created":true}}
```

Idempotent on the code (an existing person answers `created:false`; name fields are filled only where the row
has none). A missing or non-canonical code is refused with `identity:invalid`, as `identity.upsert` refuses it.
That person's first login through `identity.upsert` lands on the same row and attaches the credential.

### Fixed — what a person is shown keeps their country and their identity type (`util/V3`)

`util.identity_display` returned the bare national identifier for every code except a Latvian personal number,
so five different principals holding the same digits rendered as **one identical string**: an Estonian person,
a Lithuanian person, an Estonian organisation's register number, a passport and an identity card all became
`23456789012`. The country is part of the identity — that is why the stored key keeps it — and the identity
type is what separates a natural person from an organisation and its seal.

Where a country's own way of writing the number is known, that spelling is unchanged and identifies the code
on its own. Everywhere else the code is now shown **exactly as stored**:

```
util.identity_display('PNOLV-XXXXXXXXXXX')  ->  XXXXXX-XXXXX        (unchanged)
util.identity_display('PNOEE-XXXXXXXXXXX')  ->  PNOEE-XXXXXXXXXXX   (was 23456789012)
util.identity_display('NTRLV-XXXXXXXXXXX')  ->  NTRLV-XXXXXXXXXXX   (was 34567890123)
```

**What a deployment must act on: nothing.** Nothing compares a displayed value, so no key, index, constraint
or comparison is affected — this changes what a screen shows and no stored data. `util/V3` replaces the
function; no table is touched and there is nothing to provision. The migration is a new versioned file rather
than an edit to `util/V2`, because a versioned migration is checksummed once it has been applied.

Writing the country in front of the identifier instead (`EE 23456789012`) was considered and rejected on
measurement: a space and a hyphen are both separators to `util.canonical_identity`, so a person retyping what
they were shown would have had the country absorbed into the identifier and resolved to a **different key,
with no error**. The stored spelling can be typed back in and reaches the same person.

The services' shared library changes to match in the same breath — the two implementations must agree exactly,
and the same defect was in both, because this one was written to mirror the library and mirrored this too.

### Changed — an identity code is stored in one spelling, and every column that holds one refuses any other

A person's identity code reaches a deployment written several ways: with the identity type and country a
signing certificate or an identity provider puts on it (`PNOLV-XXXXXX-XXXXX`), with the separator dropped
(`PNOLV-XXXXXXXXXXX`), as a person writes their national code (`XXXXXX-XXXXX`), or in the `LV/LV/…` shape a
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

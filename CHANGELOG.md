# Changelog

Notable changes to the signbyte database — the schema set and the migration image —
newest first, per release. Written for whoever applies the image to a database or
integrates against the procedures.

## v0.1.0

Initial code.

The signbyte data layer as first released: ten migration locations (`util` through
`grants`) covering identity, documents, signing and validation, envelopes, the three
append-only audit trails and the trust-anchor store; one migration image that applies
any signbyte database from an explicit `LOCATIONS` list and refuses an unknown
location before touching the database; `SECURITY DEFINER` procedures as the only
entry point, `EXECUTE`-only service roles with no table access. AGPL-3.0-only.

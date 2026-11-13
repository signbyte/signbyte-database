# Changelog

Notable changes to the signbyte database — the schema set and the migration image —
newest first, per release. Written for whoever applies the image to a database or
integrates against the procedures.

## v0.8.0

### Removed — rolebyte: the procedures `bootstrap_state` and `own_rung_register` are dropped

Migration `rolebyte/V29` drops `rolebyte.bootstrap_state` and `rolebyte.own_rung_register`. The register's one-time
first-tenant door is gone from the service, and these two were called only by it; no release of the service calls
either one outside that door. **Apply order:** applied before the service's release without the door, an older service
whose door is still armed (`BOOTSTRAP_CREDENTIAL_FILE` set) answers a server error on that door from then on, and
nothing else of it is affected; with the setting unset, or once the release without the door runs, nothing is
affected at all. No data is touched: what `own_rung_register` wrote earlier stays as it is. The service's role also no
longer may execute `rolebyte.tenant_create` (the procedure stays, for the location's owner); no release of the service
calls it outside the removed door. An operator's own scripts that called it as the service's role must run it as the
location's owner.

### Changed — rolebyte: a company's row says whether somebody of it has signed in; two refusals changed their reason

No migration. The door's answer for a company (the list, one company, and the `company` in the answer of opening
one) gains the boolean `entered`: true when the company has an active account of a person, or its history shows a
person's account having become active; it stays true after that person's access is taken away. Opening a company under a name another company has
(ignoring case) is now refused `membership:name_taken`, and opening a company or the first run before the
deployment's services have declared themselves is now refused `membership:not_declared`. The sentences are unchanged and nothing is written. A caller that
matched `membership:conflict` for these two cases must match the new reasons; every other `membership:conflict`
refusal is unchanged. Apply order: the membership register's service must already be at the release that knows the
two new reasons before this database release is applied; under an older service both refusals are answered as an
internal error (500) instead of 409. The service's new release is safe against the older database.

### Added — rolebyte: a setup window for a company that was just opened

One migration, `rolebyte/V28`: `rolebyte.user_account` gains `setup_until`, null on every existing row and settable only
on a row whose key starts with `svc:`. A row that carries it is a setup account's row for ever: the register answers it
as a member only while its window is open, and never otherwise. A window is open while the row is active, `setup_until`
is in the future and nobody of the company has ever signed in: the company has no active account of a person (a key
that starts with `sub:`) and its history has no line of a person's account becoming active (`claimAttached`,
`directoryAdmitted`), so a company a person has signed in to is never opened or answered again, even if that person was
removed since. A repeatable file
adds two procedures granted to the register's own role, both behind the door's caller check: `company_setup_open`
(`tenantId`, `account`) opens a window of ten minutes, a length that is not an input, for one service account of the
company and answers `{account, scopes, endsAt}`; `company_setup_close` (`tenantId`) ends it and answers `{changed}`.
Opening is refused `membership:invalid` for an account that is not a service account's key, `membership:not_found` for
a company that does not exist or is not active, and `membership:conflict` when the account is listed under a product,
when somebody of the company has signed in (even if removed since), when a window is already open in the company, or when the account is already a
standing member of it. While the window is open the account holds exactly the company's permissions of the class
`tenantConfiguration` that are not retired and whose service and feature the company is entitled to, as
`service/feature:act` scopes: no level, no role, no administrator's box, no place on the list of the deployment's
administrators and no scope for a strong sign-in. An entitlement taken away, or a person becoming active, ends the
account's permissions or membership at once. `company_setup_close`, and every procedure that makes a person's account
active (`claim_attach`, `directory_admit`), end the company's setup rows for good: each active setup row (one whose
time ran out included) is made revoked with a `setupClosed` line of its own, so a second close ends nothing and a
window never comes back. Both history lines carry the account's row (`user_id`) and the payload `{subjectKey}`. A setup
row is never an ordinary member: `is_administrator` is false for it, and `role_grant`, `tenant_role_grant`,
`user_type_assign` and `administrator_set` refuse it as they refuse a revoked account (`chart_person_place` already
refuses a service account's key).
`products_register` refuses a list that names,
as a product's account, a key that has a setup row in any company (`membership:invalid`, 'product N lists an account
that is used for setting companies up'). New history kinds: `setupOpened`, `setupClosed`.
Nothing existing is answered differently.

### Changed — rolebyte: what a service declared is its own to change

One migration, `rolebyte/V27`: `rolebyte.service_permission` gains `declared_by`, the declaring client's service
subject (filled in from the history for every permission a service's declaration line shows, null for the rest), and
`retired_by`, the client whose declaration retired the permission (null when it is not retired or the deployment
retired it). In `service_declare`: a permission another client declared may be repeated unchanged but not changed or
retired (`membership:config_key_conflict`, "was declared by another client, and only that client changes it"); the
first client to name a permission with no declarer takes it (history line `permissionClaimed`); an entry without the
`retired` mark reinstates a permission only when the same client's declaration retired it, otherwise it stays retired
and the line says so; a level may be defined only in the group named like the service key, a group the caller lists
in the new optional `groups`, a group the key already holds, or `membership` under `rolebyte` (`membership:forbidden`
otherwise), and every key is checked against the grant before any group; the groups `declare` and `declare-group` are
reserved (also in `role_define`); a document names a service, a permission and a level once and puts at most 20
labels on a permission; one service key holds at most 1000 permissions and 100 levels through a declaration (a
document that adds nothing is never refused for it). On both paths the chart of authority is all or nothing under one
service key. The deployment's own registration still changes and reinstates any permission and has no limit.
**Apply:** the caller of `service_declare` passes in `groups` the groups the declaring client is granted; a level in
a group not named like its key, not in `groups` and not already the key's is refused. **Also apply:** the migration
cannot tell who retired a permission before it ran, so every permission retired when it runs counts afterwards as
retired by the deployment, and no service's declaration reinstates it. After the upgrade list them (`SELECT
service_key, feature_key, act FROM rolebyte.service_permission WHERE retired_at IS NOT NULL`) and reinstate, through
the deployment's own registration, any that a service should still hand out.

### Added — rolebyte: a service declares itself to the register

One migration, `rolebyte/V23`: the table `rolebyte.service_declaration` keeps, per service key and declaring client,
when a declaration was first and last accepted. The new procedure `rolebyte.service_declare` takes `actor` (the
declaring client, a service subject `svc:<client id>`), `allowed` (the service keys that client may declare) and
`section` (a `services` list in the shape `permissions_register` reads). It writes through the same registering acts
as `permissions_register` and answers the same report. It is all or nothing: one refused line leaves nothing of the
document written. It is granted to the register's own role, while `service_register`, `role_define`,
`permission_declare` and `permissions_register` keep their grants. It refuses a key outside `allowed`
(`membership:forbidden`); a member it does not know, a group or level that is not one lower-case word of at most 64
characters, more than 50 services, 50 levels or 500 permissions per service, a text over 256 characters and a document
over 262144 bytes (`membership:config_bad_document`); and a group already defined under another service key, and
`membership` under any key but `rolebyte` (`membership:config_key_conflict`). When the registration lock cannot be had
within five seconds it answers `membership:busy`, to try again. `rolebyte.role_define` now takes only a lower-case word
(`^[a-z][a-z0-9-]{0,63}$`) as a group or a level. **Apply:** an older rolebyte runs on it unchanged; the rolebyte release that declares
its own levels at start (v0.5.0) needs this location version.

### Added — rolebyte: the deployment's own company and its deployment admins

One migration, `rolebyte/V24`: `rolebyte.deployment` (at most one row, present once a company is marked) and
`rolebyte.deployment_admin` (one row per person: the account, who added it, from `settings` or `screen`, and when).
The register's own role has no access to either table. Six procedures, five granted to the register's role:
`deployment_company_mark` (`actor`; takes no tenant, an input with `tenantId` is `membership:invalid`; marks the
company by itself only when exactly one company exists, with one history line; answers
`{company: {id, name} | null, changed, companies}`; with none, or with several and none marked, it writes nothing and
answers a null company; with one already marked it answers it, `changed` false; never an error for these);
`deployment_company_set` (`actor`, `tenantId`; the deployment's own act for a deployment with several companies,
granted to nobody and run as the location's owner; an unknown tenant is `membership:not_found`, a different company
than the marked one is `membership:conflict`, the marked one again changes nothing);
`deployment_get` (optional `subjectKey`; answers `{company: {id, name} | null}`, the company only for a person whose
account in it is active while the company is active); `deployment_admin_add` (`actor`, `subjectKey`, `addedFrom` = `settings` or `screen`;
answers `{userId, changed}`; refuses no company marked and a revoked account with `membership:conflict`, a bad
`addedFrom` or a key that is not a person's with `membership:invalid`, no account in the company, including a person
in other companies only, with `membership:not_found`; an invited account is accepted); `deployment_admin_remove`
(`actor`, `userId`; answers `{userId, subjectKey, changed: true}`; an account not listed is `membership:not_found`);
`deployment_admin_list` (answers `{admins: [{userId, subjectKey, displayName, status, lastSignedInOn, addedBy,
addedFrom, addedAt}]}` for entries whose account is not revoked). Each change of the company or the list is a history
line in the company. `rolebyte.resolve` now gives a membership `"highScopes": ["deployment:admin"]` when it is a
person's account in the deployment's own company and is on the list; in every other case the member is absent, so
every other answer is unchanged. The scope is never in `scopes`. Revoking an account (`user_revoke`) deletes its entry
on the list in the same act, with a history line. The group `deployment` and the service key `deployment` are the
register's own: `service_declare` refuses a level in the group and a service with the key
(`membership:config_key_conflict`), `role_define` refuses the group and `service_register` the key
(`membership:invalid`). **Apply:** an older rolebyte runs on it unchanged.

### Added — rolebyte: the person a deployment's settings name

One migration, `rolebyte/V25`: `rolebyte.deployment` gains three nullable columns, `admin_setting_subject_key`,
`admin_setting_mode` and `admin_setting_applied_at`: the person last applied from the deployment's settings, in which
mode, and when. The new procedure `rolebyte.deployment_admin_apply`, granted to the register's own role, takes `actor`,
`mode` (`saas` or `local`), `subjectKey` (a person's `sub:` key) and an optional `displayName`; a missing actor, any
other mode and a key that is not a person's are refused `membership:invalid` with nothing written. Every other call
answers `{outcome, companyId, userId, companyMade, memberAdded, companyMarked, listAdded, rungGranted}`, the last three
saying what the call itself changed. The outcome is `applied`; `unchanged` (an account exists and this value, person
and mode, is the one last applied: nothing is written, so an entry taken off the list is not put back);
`removedMember` (the person's account in the company is revoked: one history line, `deploymentAdminRefused`, and
nothing else); `nameNeeded` (no account and no name); or `noCompany` (none marked and several exist). With no company
at all and a name it makes a company with an empty name and no starting roles, marks it as the deployment's own and
makes the person its administrator. On `saas` the person is put on the list of the deployment's administrators as
added from the settings, a new member holding no role; on `local` the person holds the company's administrator rung
and the list is never written. Each value applied writes one history line, `deploymentAdminSettingApplied`. When no
company is marked the procedure also takes the lock the one-time bootstrap door takes. **Apply:** an older rolebyte
runs on it unchanged.

### Added — rolebyte: the deployment's door, the catalog of products and their service accounts

One migration, `rolebyte/V26`: the tables `product`, `product_entitlement`, `product_requirement`, `product_account`
and `tenant_product` hold the products a deployment sells (what each gives, what it needs, the service accounts
`svc:<client id>` it carries with their levels) and which products each company has. The register's own role has no
access to them. A repeatable file adds the procedures the register's own role runs to open a company, say which
products it has and name its administrators. Each one first proves that the calling person (`actor`) is a deployment
administrator in the `saas` mode (`mode`): a person's key, an active account in the deployment's own company, which is
active, on the list of the deployment's administrators. Every other case, the `local` mode and a service's key
included, is refused `membership:forbidden` with one sentence, before anything about a company is read;
`deployment_door_check` is that check alone. A missing actor or a mode that is neither `saas` nor `local` is
`membership:invalid`. A writing procedure takes the deployment's lock and asks again, so a person taken off the list is
refused at once. No refusal carries a person's name. Reads: `company_list`, `company_get`, `company_administrators`,
`deployment_products`, `deployment_admins`. Writes: `company_open` (the company, its default user type, the
administrator invited with the rung, the starting roles in `en` or `lv`, the products ticked with their entitlements and
their service accounts as active members; a refusal after the first write leaves nothing), `company_has_set` (tick or
untick a product: a product needs the products it lists, both ways; unticking closes a whole service when no other
ticked product gives any of it), `company_administrator_set` and `company_administrator_unset`, `company_roles_seed`,
`company_first_run` (name a deployment's own company the first time; on `local` its administrator may run it, and it
gives the company every offered product), `deployment_admin_grant` and `deployment_admin_revoke` (the last deployment
administrator whose account is active cannot be removed), `local_company_follow` (a deployment run on the customer's
own machines has every product it offers), and `products_register`, granted to nobody and run as the location's owner,
which makes the catalog equal to the list it is given. Only when asked (`adopt: true`) does it take a company that
already holds every entitlement of a product as having it, and then it gives the product like any ticked one; a company
with no ticked product is never touched, a list may not give the register's own service, and a list that would make a
product need one a company having it has not ticked is refused. Entering the list again also ends, in each company
that has a ticked product, a service account that a ticked product listed before the entry and none lists after it, as
taking the product away does. A product is offered only while every service it gives
has a permission that is not retired. The follow of a company's service accounts never ends its last administrator. Giving a product makes its service accounts active members holding exactly their levels, and taking it away
ends them; an account listed under several products holds the union. For an account on the list the list decides:
levels given to it by hand are taken away, and an account a company's administrator removed is active again while a
product that lists it is ticked. An administrator's level is never given to a service account nor taken from one.
`deployment_admin_add`, `deployment_admin_remove` and `deployment_admin_list` are no longer granted to the register's
own role; the door runs them. New history kinds: `tenantRenamed`, `productTicked`, `productUnticked`,
`productRegistered`, `productUnregistered`, `serviceAccountAdded`, `serviceAccountRemoved`. **Apply:** an older
rolebyte that calls those three procedures directly must call the door instead.

## v0.7.0

### Changed — util: a name is at most 100 characters, in every language

`util/V7` adds `util.name_refusal(text)`, which answers "a name is at most 100 characters" past that, and
`util.labels_refusal` now refuses a name in another language past 100 characters and cuts a key that is not a language
to 20 characters when it says it back. rolebyte's role, user type and position names in other languages were already
held to 100 characters; past it, the refusal now reads "labels: the name in *lang* is at most 100 characters" where it
read "… is 1 to 100 characters on one line" (still `membership:invalid`). **Apply:** nothing to act on.

### Added — util: `util.file_name_refusal`

`util/V6` adds `util.file_name_refusal(text)`: what is wrong with a stored file's name, or null when nothing is — a
control character, a character that turns the direction text is drawn in, or a line or paragraph separator, named by
its code point. A shared primitive; no procedure of this product calls it yet. **Apply:** nothing to act on.

## v0.6.0

### Changed — rolebyte: an assistant's person is chosen when it is added

`rolebyte/V22` drops `rolebyte.assistant_person_set`: the person an assistant works for is chosen when it is added and
never changed after; the `assistantPersonSet` lines it wrote stay in the history. `rolebyte.assistant_list` with
`withPerson` also answers each assistant's `addedAt` and `removedAt` (`null` while it is not removed, otherwise the
time of its removal's line in the history); without `withPerson` it answers as before. **Apply with** rolebyte v0.4.0:
an older rolebyte calls the dropped procedure when an assistant's person is changed, and fails there.

## v0.5.0

### Changed — util: `util.labels_refusal` is declared STABLE

`util/V5` declares `util.labels_refusal` STABLE, and `rolebyte.name_labels_refusal`, which calls it, says the same:
the refusal sentence lists the app's languages with a function PostgreSQL declares STABLE, so neither may promise
IMMUTABLE. Every answer is the same as before, and the migration changes the declaration only; nothing to act on.

## v0.4.0

### Added — e-signing: the `legacyEid` signing flow

Two migrations, `envelope/V10` and `signflow/V7`, each drop and re-add one `CHECK` (`ck_slot_flow`,
`ck_signing_job_flow`) with `legacyEid` beside every name stored before: a scan of the table under a brief lock,
nothing rewritten. `envelope.add_slot`, `signing.save_job` and `signing.insert_signature` accept it: the eID card
signed in the person's browser through the eParaksts provider's own plugin. **Apply before** a signing service that
writes `legacyEid`, which the older schema refuses (`invalid flow`); nothing changes for a deployment that does not
offer the flow.

### Changed — rolebyte: assistants, each one person's own

Two migrations, `rolebyte/V20` and `rolebyte/V21`. `rolebyte.assistant_person` keeps the one person an assistant (a
machine member keyed `svc:assistant-<ULID>`) works for, and an assistant's name is unique in its tenant among those
not removed, ignoring case. New procedures: `assistant_create` (for one active person of the tenant; the assistant
starts in the shipped **Assistant** role, made with the tenant's first assistant), `assistant_rename`,
`assistant_person_set`, `assistant_list` and `assistants_of_person` (the sign-in service's lookup).
`permission_declare` accepts the seed `assistant`. **Apply with rolebyte v0.3.0 or later**, which declares that seed.

### Added — rolebyte: names in other languages, a person's own language and an administrator's note

- `rolebyte/V17`: tenant roles, user types and chart positions gain `labels`, their names in the app's other
  languages. Empty for every existing one, so nothing anybody reads changes until a name is given.
- `rolebyte/V18`: a person's own language, one row per person keyed by their platform subject and the same in every
  tenant, read and set with `person_language_get` and `person_language_set` (none set: the deployment's language).
- `rolebyte/V19`: an administrator's note on a member, up to 1000 characters, set with `user_note_set`; the history
  records that a note changed, never its words.

### Added — util: names in other languages for configured lists

`util/V4` adds `util.app_languages`, `util.labels_merge`, `util.labels_refusal` and `util.list_number`: the helpers
every configured list's procedures use to check its names in the app's other languages and to number its items.

### Changed — identity: every sign-in is kept under the provider it came from

- `identity/V4`: a credential keeps the email address its directory sent, renewed at each sign-in. It is shown,
  never matched on; a card or a mobile identity keeps none.
- `identity/V5`: a credential is keyed by its provider and its handle together, since a handle is unique only at the
  provider that issued it. Every credential stored before keeps the empty provider, the deployment's one provider.
- `identity/V6`: card sign-ins move under a provider of their own, `webeid`; where a newer sign-in service already
  wrote the same card's credential there, the older duplicate is removed.
- **Apply with a sign-in service that names its providers** (authbyte v0.7.0 or later).

### Changed — rolebyte: only the deployment writes the list of services, an import keeps the workspace's name and login, a workspace and one person's history can be read, and revoked people leave the chart

One new migration, `rolebyte/V16`: two indexes on `rolebyte.event`, and every person whose access was revoked taken
out of their chart position with one `chartPersonRemoved` line each (touches only those rows). **Apply with the
rolebyte service of the same date**, whose one-time bootstrap door calls the new `own_rung_register`.

- **Operators: register services, roles and permissions as the location's owner.** `service_register`,
  `role_define` and `permission_declare` are no longer executable by `rolebyte_public`; the list every tenant of a
  deployment shares is written only by the deployment (`permissions_register` or the three procedures, as owner).
- New `rolebyte.tenant_get` (a workspace's name and the entitlements in force) and `rolebyte.own_rung_register`
  (the register's own administrator rung, naming nothing else), both granted to `rolebyte_public`.
- `config_section` no longer carries the workspace's name or corporate login; `config_apply` compares a document
  with the list and never writes it — entries `unchanged` or `skipped`, a file's name and login answered as a
  `workspace` list of `skipped` items.
- `history` takes `actor` (a typed key, or `operator` for whoever runs the deployment); `user_revoke` also takes
  the person out of the chart.

### Changed — rolebyte records the day each member last signed in, its people read names each member's user type, and its history reads a page at a time

One new migration, `rolebyte/V15`, adds a nullable date column to `rolebyte.user_account` (no rewrite, a brief
lock); three procedures change behaviour. **Apply with the rolebyte service of the same date.**

- `rolebyte.resolve` reads a new optional input, `issuing` (a JSON boolean). With `issuing: true` it writes the day
  (UTC) on each membership it answers, at most once a day per membership, skipping a row another session holds
  locked; without it nothing is written. Its answer is unchanged and it writes no event.
- `rolebyte.access_list` gives each member `userType` (`{id, name}`), `chartUserType` (the chart position's type while
  the tenant has the chart, else `null`) and `lastSignedInOn` (`"YYYY-MM-DD"` or `null`). `arrival` now also needs
  the user type in force to hold nothing and no chart position carrying a box.
- `rolebyte.history` answers newest first, a page at a time, with `more`: `limit` (100 by default, at most 500),
  `before` (an event id of the same tenant) and `kindPrefix` beside `service`, `from` and `to`. A bad `limit` or
  `before` is `membership:invalid`. It used to answer up to 1,000 events oldest first.

### Changed — rolebyte's configuration section answers the whole contract, and records every import and export

No migration and no table changes; the repeatable procedures change, and two of them answer a different shape.
**Apply with the rolebyte service of the same date**, and switch any deployment script that registers the
services' permissions through `config_apply` in the same change.

- `rolebyte.config_get` answers `{section, version}` instead of the section itself. The section carries
  `"schema": "rolebyte-config/1"` and, on each permission a new tenant's roles start with, its `seeds`, so a section
  read back and applied changes nothing. The version is `util.config_token('rolebyte-config/1', tenant, section)`.
- `rolebyte.config_version` (new, granted to the register's role) answers the version alone. The vocabulary is
  every tenant's, so a vocabulary change moves every tenant's version.
- `rolebyte.config_apply` requires the schema, reads `dryRun`, `expectedVersion`, `partHash` and `documentHash`,
  needs `expectedVersion` for a writing apply (`config_version_required`) and compares it under one lock for the
  whole deployment (`config_version_moved`). A preview and an apply are one pass, undone for a preview or when an
  item is refused, and **a refused item is a line of the report, not an error**; a changed class or plane is
  `config_key_conflict` (was `conflict`). An apply that was not refused writes one `configApplied` line in the
  tenant's history with the counts, the part's hash and the document's.
- `rolebyte.config_exported` (new, granted to the register's role) writes one `configExported` line naming who took
  the section out and the part's hash.
- `rolebyte.permissions_register` (new, granted to nobody) is how a deployment registers the permissions each
  service prints, as the location's owner: no tenant, no version, no history line, and one refused entry writes
  nothing.
- `rolebyte.permission_declare` also answers `changes`, the members a declaration changed.

### Added — one helper for a configuration's version

Migration `util/V3` adds `util.config_token(schema, scope, section)`, a pure function that computes the version token
of a section of configuration (`sha256:` and the hex SHA-256 of the schema name, the scope and the section's text). It
creates no table, writes no row and is granted to no service role. Every deployment records one more applied
migration in `flyway_schema_history_util`; nothing else changes.

### Added — an organisation chart, and a user type for every member

Migration `V14` adds three tables to `rolebyte` — `chart_position` (a tree of positions, one top per tenant),
`chart_holder` (a member in a position, at most one each) and `chart_position_permission` — accepts a third plane,
`chart`, on `rolebyte.service_permission`, and adds `rolebyte.tenant.default_user_type_id`. **It rewrites every
`rolebyte.user_account` row once:** each tenant gains a user type named *Member*, holding nothing (an existing type of
that name, in any letter case, is adopted instead), every member without a type receives it with the source
`workspaceDefault`, and `user_type_id` and `user_type_source` then become NOT NULL, with one event written per member
given the type. Run it in a quiet window on a large register.

A permission declared on the `chart` plane is carried by a position, never by a role or a user type
(`rolebyte.tenant_role_permissions_set` refuses one with `membership:invalid`), must be ordinary in class and seeds no
role. Ten new procedures, granted to the register's own role, edit and read the chart: `chart_get`, `chart_document`
(for each member in a position, the subject keys of everyone in a position below theirs), `chart_position_add`,
`_rename`, `_move`, `_remove`, `_permissions_set`, `_user_type_set`, `chart_person_place` and `chart_person_remove`.
The chart is in force for a tenant only while it is entitled to the service key `authority`: until then a write is
refused with `membership:conflict`, `chart_document` answers an empty chart, and **a deployment that never entitles it
behaves exactly as before, apart from the user type below.** While it is in force, `rolebyte.resolve` adds a
position's chart permissions to its members' scopes, and a member in a position that names a user type receives that
type's permissions in place of their own. An administrator's scopes never include a chart permission.

### Changed — every member holds a user type

`rolebyte.tenant_open`, `user_invite`, `directory_admit` and the administrator seed give every arriving member the
tenant's default user type (the corporate-login default still wins for people arriving through the tenant's
directory). `rolebyte.user_type_assign` refuses an empty type with `membership:invalid`: a type is changed, never taken
away. `rolebyte.user_type_delete` refuses the default and a type a chart position names with `membership:conflict`,
and `user_type_list` marks the default with `workspaceDefault`. A caller that took a member's type away by sending an
empty one must stop doing so before applying this image.

## v0.3.0

### Added — a family of permissions, one per field

Migration `V13` widens `rolebyte.service_permission`'s class check to `perField`, requires such a permission to be on
the object plane, adds a nullable `param` column to `rolebyte.tenant_role_permission` and moves that table's key to a
unique key over `(tenant_role_id, permission_id, param)` that treats two NULLs as equal, rewriting nothing. **A
deployment whose services declare no per-field family behaves exactly as before.** Apply it before a service's
permission section that declares one: an older register refuses the class.

A service whose tenants add fields of their own declares one family per kind of field (class `perField`, object
plane, no `seeds`), and a role holds it one field at a time, spelled `<family>@<key>.<generation>`.
`rolebyte.tenant_role_permissions_set` takes such names, and refuses the bare family (every field of its kind, held
only by the Administrator checkbox) and `@` on any other permission with `membership:invalid`. The new
`rolebyte.field_permission_roles_set({actor, tenantId, permission, roleIds})` sets which of a tenant's roles hold one
field as a whole set, touching no other tick, and is granted to the register's own role.
`rolebyte.tenant_role_definitions`, `tenant_role_list` and the reconfiguration events spell a field's tick with its
`@` part; `rolebyte.resolve` never puts one on a token, and an administrator's token carries the bare family.

### Changed — the CSC signing flow is two flows

Migrations `envelope` `V9` and `signflow` `V6` each replace one `CHECK` constraint (`ck_slot_flow`,
`ck_signing_job_flow`) by drop and re-add, rewriting nothing. The single `csc` flow is now two, named for how the eID
card is read: `cscEidScan` (a phone reads it) and `cscEidPlugin` (a card reader, through the provider's browser
extension). `envelope.add_slot` and the signing procedures accept the two names and refuse `csc` with `invalid flow`;
rows already stored with `csc` stay valid and are not touched. **Deploy together with signing services that send the
new names.**

### Added — roles a new tenant can start with, and user types

Migration `V12` adds columns to `rolebyte.service_permission`, `rolebyte.tenant_role`, `rolebyte.user_account` and
`rolebyte.tenant`, and two tables (`rolebyte.user_type`, `rolebyte.user_type_permission`), rewriting nothing. **A
deployment whose services declare no shipped roles behaves exactly as before**: its tenants open with no roles.

A permission declaration may carry `seeds`, `"worker"`, `"manager"` or both, on an ordinary permission of the object
plane only (anything else is `membership:invalid`). Once any service declares one, `rolebyte.tenant_create` and
`rolebyte.tenant_open` create three roles with every new tenant: *Guest* (holding nothing), *Worker* and *Manager*,
each holding the permissions whose `seeds` name it, named in Latvian when the tenant is opened with `"language":
"lv"`. `rolebyte.tenant_open` answers them under `roles`, and `rolebyte.tenant_role_definitions` names each one's
`seed`. A tenant changes or deletes them like any other role. Tenants already open are not touched until the operator
runs `rolebyte.tenant_seed_roles({actor, tenantId})` for them, which creates the shipped roles a tenant lacks from what
is declared now, leaves what it has alone, and changes nothing when run again.

User types are named sets of a tenant's **tenant-wide** permissions, given to a member across the tenant:
`rolebyte.user_type_define`, `user_type_update`, `user_type_delete` (refused while anybody holds it),
`user_type_list` and `user_type_assign`, with `rolebyte.resolve` adding what the member's user type holds. A tenant
may also choose one user type for people arriving through its attached directory
(`rolebyte.corporate_login_default_set` / `_get`); `rolebyte.directory_admit` gives it once, to a person admitted for
the first time, never to one claiming an invitation. Every act is an attributed event, and each event carries the
state it left, so the history alone rebuilds every role and user type. All new procedures are granted to the
register's own role.

```
CALL rolebyte.user_type_define('{"actor":"sub:…","tenantId":"01K6…","name":"Office",
      "permissions":["work/project:create"]}'::jsonb, NULL);
→ {"id":"01K6…","name":"Office","description":"","permissions":["work/project:create"],
   "members":0,"corporateLoginDefault":false}
```

### Added — who holds what in a tenant

A new procedure, `rolebyte.access_list`, with no migration and nothing to provision: every member of a tenant,
ordered by name, with what the register holds for them — `kind` (`person` or `service`), `status`,
`administrator`, `arrival`, `serviceRoles` (service, group, level) and `tenantRoles` (id, name). It answers what is
stored: a member whose access was revoked is listed with the grants still on record, and service accounts are
listed and marked. `arrival` is an active person holding nothing. It is granted to the register's own role and
writes nothing.

### Changed — a declared permission says where it may be granted, carries a label per language, and can be retired

Migration `V11` adds three columns to `rolebyte.service_permission` without rewriting it.

**A declaration without `plane` is now refused**, so a service that declares permissions must send it from the
same release as this image. `plane` is `tenant` (granted to the whole tenant) or `object` (placed on one object the
service owns), and like `class` it never changes: naming the other one is refused with `membership:conflict`. A
permission declared before this migration takes its plane from its next declaration.

`labels` is an optional map from a language tag to a label (`{"lv": "…"}`); `description` stays the fallback. A
declaration with `"retired": true` retires the permission, and one without the mark brings it back. A retired
permission keeps working for every tenant role that already ticks it, cannot be added to any other
(`membership:invalid`, *"‹permission› is retired: a role that holds it keeps it, and no role can be given it
again"*), and no longer reaches a tenant's administrators. The configuration section answers and accepts all three,
so an export applied back changes nothing.

```
CALL rolebyte.permission_declare('{"actor":"svc:you","service":"work","permission":
      {"feature":"task/comment","act":"add","class":"ordinary","plane":"object",
       "labels":{"lv":"Komentēt uzdevumu"}}}'::jsonb, NULL);
→ {"permission":"work/task/comment:add","status":"added"}
```

### Added — a tenant keeps its last administrator, and the operator has a way back

A tenant's administrator is a member holding the `membership:admin` role whose access is not revoked. Revoking
that role from the tenant's last administrator, or revoking their access, is now refused with
`membership:conflict` and *"‹name› is this tenant's last administrator; make someone else an administrator
first"*. An invited administrator counts. Two administrators removing each other at the same moment cannot both
succeed.

The deployment's operator, as the location's owner (the service role cannot), can now open a tenant with its first
administrator, make someone an administrator, remove one, and list every tenant with its administrators:

```
CALL rolebyte.tenant_open('{"actor":"op:you","name":"Workshop","administrator":{"subjectKey":"sub:01J…","displayName":"Ilze"}}'::jsonb, NULL);
CALL rolebyte.administrator_set('{"actor":"op:you","tenantId":"01J…","subjectKey":"sub:01J…","displayName":"Ilze"}'::jsonb, NULL);
CALL rolebyte.administrator_unset('{"actor":"op:you","tenantId":"01J…","userId":"01J…"}'::jsonb, NULL);
CALL rolebyte.tenant_overview('{}'::jsonb, NULL);
```

An administrator can also be named in the service's environment and is applied at start, once per value, through
the new `rolebyte.administrator_seed`, remembered in the new table `rolebyte.administrator_seed` (migration `V10`,
a new empty table). A seed never removes anyone.

**Changed:** an administrator now also resolves every permission the tenant has, and no role can hold a permission
that changes the tenant's own setup. Where no service declares permissions, which is the signbyte case today,
every resolve answers exactly as before. Nothing to do on upgrade.

### Added — a service that places a tenant's roles reads them, and a role in use cannot be deleted

A member service that places the tenant's roles on its own objects reads what each role carries with the new
`rolebyte.tenant_role_definitions`: each role's id, name and description, and its permissions narrowed to what the
tenant has. It reports how many times it placed each role with the new `rolebyte.tenant_role_placements_set`,
stored in the new table `rolebyte.tenant_role_placement` (migration `V9`, a new empty table).

```
CALL rolebyte.tenant_role_definitions('{"tenantId":"01J…"}'::jsonb, NULL);
CALL rolebyte.tenant_role_placements_set('{"tenantId":"01J…","reporterId":"01J…","placements":{"01J…":12}}'::jsonb, NULL);
```

**Changed:** `rolebyte.tenant_role_delete` now also refuses a role that an active member service reports placed,
with `membership:conflict` and the count. Nothing to do on upgrade: until a service reports a placement, every
delete answers as before.

### Added — what a tenant has decides which of its roles' permissions reach a token

A tenant now has a part of the catalog services declare: a whole service, or one feature of it, recorded in
the new table `rolebyte.tenant_entitlement` (migration `V8`, a new empty table). A permission a tenant role ticks
reaches `rolebyte.resolve` only while the tenant has its feature; a feature covers the features nested under it.

```
CALL rolebyte.entitlement_grant('{"actor":"op:you","tenantId":"01J…","service":"projects"}'::jsonb, NULL);
CALL rolebyte.entitlement_revoke('{"actor":"op:you","tenantId":"01J…","service":"projects"}'::jsonb, NULL);
CALL rolebyte.entitlement_list('{"tenantId":"01J…"}'::jsonb, NULL);
```

Revoking deletes nothing the tenant configured: its roles keep their permissions, which come back when the
entitlement does. The three procedures are **not** granted to `rolebyte_public`; the deployment's operator calls
them as the location's owner. A service's `group:level` role is never filtered, so **a person holding no tenant
role resolves exactly as before**. **If you grant tenant roles:** entitle each such tenant after applying this
image, or its roles' permissions stop reaching tokens.

### Changed — `rolebyte.resolve` answers what a granted tenant role holds

Each membership's `scopes` now carries every permission a granted tenant role of that membership ticks,
spelled as it travels, beside the `group:level` strings its service roles give:

```
{"subjectKey":"sub:01J…"}
→ {"memberships":[{"tenantId":"01J…","userId":"01J…","displayName":"…",
                   "scopes":["projects/spentTime:view","projects/task:edit","projects:log"]}]}
```

**A person holding no tenant role resolves byte for byte as before** (asserted by `unit.rolebyte_resolve.sql`
against the previous aggregation). The list stays distinct; its order is the database collation's and is not
part of the contract. No signature change and no new migration.

### Added — a tenant defines its own roles

A role was always a service's: one `group:level` rung, the same on every tenant. A tenant can now make
**its own roles** out of the permissions services declare, name them as it names them, and change them at
will. A tenant role is identified by its id; its name is a label, unique in the tenant ignoring case, and
one role may hold permissions of several services. What a granted role holds reaches `rolebyte.resolve`
(below).

```
rolebyte.tenant_role_define        {"actor":"…","tenantId":"…","name":"Manager"}
  → {"id":"…","name":"Manager","description":"","permissions":[]}
rolebyte.tenant_role_permissions_set {"actor":"…","tenantId":"…","roleId":"…",
                                    "permissions":["projects/task:edit","projects/spentTime:view"]}
  → {"id":"…","permissions":[…],"added":[…],"removed":[],"changed":true}
```

Beside them: `tenant_role_list`, `tenant_role_update` (rename; an absent description keeps the one there),
`tenant_role_delete` (**refused with `membership:conflict` while anybody holds the role**), and
`tenant_role_grant` / `tenant_role_revoke` by the role's id. A tick naming a permission nobody declared is
`membership:unknown_permission` and changes nothing. A role of another tenant answers exactly as one that
never existed. Every change is an attributed event under new kinds (`tenantRoleDefined` … `tenantRoleRevoked`),
none of which carries a `service`.

New migration `rolebyte/V7__tenant_role.sql`. It rewrites no row. It adds `UNIQUE (tenant_id, id)` to
`rolebyte.user_account`, which refuses nothing and builds one index, so that a grant can reference a person
and a role **together with their tenant**: a grant joining two tenants cannot be stored at all. Apply the
schema before a rolebyte service that uses these procedures; an older service is unaffected.

### Added — `rolebyte.permission_declare`: a service declares the permissions it enforces

A service could declare its roles (one `group:level` rung each) and nothing finer. It can now also
declare **permissions**: one act on one feature, spelled `<service>/<feature path>:<act>`, for example
`projects/task/attachment:deleteAny`. The feature path may nest, and nesting grants nothing. Declaring
changes nothing that anybody holds: no role carries a permission and no token contains one yet.

```
{"actor":"…","service":"projects",
 "permission":{"feature":"task/attachment","act":"deleteAny","description":"…","class":"ordinary"}}
→ {"permission":"projects/task/attachment:deleteAny","status":"added"}
```

The status is `added`, `unchanged`, or `changed` for a new description. **A permission's `class`**
(`ordinary` · `tenantConfiguration` · `roleManagement`) **never changes**: a declaration naming a
different class is refused with `membership:conflict`, naming the permission. **An unknown property is
refused** with `membership:invalid` rather than dropped. The configuration section carries
`services[].permissions[]` beside `roles`: `config_get` answers it, and `config_apply` declares it and
rolls the whole section back on any refused entry.

New migration `rolebyte/V6__service_permission.sql`. It rewrites no row.

### Changed — a role's group may no longer contain `/`

`/` now marks a permission, so `rolebyte.role_define` refuses such a group with `membership:invalid`
and the table checks it too. The migration confirms first that no existing role group contains one; if
one does, it stops and says so rather than rewriting anything.

## v0.2.0

### Added — `rolebyte.user_list`: the tenant's people, by name, for a picker

A screen that shows who holds a piece of work has to put a name to the opaque key the work is
attributed to, and almost nobody who may read that work may also read the membership
administration. `rolebyte.user_list(jsonb, jsonb)` answers only that question: for one tenant,
every member's `id`, `subjectKey`, `displayName` and `status`, ordered by name. No roles, no
grants, no history, no identity code.

```
{"tenantId": "01M…"}
→ {"users":[{"id":"01M…","subjectKey":"sub:01HZ…","displayName":"Anna Kalniņa","status":"active"}]}
```

**Service accounts are excluded inside the procedure, not by the caller.** A service account is a
member row like any other, so a list that returned every member would offer the storage service as
a person to assign work to.

**Revoked members ARE returned, with their status saying so.** Work attributed to somebody who has
left still has to show their name, and the caller decides for itself whether to offer them. An
anonymised row carries whatever name the erasure left behind.

Refuses `membership:invalid` with no `tenantId` and `tenant:not_found` for a tenant that does not
exist. Granted to `rolebyte_public`. This is a new procedure in the repeatable `rolebyte`
migration — nothing else in that location changed, and re-applying it is the whole upgrade.

### Changed — the identity helpers move out of `util` into their own `util_identity` location

**Act on this: add `util_identity` to your `LOCATIONS`, immediately after `util`.** It is not caught if
you forget. The runner refuses a location you *name* that does not exist; it cannot know about one you
failed to name. Leave it out and the migration succeeds, the five identity functions are never created,
and the first procedure that calls `util.canonical_identity` fails at run time instead of at migration
time.

What moved: `util/V2__canonical_identity.sql` and `util/V3__identity_display_keeps_the_code.sql` become
`util_identity/V1__` and `util_identity/V2__`. They still create their functions in the **`util`
schema** — a location is a packaging unit, not a schema, the same way `grants` is. Same functions, same
signatures, same behaviour. Both files are `CREATE OR REPLACE FUNCTION` only, so a database that already
has them re-applies them as a no-op under the new history table; nothing is dropped and no data moves.

`util` keeps the primitives every schema uses: `generate_ulid()`, `result_success()`, `result_error()`.

Why: a deployment that needs the identifier generator and the result envelope does not necessarily need
identity-code canonicalisation, and until now it had no way to say so, because a location ships as a
whole directory.

### Added — third-party notices, and an MIT marker on the trust-anchor schema

**Act on this if you redistribute this repository or the image.** The body of `util.generate_ulid` is
third-party code — `geckoboard/pgulid`, Copyright 2016 The Oklog Authors, Apache License 2.0 — adapted
for this schema set, and it had been shipping without the notice its licence requires. It now carries
the upstream notice and a statement that the file was modified, and the new `THIRD-PARTY-NOTICES.md`
carries the entry plus the full Apache-2.0 text, so a copy of the licence reaches every recipient.

The two trust-anchor migration files also carry an SPDX `MIT` marker: that schema is MIT wherever it
travels, independently of this repository's own licence.

Nothing executable changed — comments and one new file. The `util` and `trust_anchor` versioned
migrations change checksum as a result, so a database that has already applied them needs its
migration baseline moved rather than a re-run.

### Added — a document can be kept until its owner releases it, owned by a product (`document/V12`, `R__`)

Every document in this schema has belonged to a **person** and been swept after its retention window.
A file a product keeps on an organisation's behalf is neither: it belongs to that organisation, and it
has to still be there next year.

`document.document` gains **`retention_class`** (`ttl` | `durable`, default `ttl`), which says **who
decides** when a document goes — the service or its owner — and **not** whether a date exists. The
`NOT NULL` on `retention_until` is dropped: a durable document its owner has not dated carries no date
at all, rather than a placeholder a later reader would believe.

**Applying this is cheap.** One column with a default and one dropped `NOT NULL` — catalogue-only, **no
table rewrite, no backfill, no long lock**. Every row already stored reads as `ttl`, which is exactly how
it already behaved.

### Changed — the retention sweep skips a document with no date, and deliberately does not read the class

`document.sweep_retention`'s filter becomes `retention_until IS NOT NULL AND retention_until < now`.

What protects a document is **having no date**. A durable document whose owner set a date — an
organisation's own data-protection policy is exactly that case — is swept when that date passes, like any
other, because that is the owner's own instruction carried out later. A filter that tested the class
instead would turn such a deadline into a suggestion.

### Added — `product`, a third kind of access principal

`ck_document_acl_kind` admits `product` beside `sub` and `serial`, for a document owned by a product
acting for one organisation rather than by a person. The calling service derives that principal from the
credential it authenticated with, never from a request, and a read or a release is additionally checked
against the organisation recorded on the row.

The existing canonical-identity constraint needed no change: it applies only where the principal is an
identity code, so a product principal passes it untouched.

### Changed — `document.acl_allows` has a NEW SIGNATURE; five procedures take new optional inputs

**This is the part to act on.** `document.acl_allows(text, text, text, text)` is **dropped in `V12`** and
recreated by the repeatable file with a fifth parameter. It is an internal helper with no
`document_public` `EXECUTE` grant, so nothing outside this schema calls it — but anything that did would
break.

`document.insert` accepts `owner_kind` (`sub` | `product`) and `retention_class`, and no longer requires
`retention_until` when the class is `durable`. `document.get`, `document.list` and
`document.remove_access` accept `caller_product` and `caller_tenant`. **All optional** — omitting them
gives exactly today's behaviour, so no existing caller changes.


### Added — a tenant's attached directory: its people are admitted as members with no grants (`rolebyte/V5`, `directory_attach`, `directory_admit`)

An organisation whose people sign in through their own directory names that directory on its tenant — the
issuer of the identity provider it trusts as its own. `rolebyte/V5` adds a nullable `tenant.directory_issuer`,
a partial unique index (**one directory belongs to at most one tenant**) and a shape check (an absolute
http(s) URL with no whitespace, query or fragment; stored exactly as given and matched byte for byte, which is
how identity providers compare issuers). No existing row is touched.

Two procedures, both granted to `rolebyte_public`:

```
CALL rolebyte.directory_attach('{"actor":"…","tenantId":"…","issuer":"https://login.example/tenant-id/v2.0"}', po);
→ {"result":"success","data":{"tenantId":"…","issuer":"https://login.example/tenant-id/v2.0","changed":true}}
   an empty or missing issuer detaches · the same issuer again answers changed:false · another tenant's issuer is membership:conflict

CALL rolebyte.directory_admit('{"actor":"…","subjectKey":"sub:01J8X2K4M9N7P3Q5R6S8T0V1W2","issuer":"https://login.example/tenant-id/v2.0","displayName":"…"}', po);
→ {"result":"success","data":{"outcome":"admitted","tenantId":"…","admitted":[{"userId":"…","tenantId":"…"}]}}
   outcome: admitted · member (already active, nothing changed) · revoked (an administrator's revocation stands) · noDirectory (nobody attached this issuer, nobody admitted)
```

An admitted person is an **active member with no grants** — `resolve` answers the tenant with an empty scope
set until an administrator grants a role. Only a person (`sub:<person id>`) is admitted; a service account is
`membership:invalid`. Nothing but the issuer decides the tenant. A person invited by an administrator who then
arrives through the directory is admitted on their invited row, roles kept. Three new event kinds —
`directoryAttached` (with the previous issuer when replaced), `directoryDetached`, `directoryAdmitted` — and
the configuration document (`config_get` / `config_apply`) carries `tenant.directory.issuer`; a document
attaches or replaces, never detaches.

**What a deployment must act on.** Apply this image before the membership service version that exposes the
doors and the authorization server that calls the admission at first login. Nothing to provision; no new
role, no new location. The migration is a new versioned file (`rolebyte/V5`).

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
util.identity_display('PNOEE-XXXXXXXXXXX')  ->  PNOEE-XXXXXXXXXXX   (was XXXXXXXXXXX)
util.identity_display('NTRLV-XXXXXXXXXXX')  ->  NTRLV-XXXXXXXXXXX   (was XXXXXXXXXXX)
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

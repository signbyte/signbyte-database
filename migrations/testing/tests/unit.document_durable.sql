-- Unit test: a document kept until its owner releases it, owned by a product acting
-- for one organisation.
--
-- Two capabilities, and the properties that make them worth having:
--   * WHO DECIDES THE DATE. A document may be stored with no retention date at all,
--     and then nothing removes it. Its owner may instead set a date of its own — an
--     organisation's data-protection policy is exactly that case — and when that date
--     passes the document goes, like any other. So the pair of sweep assertions below
--     is the whole rule: a dateless document survives, a dated one does not, and the
--     class it carries decides neither. Either assertion alone would pass against an
--     implementation that simply skipped the class, which is the bug worth catching.
--   * WHO OWNS IT. A product acting for an organisation is a third kind of principal,
--     beside a person and an invited signatory. A product reaching for another
--     organisation's document is told it does not exist — in the same words, to the
--     byte, as a document that was never stored, because anything else confirms the
--     id. And because the ownership names the product and the organisation and never
--     the credential, the same owner reads and releases after its credential changes.
--
-- The principal is an opaque string to the database: it is compared whole and never
-- parsed here, so these assertions hold whatever spelling the calling service uses.
--
-- Runs as the owner (which owns the SECURITY DEFINER procedures, so it may CALL them
-- regardless of the EXECUTE grants). ON_ERROR_STOP + RAISE EXCEPTION on a failed
-- assertion fails the build.
--   psql -v ON_ERROR_STOP=1 -f migrations/testing/tests/unit.document_durable.sql

DO $$
DECLARE
    v          jsonb;
    v_absent   jsonb;
    v_org_a    text := 'unit-durable-org-a';
    v_org_b    text := 'unit-durable-org-b';
    v_prod_a   text := 'product:unit-durable-product:unit-durable-org-a';
    v_prod_b   text := 'product:unit-durable-product:unit-durable-org-b';
    v_person   text := 'unit-durable-person';
    v_kept     text;   -- durable, no date       — must survive the sweep
    v_dated    text;   -- durable, owner-dated   — must NOT survive once the date passes
    v_ttl      text;   -- ttl, dated             — the unchanged behaviour
    v_hold     text;   -- durable, on legal hold — release must refuse
    v_status   text;
    v_class    text;
    v_ref      text;
    v_until    timestamptz;
    v_n        integer;
BEGIN
    -- ------------------------------------------------------------- refusals
    -- Each of these must be refused BEFORE anything is written: a caller who gets an
    -- error must not also get a row.
    CALL document.insert(jsonb_build_object(
        'owner', v_person, 'content_hash', 'h', 'mime', 'application/pdf', 'size', 1,
        'retention_until', (now() + interval '1 day')::text,
        'retention_class', 'forever'), v);
    IF v->>'code' IS DISTINCT FROM 'document:invalid' THEN
        RAISE EXCEPTION 'an unknown retention class must be refused: %', v;
    END IF;

    -- A product owns on behalf of an organisation. Without one there is nobody
    -- identifiable to release the document later, which is the one state that cannot
    -- be recovered from.
    CALL document.insert(jsonb_build_object(
        'owner', v_prod_a, 'owner_kind', 'product',
        'content_hash', 'h', 'mime', 'application/pdf', 'size', 1,
        'retention_class', 'durable'), v);
    IF v->>'code' IS DISTINCT FROM 'document:invalid' THEN
        RAISE EXCEPTION 'a product-owned document with no organisation must be refused: %', v;
    END IF;

    -- A date already in the past means "remove this at the next opportunity", which is
    -- almost never what a caller setting a retention policy meant.
    CALL document.insert(jsonb_build_object(
        'owner', v_prod_a, 'owner_kind', 'product', 'tenant_id', v_org_a,
        'content_hash', 'h', 'mime', 'application/pdf', 'size', 1,
        'retention_class', 'durable',
        'retention_until', (now() - interval '1 day')::text), v);
    IF v->>'code' IS DISTINCT FROM 'document:invalid' THEN
        RAISE EXCEPTION 'a retention date already in the past must be refused: %', v;
    END IF;

    -- The service still owns the clock for the default class, so a date is still
    -- required there. This is the assertion that fails if the new class is allowed to
    -- loosen the old one.
    CALL document.insert(jsonb_build_object(
        'owner', v_person, 'content_hash', 'h', 'mime', 'application/pdf', 'size', 1), v);
    IF v->>'code' IS DISTINCT FROM 'document:invalid' THEN
        RAISE EXCEPTION 'a service-dated document must still require its date: %', v;
    END IF;

    -- ------------------------------------------------------------- the fixture
    CALL document.insert(jsonb_build_object(
        'owner', v_prod_a, 'owner_kind', 'product', 'tenant_id', v_org_a,
        'content_hash', 'kept', 'mime', 'application/pdf', 'size', 10,
        'filename', 'kept.pdf', 'storage_ref', 'obj-kept',
        'encryption_key_ref', 'key-kept',
        'retention_class', 'durable'), v);
    IF v->>'result' IS DISTINCT FROM 'success' THEN
        RAISE EXCEPTION 'fixture: the dateless durable document was refused: %', v;
    END IF;
    v_kept := v->'data'->>'id';

    CALL document.insert(jsonb_build_object(
        'owner', v_prod_a, 'owner_kind', 'product', 'tenant_id', v_org_a,
        'content_hash', 'dated', 'mime', 'application/pdf', 'size', 10,
        'storage_ref', 'obj-dated', 'encryption_key_ref', 'key-dated',
        'retention_class', 'durable',
        'retention_until', (now() + interval '365 days')::text), v);
    IF v->>'result' IS DISTINCT FROM 'success' THEN
        RAISE EXCEPTION 'fixture: the owner-dated durable document was refused: %', v;
    END IF;
    v_dated := v->'data'->>'id';

    CALL document.insert(jsonb_build_object(
        'owner', v_person, 'content_hash', 'ttl', 'mime', 'application/pdf', 'size', 10,
        'storage_ref', 'obj-ttl', 'encryption_key_ref', 'key-ttl',
        'retention_until', (now() + interval '1 day')::text), v);
    v_ttl := v->'data'->>'id';

    CALL document.insert(jsonb_build_object(
        'owner', v_prod_a, 'owner_kind', 'product', 'tenant_id', v_org_a,
        'content_hash', 'hold', 'mime', 'application/pdf', 'size', 10,
        'storage_ref', 'obj-hold', 'encryption_key_ref', 'key-hold',
        'retention_class', 'durable'), v);
    v_hold := v->'data'->>'id';
    UPDATE document.document SET legal_hold = true WHERE id = v_hold;

    -- ------------------------------------------------- what was actually stored
    SELECT retention_class, retention_until INTO v_class, v_until
    FROM document.document WHERE id = v_kept;
    IF v_class IS DISTINCT FROM 'durable' OR v_until IS NOT NULL THEN
        RAISE EXCEPTION 'a dateless durable document must be stored with no date: class=% until=%',
            v_class, v_until;
    END IF;

    SELECT retention_class, retention_until INTO v_class, v_until
    FROM document.document WHERE id = v_dated;
    IF v_class IS DISTINCT FROM 'durable' OR v_until IS NULL THEN
        RAISE EXCEPTION 'an owner-dated durable document must keep its date: class=% until=%',
            v_class, v_until;
    END IF;

    -- Every document stored before this existed is service-dated, and so is every one
    -- stored without asking for anything else.
    SELECT retention_class INTO v_class FROM document.document WHERE id = v_ttl;
    IF v_class IS DISTINCT FROM 'ttl' THEN
        RAISE EXCEPTION 'the default retention class must be the service-dated one, got %', v_class;
    END IF;

    -- The access entry names the product, and the organisation travels with it. This
    -- also proves the identity-code constraint stays off a principal that is not one:
    -- an unconditional version of it would have refused every insert above.
    SELECT count(*) INTO v_n FROM document.document_acl
     WHERE chain_root_id = v_kept AND principal_kind = 'product'
       AND principal_id = v_prod_a AND tenant_id = v_org_a;
    IF v_n <> 1 THEN
        RAISE EXCEPTION 'the product must hold exactly one access entry, found %', v_n;
    END IF;

    -- ------------------------------------------------------------ the sweep
    -- The owner's date is moved into the past directly: the sweep reads the clock
    -- column and a test cannot wait a year.
    UPDATE document.document
       SET retention_until = now() - interval '1 day'
     WHERE id = v_dated;
    UPDATE document.document
       SET retention_until = now() - interval '1 day'
     WHERE id = v_ttl;

    CALL document.sweep_retention(jsonb_build_object('now', now()::text), v);
    IF v->>'result' IS DISTINCT FROM 'success' THEN
        RAISE EXCEPTION 'the sweep failed: %', v;
    END IF;

    -- (1) No date, so nothing to act on: it stands, with its bytes.
    SELECT status, storage_ref INTO v_status, v_ref FROM document.document WHERE id = v_kept;
    IF v_status IS DISTINCT FROM 'received' OR v_ref IS NULL THEN
        RAISE EXCEPTION 'a durable document with no date must survive the sweep: status=% ref=%',
            v_status, v_ref;
    END IF;

    -- (2) The owner set a date and it has passed: the document goes. This is the
    -- owner's own instruction carried out later, not the store overruling the owner —
    -- and it is what makes an organisation's retention policy a control rather than a
    -- promise.
    SELECT status, storage_ref INTO v_status, v_ref FROM document.document WHERE id = v_dated;
    IF v_status IS DISTINCT FROM 'expired' OR v_ref IS NOT NULL THEN
        RAISE EXCEPTION 'a durable document whose own date has passed must be swept: status=% ref=%',
            v_status, v_ref;
    END IF;

    -- (3) The behaviour that already existed is untouched.
    SELECT status INTO v_status FROM document.document WHERE id = v_ttl;
    IF v_status IS DISTINCT FROM 'expired' THEN
        RAISE EXCEPTION 'a service-dated document past its date must still be swept, got %', v_status;
    END IF;

    -- A legal hold outranks a date, as it always has.
    SELECT status INTO v_status FROM document.document WHERE id = v_hold;
    IF v_status IS DISTINCT FROM 'received' THEN
        RAISE EXCEPTION 'a document on legal hold must not be swept, got %', v_status;
    END IF;

    -- ------------------------------------------------ who can read it, and who cannot
    CALL document.get(jsonb_build_object(
        'id', v_kept, 'caller_product', v_prod_a, 'caller_tenant', v_org_a), v);
    IF v->>'result' IS DISTINCT FROM 'success' THEN
        RAISE EXCEPTION 'the owning product must be able to read its own document: %', v;
    END IF;

    -- The credential changed; the owner did not. Nothing about the subject presenting
    -- the request takes part in the decision, which is what keeps a rotated secret from
    -- orphaning every document it stored.
    CALL document.get(jsonb_build_object(
        'id', v_kept, 'caller_sub', 'a-completely-different-subject',
        'caller_product', v_prod_a, 'caller_tenant', v_org_a), v);
    IF v->>'result' IS DISTINCT FROM 'success' THEN
        RAISE EXCEPTION 'the owning product must still read after its credential changes: %', v;
    END IF;

    -- Another organisation's product is told the document does not exist...
    CALL document.get(jsonb_build_object(
        'id', v_kept, 'caller_product', v_prod_b, 'caller_tenant', v_org_b), v);
    IF v->>'code' IS DISTINCT FROM 'document:not_found' THEN
        RAISE EXCEPTION 'another organisation must not reach this document: %', v;
    END IF;

    -- ...in exactly the words a document that was never stored gets. A refusal that
    -- reads differently from absence confirms the id to whoever is guessing.
    CALL document.get(jsonb_build_object(
        'id', 'no-such-document-at-all', 'caller_product', v_prod_b,
        'caller_tenant', v_org_b), v_absent);
    IF v IS DISTINCT FROM v_absent THEN
        RAISE EXCEPTION 'a foreign read must be indistinguishable from an absent one: % vs %',
            v, v_absent;
    END IF;

    -- A person is not on a product's document at all, however the request is shaped.
    CALL document.get(jsonb_build_object('id', v_kept, 'caller_sub', v_person), v);
    IF v->>'code' IS DISTINCT FROM 'document:not_found' THEN
        RAISE EXCEPTION 'a person must not reach a product-owned document: %', v;
    END IF;

    -- The listing answers the same question the same way.
    CALL document.list(jsonb_build_object(
        'caller_product', v_prod_a, 'caller_tenant', v_org_a), v);
    SELECT count(*) INTO v_n
    FROM jsonb_array_elements(v->'data'->'documents') d
    WHERE d->>'id' = v_kept;
    IF v_n <> 1 THEN
        RAISE EXCEPTION 'the owning product must see its document in its own listing: %', v;
    END IF;

    CALL document.list(jsonb_build_object(
        'caller_product', v_prod_b, 'caller_tenant', v_org_b), v);
    IF jsonb_array_length(v->'data'->'documents') <> 0 THEN
        RAISE EXCEPTION 'another organisation must see nothing: %', v;
    END IF;

    -- ------------------------------------------------------------- the release
    -- A legal hold refuses it, as it does for anyone else.
    CALL document.remove_access(jsonb_build_object(
        'doc_id', v_hold, 'caller_product', v_prod_a, 'caller_tenant', v_org_a), v);
    IF v->>'code' IS DISTINCT FROM 'document:legal_hold' THEN
        RAISE EXCEPTION 'a release must refuse under legal hold: %', v;
    END IF;

    -- Another organisation cannot release what it cannot read.
    CALL document.remove_access(jsonb_build_object(
        'doc_id', v_kept, 'caller_product', v_prod_b, 'caller_tenant', v_org_b), v);
    IF v->>'code' IS DISTINCT FROM 'document:not_found' THEN
        RAISE EXCEPTION 'another organisation must not release this document: %', v;
    END IF;

    -- The owner's own delete is the release: the entry goes, and with nothing left
    -- holding the document, so do the bytes.
    CALL document.remove_access(jsonb_build_object(
        'doc_id', v_kept, 'caller_product', v_prod_a, 'caller_tenant', v_org_a), v);
    IF v->>'result' IS DISTINCT FROM 'success' THEN
        RAISE EXCEPTION 'the owning product must be able to release its document: %', v;
    END IF;
    IF jsonb_array_length(v->'data'->'purged') <> 1 THEN
        RAISE EXCEPTION 'the release must report the bytes it destroyed: %', v;
    END IF;

    SELECT status, storage_ref INTO v_status, v_ref FROM document.document WHERE id = v_kept;
    IF v_status IS DISTINCT FROM 'deleted' OR v_ref IS NOT NULL THEN
        RAISE EXCEPTION 'a released document must be terminal with no bytes: status=% ref=%',
            v_status, v_ref;
    END IF;

    CALL document.get(jsonb_build_object(
        'id', v_kept, 'caller_product', v_prod_a, 'caller_tenant', v_org_a), v);
    IF v->>'code' IS DISTINCT FROM 'document:not_found' THEN
        RAISE EXCEPTION 'a released document must no longer be found: %', v;
    END IF;

    -- ---------------------------------------------------------------- cleanup
    DELETE FROM document.document_acl
     WHERE principal_id IN (v_prod_a, v_prod_b, v_person);
    DELETE FROM document.document
     WHERE owner IN (v_prod_a, v_prod_b, v_person);

    RAISE NOTICE 'unit.document_durable: all assertions passed';
END $$;

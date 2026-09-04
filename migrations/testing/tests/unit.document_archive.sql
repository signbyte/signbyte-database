-- Unit test: the archive-timestamp refresh records its preservation class in the
-- SAME write as the swapped bytes. The fact and the bytes commit together: a
-- refused class leaves the document untouched, a swapped document always carries
-- the class, and the separate setter that once wrote the fact as a second step
-- (which only the uploader could pass) no longer exists.
-- Runs as the owner (which owns the SECURITY DEFINER procedures, so it may CALL
-- them regardless of the EXECUTE grants). ON_ERROR_STOP + RAISE EXCEPTION on a
-- failed assertion fails the build.
--   psql -v ON_ERROR_STOP=1 -f migrations/testing/tests/unit.document_archive.sql

DO $$
DECLARE
    v       jsonb;
    v_owner text := 'unit-archive-owner';
    v_doc   text;
BEGIN
    -- ---------------------------------------------------------------- fixture
    -- A signed container that heads its own chain — the shape an archive refresh
    -- replaces in place.
    CALL document.insert(jsonb_build_object(
        'owner', v_owner, 'kind', 'container', 'filename', 'signed.asice',
        'content_hash', 'hash-arch-1', 'mime', 'application/vnd.etsi.asic-e+zip',
        'status', 'signed', 'size', 1000,
        'retention_until', (now() + interval '1 day')::text), v);
    IF v->>'result' IS DISTINCT FROM 'success' THEN
        RAISE EXCEPTION 'insert of the signed container failed: %', v;
    END IF;
    v_doc := v->'data'->>'id';

    -- (1) A plain replace (a co-sign merge) leaves the class as it was.
    CALL document.replace_container_blob(jsonb_build_object(
        'id', v_doc, 'expected_hash', 'hash-arch-1',
        'storage_ref', 'blob/2', 'content_hash', 'hash-arch-2',
        'size', 1100, 'encryption_key_ref', 'key-2'), v);
    IF v->>'result' IS DISTINCT FROM 'success' THEN
        RAISE EXCEPTION 'plain replace failed: %', v;
    END IF;
    IF v->'data'->'document'->>'preservation_class' IS DISTINCT FROM 'none' THEN
        RAISE EXCEPTION 'a replace without a class must not change it: %', v;
    END IF;

    -- (2) An unknown class is refused BEFORE any write: the bytes stay.
    CALL document.replace_container_blob(jsonb_build_object(
        'id', v_doc, 'expected_hash', 'hash-arch-2',
        'storage_ref', 'blob/3', 'content_hash', 'hash-arch-3',
        'size', 1200, 'encryption_key_ref', 'key-3',
        'preservation_class', 'forever'), v);
    IF v->>'result' IS DISTINCT FROM 'error' OR v->>'code' IS DISTINCT FROM 'document:invalid' THEN
        RAISE EXCEPTION 'an unknown class must be refused as document:invalid: %', v;
    END IF;
    CALL document.get(jsonb_build_object('id', v_doc, 'caller_sub', v_owner), v);
    IF v->'data'->>'content_hash' IS DISTINCT FROM 'hash-arch-2'
       OR v->'data'->>'preservation_class' IS DISTINCT FROM 'none' THEN
        RAISE EXCEPTION 'a refused class must leave the row untouched: %', v;
    END IF;

    -- (3) The archive-timestamp refresh: swap + class in ONE call, and the returned row
    --     already carries both.
    CALL document.replace_container_blob(jsonb_build_object(
        'id', v_doc, 'expected_hash', 'hash-arch-2',
        'storage_ref', 'blob/3', 'content_hash', 'hash-arch-3',
        'size', 1200, 'encryption_key_ref', 'key-3',
        'preservation_class', 'preservation'), v);
    IF v->>'result' IS DISTINCT FROM 'success' THEN
        RAISE EXCEPTION 'archive-timestamp refresh failed: %', v;
    END IF;
    IF v->'data'->'document'->>'preservation_class' IS DISTINCT FROM 'preservation'
       OR v->'data'->'document'->>'content_hash' IS DISTINCT FROM 'hash-arch-3' THEN
        RAISE EXCEPTION 'the returned row must carry the new bytes AND the class: %', v;
    END IF;
    CALL document.get(jsonb_build_object('id', v_doc, 'caller_sub', v_owner), v);
    IF v->'data'->>'preservation_class' IS DISTINCT FROM 'preservation'
       OR v->'data'->>'content_hash' IS DISTINCT FROM 'hash-arch-3' THEN
        RAISE EXCEPTION 'bytes and class must land together on the row: %', v;
    END IF;

    -- (4) The CAS still guards the archive-timestamp refresh: a stale hash is refused with
    --     the class NOT applied.
    CALL document.replace_container_blob(jsonb_build_object(
        'id', v_doc, 'expected_hash', 'hash-arch-2',
        'storage_ref', 'blob/4', 'content_hash', 'hash-arch-4',
        'size', 1300, 'encryption_key_ref', 'key-4',
        'preservation_class', 'b_lt'), v);
    IF v->>'result' IS DISTINCT FROM 'error' OR v->>'code' IS DISTINCT FROM 'document:chain_advanced' THEN
        RAISE EXCEPTION 'a stale hash must still be refused as chain_advanced: %', v;
    END IF;
    CALL document.get(jsonb_build_object('id', v_doc, 'caller_sub', v_owner), v);
    IF v->'data'->>'preservation_class' IS DISTINCT FROM 'preservation' THEN
        RAISE EXCEPTION 'a refused swap must not touch the class: %', v;
    END IF;

    -- (5) The second-step setter is gone: the fact has exactly one writer.
    IF EXISTS (SELECT 1
                 FROM pg_proc p
                 JOIN pg_namespace n ON n.oid = p.pronamespace
                WHERE n.nspname = 'document' AND p.proname = 'set_preservation_class') THEN
        RAISE EXCEPTION 'document.set_preservation_class must no longer exist';
    END IF;

    RAISE NOTICE 'unit.document_archive: OK';
END
$$;

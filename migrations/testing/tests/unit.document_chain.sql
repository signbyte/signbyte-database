-- Unit test: the chain projection — one derivation, three readers.
-- The live listing, the single-chain read and the history listing must agree
-- about the same document, in particular about the two signed-ness facts. The
-- case that matters most here is a chain signed IN PLACE (no child row, only a
-- signature timestamp): reading only the parent link calls such a chain unsigned,
-- which is exactly how a completed signing came to render as a draft.
-- Runs as the owner (which owns the SECURITY DEFINER procedures, so it may CALL
-- them regardless of the EXECUTE grants). ON_ERROR_STOP + RAISE EXCEPTION on a
-- failed assertion fails the build.
--   psql -v ON_ERROR_STOP=1 -f migrations/testing/tests/unit.document_chain.sql

DO $$
DECLARE
    v          jsonb;
    v_owner    text := 'unit-chain-owner';
    v_stranger text := 'unit-chain-stranger';
    v_inplace  text;   -- a container signed in place (root-headed chain)
    v_pre      text;   -- an upload that arrived already signed
    v_src      text;   -- a plain source, later signed into a child container
    v_child    text;
    v_chain    jsonb;
BEGIN
    -- ---------------------------------------------------------------- fixtures
    -- (1) A container the platform signs IN PLACE — the bundle case: the chain's
    --     head IS its root, and the only evidence of the signature is signed_at.
    CALL document.insert(jsonb_build_object(
        'owner', v_owner, 'kind', 'container', 'filename', 'in-place.asice',
        'content_hash', 'hash-inplace-1', 'mime', 'application/vnd.etsi.asic-e+zip',
        'size', 1024, 'retention_until', (now() + interval '1 day')::text,
        'inner_files', jsonb_build_array(jsonb_build_object('name', 'a.pdf'))), v);
    IF v->>'result' IS DISTINCT FROM 'success' THEN
        RAISE EXCEPTION 'insert of the in-place container failed: %', v;
    END IF;
    v_inplace := v->'data'->>'id';

    -- (2) An upload that ARRIVED signed — same kind, but no signature was applied
    --     here, so it stays a draft the user can act on.
    CALL document.insert(jsonb_build_object(
        'owner', v_owner, 'kind', 'container', 'filename', 'pre-signed.asice',
        'content_hash', 'hash-pre-1', 'mime', 'application/vnd.etsi.asic-e+zip',
        'size', 2048, 'retention_until', (now() + interval '1 day')::text), v);
    v_pre := v->'data'->>'id';

    -- (3) A plain source with a signed child container — the classic chain.
    CALL document.insert(jsonb_build_object(
        'owner', v_owner, 'kind', 'source', 'filename', 'plain.pdf',
        'content_hash', 'hash-src-1', 'mime', 'application/pdf',
        'size', 512, 'retention_until', (now() + interval '1 day')::text), v);
    v_src := v->'data'->>'id';
    CALL document.insert(jsonb_build_object(
        'owner', v_owner, 'kind', 'container', 'parent_id', v_src,
        'filename', 'plain.asice', 'content_hash', 'hash-child-1',
        'mime', 'application/vnd.etsi.asic-e+zip', 'status', 'signed',
        'size', 900, 'retention_until', (now() + interval '1 day')::text), v);
    v_child := v->'data'->>'id';

    -- Sign (1) in place, through the procedure that really does it.
    CALL document.replace_container_blob(jsonb_build_object(
        'id', v_inplace, 'expected_hash', 'hash-inplace-1',
        'storage_ref', 'blob/signed', 'content_hash', 'hash-inplace-2',
        'size', 1500, 'encryption_key_ref', 'key-1'), v);
    IF v->>'result' IS DISTINCT FROM 'success' THEN
        RAISE EXCEPTION 'in-place signing failed: %', v;
    END IF;

    -- ------------------------------------------------- the single-chain read
    CALL document.get_chain(jsonb_build_object('caller_sub', v_owner, 'id', v_inplace), v);
    IF v->>'result' IS DISTINCT FROM 'success' THEN
        RAISE EXCEPTION 'get_chain on the in-place-signed chain failed: %', v;
    END IF;
    v_chain := v->'data'->'chain';
    -- THE regression this test exists for: signed in place, no child row.
    IF (v_chain->>'platform_signed')::boolean IS NOT TRUE THEN
        RAISE EXCEPTION 'a chain signed in place must read platform_signed=true: %', v_chain;
    END IF;
    IF (v_chain->>'has_signatures')::boolean IS NOT TRUE THEN
        RAISE EXCEPTION 'a chain signed in place must read has_signatures=true: %', v_chain;
    END IF;
    IF v_chain->>'id' IS DISTINCT FROM v_inplace THEN
        RAISE EXCEPTION 'get_chain returned the wrong head: % want %', v_chain->>'id', v_inplace;
    END IF;
    -- The inner-file manifest rides along, so a container screen needs one read.
    IF v_chain->'inner_files'->0->>'name' IS DISTINCT FROM 'a.pdf' THEN
        RAISE EXCEPTION 'get_chain did not carry the inner files: %', v_chain;
    END IF;

    -- An upload that merely arrived signed is NOT platform-signed.
    CALL document.get_chain(jsonb_build_object('caller_sub', v_owner, 'id', v_pre), v);
    v_chain := v->'data'->'chain';
    IF (v_chain->>'has_signatures')::boolean IS NOT TRUE THEN
        RAISE EXCEPTION 'a pre-signed upload must read has_signatures=true: %', v_chain;
    END IF;
    IF (v_chain->>'platform_signed')::boolean IS NOT FALSE THEN
        RAISE EXCEPTION 'a pre-signed upload must read platform_signed=false: %', v_chain;
    END IF;

    -- Addressed by the ROOT id, a chain with a signed child answers with the
    -- CHILD as its head — the same row the listing would show.
    CALL document.get_chain(jsonb_build_object('caller_sub', v_owner, 'id', v_src), v);
    v_chain := v->'data'->'chain';
    IF v_chain->>'id' IS DISTINCT FROM v_child THEN
        RAISE EXCEPTION 'the root id must resolve to the signed head: % want %', v_chain->>'id', v_child;
    END IF;
    IF v_chain->>'chain_root_id' IS DISTINCT FROM v_src THEN
        RAISE EXCEPTION 'chain_root_id must be the source: %', v_chain;
    END IF;
    -- ...and addressed by the HEAD id it answers with the same chain.
    CALL document.get_chain(jsonb_build_object('caller_sub', v_owner, 'id', v_child), v);
    IF v->'data'->'chain'->>'id' IS DISTINCT FROM v_child
       OR v->'data'->'chain'->>'chain_root_id' IS DISTINCT FROM v_src THEN
        RAISE EXCEPTION 'head id and root id must resolve to the same chain: %', v;
    END IF;

    -- ------------------------------------------------- the listing agrees
    CALL document.list_chains(jsonb_build_object('caller_sub', v_owner), v);
    SELECT c INTO v_chain
    FROM jsonb_array_elements(v->'data'->'chains') c
    WHERE c->>'id' = v_inplace;
    IF v_chain IS NULL THEN
        RAISE EXCEPTION 'the in-place-signed chain is missing from the listing: %', v;
    END IF;
    IF (v_chain->>'platform_signed')::boolean IS NOT TRUE THEN
        RAISE EXCEPTION 'the listing disagrees with the single read about platform_signed: %', v_chain;
    END IF;

    -- ------------------------------------------------- access + not-found
    -- A caller with no access is answered exactly like a caller asking for an id
    -- that does not exist.
    CALL document.get_chain(jsonb_build_object('caller_sub', v_stranger, 'id', v_inplace), v);
    IF v->>'code' IS DISTINCT FROM 'document:not_found' THEN
        RAISE EXCEPTION 'a stranger must get not_found, got: %', v;
    END IF;
    CALL document.get_chain(jsonb_build_object('caller_sub', v_owner, 'id', 'no-such-id'), v);
    IF v->>'code' IS DISTINCT FROM 'document:not_found' THEN
        RAISE EXCEPTION 'an unknown id must get not_found, got: %', v;
    END IF;
    CALL document.get_chain(jsonb_build_object('caller_sub', v_owner), v);
    IF v->>'code' IS DISTINCT FROM 'document:invalid' THEN
        RAISE EXCEPTION 'a missing id must be rejected, got: %', v;
    END IF;
    CALL document.get_chain(jsonb_build_object('id', v_inplace), v);
    IF v->>'code' IS DISTINCT FROM 'document:invalid' THEN
        RAISE EXCEPTION 'a missing caller must be rejected, got: %', v;
    END IF;

    -- ------------------------------------------------- expiry and history
    -- An EXPIRED chain still answers: the screen states the expiry rather than
    -- pretending the record is gone.
    UPDATE document.document SET status = 'expired' WHERE id = v_inplace;
    CALL document.get_chain(jsonb_build_object('caller_sub', v_owner, 'id', v_inplace), v);
    IF v->>'result' IS DISTINCT FROM 'success' OR v->'data'->'chain'->>'status' IS DISTINCT FROM 'expired' THEN
        RAISE EXCEPTION 'an expired chain must still be readable: %', v;
    END IF;

    -- History reads the SAME derivation: a chain signed in place is a completed
    -- record there too, not an unsigned one.
    CALL document.list_history(jsonb_build_object('caller_sub', v_owner), v);
    SELECT c INTO v_chain
    FROM jsonb_array_elements(v->'data'->'chains') c
    WHERE c->>'id' = v_inplace;
    IF v_chain IS NULL THEN
        RAISE EXCEPTION 'the expired chain is missing from history: %', v;
    END IF;
    IF (v_chain->>'platform_signed')::boolean IS NOT TRUE THEN
        RAISE EXCEPTION 'history disagrees about platform_signed on an in-place-signed chain: %', v_chain;
    END IF;

    -- A chain with nothing live left is not found by the single read.
    UPDATE document.document SET status = 'deleted' WHERE id = v_inplace;
    CALL document.get_chain(jsonb_build_object('caller_sub', v_owner, 'id', v_inplace), v);
    IF v->>'code' IS DISTINCT FROM 'document:not_found' THEN
        RAISE EXCEPTION 'a fully deleted chain must not be found: %', v;
    END IF;

    -- ---------------------------------------------------------------- cleanup
    DELETE FROM document.document_acl WHERE granted_by = v_owner;
    DELETE FROM document.document WHERE owner = v_owner;

    RAISE NOTICE 'unit.document_chain: all assertions passed';
END $$;

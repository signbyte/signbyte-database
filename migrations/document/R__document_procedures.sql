-- R: repeatable migration — the `document` store API.
--
-- These back the store.Store interface the document-store service uses. They run
-- as the owner of the table, so the EXECUTE-only `document_public`
-- service role drives them without any table privileges. Each:
--   * uses the uniform JSONB envelope `(pi_data jsonb, INOUT po_data jsonb)`,
--   * pins `search_path` ending in pg_temp (SECURITY DEFINER hardening),
--   * returns a structured result via util.result_success / util.result_error
--     with `document:<reason>` error codes (`:not_found` → 404, else 422),
--   * validates BEFORE any write (Pattern A: return) and, on any unexpected error
--     after a write, re-raises a structured error with SQLSTATE P0001 (Pattern B)
--     so the transaction ROLLS BACK.
--
-- Hashing + envelope encryption stay in Go (the bytes never touch the DB). These
-- procedures only persist + read the METADATA row and enforce ownership.
-- Re-applied whenever the checksum changes.

-- ---------------------------------------------------------------------------
-- ACL helpers (the multi-party access model — V2 `document_acl`). Access to a
-- document chain is granted to its creator at upload and to invited co-signers
-- at workflow send; these helpers are the single authorization predicate the
-- read/co-sign/delete procedures share. Both are invoked INSIDE the SECURITY
-- DEFINER procedures (as the owner), so they need no service grant.
-- ---------------------------------------------------------------------------

-- document.normalize_serial — canonical form of an eIDAS identity code for ACL
-- matching: trims surrounding whitespace and upper-cases, so trivially-different
-- spellings of the same code match. Fuller cross-border normalization (country
-- prefixes, separators) is a planned extension behind THIS seam — callers store
-- and match through this function, so widening it later needs no schema change.
CREATE OR REPLACE FUNCTION document.normalize_serial(p_serial text)
RETURNS text
LANGUAGE sql
IMMUTABLE
RETURNS NULL ON NULL INPUT
SET search_path = pg_temp
AS $$
    SELECT upper(btrim(p_serial));
$$;

-- document.acl_allows — true when the caller holds right p_right on the chain
-- rooted at p_chain_root, EITHER as the owning subject OR as an invited eIDAS
-- serial. Fail-closed: an unknown root, a wrong serial, or a missing right is
-- false (so the read procedures return :not_found — no enumeration).
CREATE OR REPLACE FUNCTION document.acl_allows(
    p_chain_root text, p_sub text, p_serial text, p_right text
) RETURNS boolean
LANGUAGE sql
STABLE
SET search_path = document, pg_temp
AS $$
    SELECT EXISTS (
        SELECT 1 FROM document.document_acl a
        WHERE a.chain_root_id = p_chain_root
          AND p_right = ANY(a.rights)
          AND (
                (a.principal_kind = 'sub'
                    AND p_sub IS NOT NULL AND p_sub <> ''
                    AND a.principal_id = p_sub)
             OR (a.principal_kind = 'serial'
                    AND p_serial IS NOT NULL AND p_serial <> ''
                    AND a.principal_id = document.normalize_serial(p_serial))
          )
    );
$$;

-- document.insert — persist one document metadata row (a `source` upload or an
-- assembled `container`). Hashing + encryption + the S3 put happen in Go BEFORE
-- this call; the row records where the bytes live (storage_ref / encryption_key_ref)
-- and the canonical digest. retention_until is supplied by Go (it owns the 24h
-- clock — distinct from the SignAPI session TTL).
-- pi_data = { owner, content_hash, mime, size, retention_until, [tenant_id],
--             [kind=source|container], [parent_id], [filename], [storage_ref],
--             [encryption_key_ref], [status], [preservation_class] }.
CREATE OR REPLACE PROCEDURE document.insert(pi_data jsonb, INOUT po_data jsonb)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = document, util, pg_temp
AS $$
DECLARE
    v_owner    text := pi_data->>'owner';
    v_hash     text := pi_data->>'content_hash';
    v_mime     text := pi_data->>'mime';
    v_kind     text := COALESCE(pi_data->>'kind', 'source');
    v_status   text := COALESCE(pi_data->>'status', 'received');
    v_presv    text := COALESCE(pi_data->>'preservation_class', 'none');
    v_size     bigint;
    v_retention timestamptz;
    v_id       text;
BEGIN
    -- Pattern A validation (before any write).
    IF v_owner IS NULL OR v_owner = '' THEN
        po_data := util.result_error('document:invalid', 'owner is required');
        RETURN;
    END IF;
    IF v_hash IS NULL OR v_hash = '' THEN
        po_data := util.result_error('document:invalid', 'content_hash is required');
        RETURN;
    END IF;
    IF v_mime IS NULL OR v_mime = '' THEN
        po_data := util.result_error('document:invalid', 'mime is required');
        RETURN;
    END IF;
    IF (pi_data->>'size') IS NULL THEN
        po_data := util.result_error('document:invalid', 'size is required');
        RETURN;
    END IF;
    IF (pi_data->>'retention_until') IS NULL THEN
        po_data := util.result_error('document:invalid', 'retention_until is required');
        RETURN;
    END IF;
    -- source = an unsigned upload; container = a signed ASiC-E; pdf = a PAdES
    -- signature embedded in the PDF (no container). The table CHECK constraint and
    -- the per-chain unique indexes carry the same set.
    IF v_kind NOT IN ('source', 'container', 'pdf') THEN
        po_data := util.result_error('document:invalid', 'kind must be source, container or pdf');
        RETURN;
    END IF;
    IF v_presv NOT IN ('none', 'b_lt', 'preservation') THEN
        po_data := util.result_error('document:invalid', 'invalid preservation_class');
        RETURN;
    END IF;
    IF v_status NOT IN ('received', 'signing', 'signed', 'expired', 'deleted') THEN
        po_data := util.result_error('document:invalid', 'invalid status');
        RETURN;
    END IF;

    v_size      := (pi_data->>'size')::bigint;
    v_retention := (pi_data->>'retention_until')::timestamptz;

    INSERT INTO document.document (
        owner, tenant_id, kind, parent_id, filename, storage_ref,
        content_hash, mime, size, status, encryption_key_ref,
        preservation_class, retention_until, inner_files
    )
    VALUES (
        v_owner,
        NULLIF(pi_data->>'tenant_id', ''),
        v_kind,
        NULLIF(pi_data->>'parent_id', ''),
        COALESCE(pi_data->>'filename', ''),
        NULLIF(pi_data->>'storage_ref', ''),
        v_hash,
        v_mime,
        v_size,
        v_status,
        NULLIF(pi_data->>'encryption_key_ref', ''),
        v_presv,
        v_retention,
        -- The ASiC-E inner-file manifest (a JSON array), captured from go-asice
        -- Inspect at write time; NULL for a plain source. Metadata only.
        pi_data->'inner_files'
    )
    RETURNING id INTO v_id;

    -- A newly-uploaded source (a chain root) seeds its creator's standing access
    -- (read + co-sign); a co-signed container inherits the root's entry, so it
    -- adds none. Same transaction as the row insert, so they commit together.
    IF NULLIF(pi_data->>'parent_id', '') IS NULL THEN
        INSERT INTO document.document_acl (chain_root_id, principal_kind, principal_id, rights, tenant_id, granted_by)
        VALUES (v_id, 'sub', v_owner, ARRAY['read', 'cosign']::text[], NULLIF(pi_data->>'tenant_id', ''), v_owner)
        ON CONFLICT (chain_root_id, principal_kind, principal_id) DO NOTHING;
    END IF;

    po_data := util.result_success(jsonb_build_object('id', v_id));
EXCEPTION
    WHEN SQLSTATE 'P0001' THEN
        RAISE;
    WHEN unique_violation THEN
        -- One live signed artifact per chain root (a container for ASiC-E, or a
        -- signed PDF for PAdES) — enforced by the per-chain unique indexes. A
        -- concurrent sign lost the race; surface it as chain-advanced so the caller
        -- re-resolves the current one and either co-signs into it (container) or
        -- re-signs on top of it (PDF, which cannot be merged after the fact).
        po_data := util.result_error('document:chain_advanced', 'a signed document already exists for this chain');
        RETURN;
    WHEN OTHERS THEN
        RAISE EXCEPTION '%', util.result_error('document:insert_failed', SQLERRM) USING ERRCODE = 'P0001';
END
$$;

-- document.get — read one document's metadata, authorized by the chain's ACL
-- (DB-enforced, defence-in-depth no-IDOR): the caller must hold `read` on the
-- document's chain root, as the owning subject OR an invited eIDAS serial.
-- Returns :not_found when the row is absent OR the caller is not on the ACL —
-- the two are deliberately indistinguishable (no enumeration).
-- pi_data = { id, caller_sub, [caller_serial] }.
CREATE OR REPLACE PROCEDURE document.get(pi_data jsonb, INOUT po_data jsonb)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = document, util, pg_temp
AS $$
DECLARE
    v_id     text := pi_data->>'id';
    v_sub    text := pi_data->>'caller_sub';
    v_serial text := pi_data->>'caller_serial';
    v_root   text;
    v_row    jsonb;
BEGIN
    IF v_id IS NULL OR v_id = '' THEN
        po_data := util.result_error('document:invalid', 'id is required');
        RETURN;
    END IF;
    IF (v_sub IS NULL OR v_sub = '') AND (v_serial IS NULL OR v_serial = '') THEN
        po_data := util.result_error('document:invalid', 'caller is required');
        RETURN;
    END IF;

    SELECT to_jsonb(d), COALESCE(NULLIF(d.parent_id, ''), d.id)
      INTO v_row, v_root
    FROM document.document d
    WHERE d.id = v_id;

    -- Absent row OR caller-not-on-the-chain-ACL are deliberately indistinguishable.
    IF v_row IS NULL OR NOT document.acl_allows(v_root, v_sub, v_serial, 'read') THEN
        po_data := util.result_error('document:not_found', 'no document for that id');
        RETURN;
    END IF;

    -- The chain-level result freeze lives on the ROOT row; project the chain's
    -- effective flag onto whichever row was fetched, so a byte-serving consumer
    -- can honour the freeze without a second lookup.
    v_row := v_row || jsonb_build_object('result_frozen',
        COALESCE((SELECT r.result_frozen FROM document.document r WHERE r.id = v_root), false));

    po_data := util.result_success(v_row);
EXCEPTION
    WHEN SQLSTATE 'P0001' THEN
        RAISE;
    WHEN OTHERS THEN
        RAISE EXCEPTION '%', util.result_error('document:get_failed', SQLERRM) USING ERRCODE = 'P0001';
END
$$;

-- document.get_container_by_parent — the single container of a chain root,
-- authorized by the same chain ACL as document.get (the chain root IS the parent).
-- Used when a concurrent first co-sign lost the create race: the caller re-resolves
-- the existing container to co-sign into it. Returns :not_found when the caller is
-- not on the chain ACL OR no container exists yet (deliberately indistinguishable).
-- pi_data = { parent_id, caller_sub, [caller_serial] }.
CREATE OR REPLACE PROCEDURE document.get_container_by_parent(pi_data jsonb, INOUT po_data jsonb)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = document, util, pg_temp
AS $$
DECLARE
    v_parent text := pi_data->>'parent_id';
    v_sub    text := pi_data->>'caller_sub';
    v_serial text := pi_data->>'caller_serial';
    v_row    jsonb;
BEGIN
    IF v_parent IS NULL OR v_parent = '' THEN
        po_data := util.result_error('document:invalid', 'parent_id is required');
        RETURN;
    END IF;
    IF (v_sub IS NULL OR v_sub = '') AND (v_serial IS NULL OR v_serial = '') THEN
        po_data := util.result_error('document:invalid', 'caller is required');
        RETURN;
    END IF;

    SELECT to_jsonb(d)
      INTO v_row
    FROM document.document d
    WHERE d.parent_id = v_parent AND d.kind = 'container' AND d.status <> 'deleted'
    LIMIT 1;

    -- No container yet OR caller-not-on-the-chain-ACL are deliberately indistinguishable.
    IF v_row IS NULL OR NOT document.acl_allows(v_parent, v_sub, v_serial, 'read') THEN
        po_data := util.result_error('document:not_found', 'no container for that chain');
        RETURN;
    END IF;

    po_data := util.result_success(v_row);
EXCEPTION
    WHEN SQLSTATE 'P0001' THEN
        RAISE;
    WHEN OTHERS THEN
        RAISE EXCEPTION '%', util.result_error('document:get_failed', SQLERRM) USING ERRCODE = 'P0001';
END
$$;

-- document.get_latest_signed_pdf_by_chain — the single live signed PDF of a chain,
-- authorized by the same chain ACL as document.get. A signed child of the root, or
-- the ROOT ITSELF when the uploaded document arrived already signed (kind='pdf',
-- no parent) — such a root is its own chain head until a signing supersedes it in
-- place. The PDF analog of get_container_by_parent: a PDF signature is embedded
-- (incremental), so a co-signer re-resolves the current signed PDF to sign on top
-- of it. One live signed PDF per chain tree is enforced by the uniqueness index;
-- latest-first is defensive. Returns :not_found when the caller is not on the
-- chain ACL OR no signed PDF exists yet (deliberately indistinguishable).
-- pi_data = { parent_id (the chain root id), caller_sub, [caller_serial] }.
CREATE OR REPLACE PROCEDURE document.get_latest_signed_pdf_by_chain(pi_data jsonb, INOUT po_data jsonb)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = document, util, pg_temp
AS $$
DECLARE
    v_parent text := pi_data->>'parent_id';
    v_sub    text := pi_data->>'caller_sub';
    v_serial text := pi_data->>'caller_serial';
    v_row    jsonb;
BEGIN
    IF v_parent IS NULL OR v_parent = '' THEN
        po_data := util.result_error('document:invalid', 'parent_id is required');
        RETURN;
    END IF;
    IF (v_sub IS NULL OR v_sub = '') AND (v_serial IS NULL OR v_serial = '') THEN
        po_data := util.result_error('document:invalid', 'caller is required');
        RETURN;
    END IF;

    SELECT to_jsonb(d)
      INTO v_row
    FROM document.document d
    WHERE (d.parent_id = v_parent OR d.id = v_parent)
      AND d.kind = 'pdf' AND d.status <> 'deleted'
    ORDER BY d.id DESC
    LIMIT 1;

    -- No signed PDF yet OR caller-not-on-the-chain-ACL are deliberately indistinguishable.
    IF v_row IS NULL OR NOT document.acl_allows(v_parent, v_sub, v_serial, 'read') THEN
        po_data := util.result_error('document:not_found', 'no signed pdf for that chain');
        RETURN;
    END IF;

    po_data := util.result_success(v_row);
EXCEPTION
    WHEN SQLSTATE 'P0001' THEN
        RAISE;
    WHEN OTHERS THEN
        RAISE EXCEPTION '%', util.result_error('document:get_failed', SQLERRM) USING ERRCODE = 'P0001';
END
$$;

-- document.list — the SPA "my documents": every chain the caller can read,
-- keyset-paginated by descending id (ULIDs are time-sortable). Excludes deleted
-- rows. A row is included when the caller holds `read` on its chain root (as the
-- owning subject OR an invited eIDAS serial) — so a co-signer sees the shared
-- document, not only their own uploads.
-- pi_data = { caller_sub, [caller_serial], [limit], [after] (exclusive upper-bound id) }.
CREATE OR REPLACE PROCEDURE document.list(pi_data jsonb, INOUT po_data jsonb)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = document, util, pg_temp
AS $$
DECLARE
    v_sub     text := pi_data->>'caller_sub';
    v_serial  text := NULLIF(pi_data->>'caller_serial', '');
    v_nserial text := document.normalize_serial(v_serial);
    v_limit   int  := LEAST(COALESCE((pi_data->>'limit')::int, 100), 1000);
    v_after   text := NULLIF(pi_data->>'after', '');
    v_rows    jsonb;
BEGIN
    IF (v_sub IS NULL OR v_sub = '') AND v_serial IS NULL THEN
        po_data := util.result_error('document:invalid', 'caller is required');
        RETURN;
    END IF;
    IF v_limit < 1 THEN
        v_limit := 100;
    END IF;

    SELECT COALESCE(jsonb_agg(r ORDER BY r.id DESC), '[]'::jsonb) INTO v_rows
    FROM (
        SELECT d.* FROM document.document d
        WHERE d.status <> 'deleted'
          AND EXISTS (
              SELECT 1 FROM document.document_acl a
              WHERE a.chain_root_id = COALESCE(NULLIF(d.parent_id, ''), d.id)
                AND 'read' = ANY(a.rights)
                AND (
                      (a.principal_kind = 'sub'    AND v_sub IS NOT NULL AND v_sub <> '' AND a.principal_id = v_sub)
                   OR (a.principal_kind = 'serial' AND v_nserial IS NOT NULL AND a.principal_id = v_nserial)
                )
          )
          AND (v_after IS NULL OR d.id < v_after)
        ORDER BY d.id DESC
        LIMIT v_limit
    ) r;

    po_data := util.result_success(jsonb_build_object('documents', v_rows));
EXCEPTION
    WHEN SQLSTATE 'P0001' THEN
        RAISE;
    WHEN OTHERS THEN
        RAISE EXCEPTION '%', util.result_error('document:list_failed', SQLERRM) USING ERRCODE = 'P0001';
END
$$;

-- document.document_facts — the ONE derivation of a document row's chain facts.
-- Every reader that speaks about a chain (the live listing, the history listing,
-- a single chain read) selects these columns instead of restating the formulas,
-- so two screens can never disagree about whether the same document is signed.
-- Columns are listed explicitly on purpose: a view built on `d.*` freezes its
-- column list at creation time and would silently miss a column added later.
CREATE OR REPLACE VIEW document.document_facts AS
SELECT d.id,
       d.owner,
       d.tenant_id,
       d.kind,
       d.parent_id,
       d.filename,
       d.mime,
       d.size,
       d.status,
       d.preservation_class,
       d.retention_until,
       d.legal_hold,
       d.created_at,
       d.updated_at,
       d.signed_at,
       d.inner_files,
       d.result_frozen,
       COALESCE(NULLIF(d.parent_id, ''), d.id) AS chain_root_id,
       -- Actual signatures: a bundle records has_signatures=false at creation; an
       -- ingested upload is NULL and falls back to the kind proxy; a signature
       -- applied here shows via signed_at.
       (COALESCE(d.has_signatures, d.kind <> 'source') OR d.signed_at IS NOT NULL) AS chain_has_signatures,
       -- "The platform signed this chain": the head is a signed child of its root,
       -- OR the head IS the root and a signature was applied to it IN PLACE (a
       -- multi-document bundle, or an uploaded container/PDF co-signed here). A
       -- merely-uploaded pre-signed file has neither and stays a draft the user
       -- can act on. Both branches are required — a chain signed in place has no
       -- child row, and reading only the parent link calls it unsigned.
       (NULLIF(d.parent_id, '') IS NOT NULL OR d.signed_at IS NOT NULL) AS chain_platform_signed
FROM document.document d;

-- document.list_chains — the caller's documents projected ONE ROW PER CHAIN.
-- A chain is a source document plus everything derived from it (a signed
-- container or a signed PDF); at most one signed artifact lives per chain, so
-- each chain is returned as its single LIVE HEAD — the signed artifact where
-- one exists, else the uploaded source. This is the "always latest" listing: a
-- consumer never sees a chain's source next to its signed result as two rows.
-- Head fields ride with:
--   * has_signatures  — the head carries signatures (any non-source kind; an
--                       already-signed upload is ingested as pdf/container, so
--                       this also covers files that arrived signed);
--   * platform_signed — the head was produced by a signing here (it derives
--                       from a parent), as opposed to being the upload itself;
--   * chain_created_at — when the chain started (the root's created_at; falls
--                       back to the head's if the root row is gone).
-- A chain whose head has expired is omitted unless include_expired is set —
-- an expired signed result never falls back to presenting its source as the
-- head. Same access rule as document.list (read on the chain root, as subject
-- or invited serial). Keyset-paginated by descending chain root id.
-- pi_data = { caller_sub, [caller_serial], [limit], [after] (exclusive
--             upper-bound chain root id), [include_expired] }.
CREATE OR REPLACE PROCEDURE document.list_chains(pi_data jsonb, INOUT po_data jsonb)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = document, util, pg_temp
AS $$
DECLARE
    v_sub     text    := pi_data->>'caller_sub';
    v_serial  text    := NULLIF(pi_data->>'caller_serial', '');
    v_nserial text    := document.normalize_serial(v_serial);
    v_limit   int     := LEAST(COALESCE((pi_data->>'limit')::int, 100), 1000);
    v_after   text    := NULLIF(pi_data->>'after', '');
    v_expired boolean := COALESCE((pi_data->>'include_expired')::boolean, false);
    v_rows    jsonb;
BEGIN
    IF (v_sub IS NULL OR v_sub = '') AND v_serial IS NULL THEN
        po_data := util.result_error('document:invalid', 'caller is required');
        RETURN;
    END IF;
    IF v_limit < 1 THEN
        v_limit := 100;
    END IF;

    -- The cursor pages by LAST ACTION: "<updated_at RFC3339>|<chain_root_id>"
    -- (both from the previous page's last row). A legacy bare chain-root id is
    -- still accepted and pages by root id alone.
    DECLARE
        v_after_ts timestamptz;
        v_after_id text;
    BEGIN
        IF v_after IS NOT NULL AND position('|' IN v_after) > 0 THEN
            v_after_ts := split_part(v_after, '|', 1)::timestamptz;
            v_after_id := split_part(v_after, '|', 2);
        ELSE
            v_after_id := v_after;
        END IF;

        SELECT COALESCE(jsonb_agg(to_jsonb(c) ORDER BY c.updated_at DESC, c.chain_root_id DESC), '[]'::jsonb) INTO v_rows
        FROM (
            SELECT heads.*
            FROM (
                -- One head per chain: the signed artifact outranks the source,
                -- then the newest row wins.
                SELECT DISTINCT ON (h.chain_root_id)
                       h.chain_root_id,
                       h.id, h.kind, h.status, h.filename, h.mime, h.size,
                       h.retention_until, h.legal_hold, h.created_at, h.updated_at,
                       h.preservation_class,
                       h.chain_has_signatures  AS has_signatures,
                       h.chain_platform_signed AS platform_signed,
                       -- The chain's download freeze (a ROOT-row flag): while a
                       -- signing workflow is in progress the listing consumer
                       -- renders the row as in-signing, not draft/completed.
                       COALESCE(r.result_frozen, false)      AS result_frozen,
                       COALESCE(r.created_at, h.created_at)  AS chain_created_at
                FROM document.document_facts h
                LEFT JOIN document.document r ON r.id = h.chain_root_id
                WHERE h.status <> 'deleted'
                  AND EXISTS (
                      SELECT 1 FROM document.document_acl a
                      WHERE a.chain_root_id = h.chain_root_id
                        AND 'read' = ANY(a.rights)
                        AND (
                              (a.principal_kind = 'sub'    AND v_sub IS NOT NULL AND v_sub <> '' AND a.principal_id = v_sub)
                           OR (a.principal_kind = 'serial' AND v_nserial IS NOT NULL AND a.principal_id = v_nserial)
                        )
                  )
                ORDER BY h.chain_root_id DESC,
                         (h.kind <> 'source') DESC,
                         h.id DESC
            ) heads
            WHERE (v_expired OR heads.status <> 'expired')
              AND (
                    v_after_ts IS NOT NULL AND (heads.updated_at < v_after_ts
                        OR (heads.updated_at = v_after_ts AND heads.chain_root_id < v_after_id))
                 OR v_after_ts IS NULL AND v_after_id IS NOT NULL AND heads.chain_root_id < v_after_id
                 OR v_after IS NULL
              )
            -- Last action first: every mutation (sign, rebundle, archive
            -- refresh) touches the head's updated_at via the table trigger.
            ORDER BY heads.updated_at DESC, heads.chain_root_id DESC
            LIMIT v_limit
        ) c;
    END;

    po_data := util.result_success(jsonb_build_object('chains', v_rows));
EXCEPTION
    WHEN SQLSTATE 'P0001' THEN
        RAISE;
    WHEN OTHERS THEN
        RAISE EXCEPTION '%', util.result_error('document:list_chains_failed', SQLERRM) USING ERRCODE = 'P0001';
END
$$;

-- document.get_chain — ONE chain, addressed by ANY id in it (its root, or the
-- signed head derived from it), projected exactly like a listing row. The screen
-- that owns a document reads this rather than looking the document up in a
-- listing: a listing legitimately omits chains (filtered, paged, or represented
-- by the workflow that covers them), and a chain's own facts must never depend on
-- whether some other view chose to show it.
-- An expired chain IS returned — the screen states the expiry; a chain whose rows
-- are all deleted is not found, and its record belongs to the history listing.
-- Same access rule as the single-document read: read on the chain root, as
-- subject or invited serial, with absent and not-permitted deliberately
-- indistinguishable.
-- pi_data = { caller_sub, [caller_serial], id }.
CREATE OR REPLACE PROCEDURE document.get_chain(pi_data jsonb, INOUT po_data jsonb)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = document, util, pg_temp
AS $$
DECLARE
    v_id     text := pi_data->>'id';
    v_sub    text := pi_data->>'caller_sub';
    v_serial text := pi_data->>'caller_serial';
    v_root   text;
    v_row    jsonb;
BEGIN
    IF v_id IS NULL OR v_id = '' THEN
        po_data := util.result_error('document:invalid', 'id is required');
        RETURN;
    END IF;
    IF (v_sub IS NULL OR v_sub = '') AND (v_serial IS NULL OR v_serial = '') THEN
        po_data := util.result_error('document:invalid', 'caller is required');
        RETURN;
    END IF;

    -- The id may name any row of the chain; the chain is identified by its root.
    SELECT COALESCE(NULLIF(d.parent_id, ''), d.id) INTO v_root
    FROM document.document d
    WHERE d.id = v_id;

    IF v_root IS NULL OR NOT document.acl_allows(v_root, v_sub, v_serial, 'read') THEN
        po_data := util.result_error('document:not_found', 'no chain for that id');
        RETURN;
    END IF;

    SELECT to_jsonb(c) INTO v_row
    FROM (
        -- One head per chain, by the same rule the listings use: the signed
        -- artifact outranks the source, then the newest row wins.
        SELECT DISTINCT ON (h.chain_root_id)
               h.chain_root_id,
               h.id, h.kind, h.status, h.filename, h.mime, h.size,
               h.retention_until, h.legal_hold, h.created_at, h.updated_at,
               h.preservation_class,
               h.chain_has_signatures  AS has_signatures,
               h.chain_platform_signed AS platform_signed,
               -- The head's inner files ride along, so the screen that shows what
               -- is inside a container needs one read, not two.
               h.inner_files,
               COALESCE(r.result_frozen, false)      AS result_frozen,
               COALESCE(r.created_at, h.created_at)  AS chain_created_at
        FROM document.document_facts h
        LEFT JOIN document.document r ON r.id = h.chain_root_id
        WHERE h.chain_root_id = v_root
          AND h.status <> 'deleted'
        ORDER BY h.chain_root_id DESC,
                 (h.kind <> 'source') DESC,
                 h.id DESC
    ) c;

    IF v_row IS NULL THEN
        po_data := util.result_error('document:not_found', 'no chain for that id');
        RETURN;
    END IF;

    po_data := util.result_success(jsonb_build_object('chain', v_row));
EXCEPTION
    WHEN SQLSTATE 'P0001' THEN
        RAISE;
    WHEN OTHERS THEN
        RAISE EXCEPTION '%', util.result_error('document:get_chain_failed', SQLERRM) USING ERRCODE = 'P0001';
END
$$;

-- document.list_history — the caller's TERMINAL chains: chains with no live row
-- left (every row expired or deleted — the storage is gone, the record remains).
-- One row per chain, as its terminal head (signed artifact over source), with
-- destroyed_at = when the head reached its terminal state. Owner-scoped by the
-- uploader subject: a deleted chain has no ACL rows left, so the standing-access
-- rule cannot apply here — the history is the owner's own record. Keyset-
-- paginated by descending chain root id.
-- pi_data = { caller_sub, [limit], [after] (exclusive upper-bound chain root id) }.
CREATE OR REPLACE PROCEDURE document.list_history(pi_data jsonb, INOUT po_data jsonb)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = document, util, pg_temp
AS $$
DECLARE
    v_sub   text := pi_data->>'caller_sub';
    v_limit int  := LEAST(COALESCE((pi_data->>'limit')::int, 50), 200);
    v_after text := NULLIF(pi_data->>'after', '');
    v_rows  jsonb;
BEGIN
    IF v_sub IS NULL OR v_sub = '' THEN
        po_data := util.result_error('document:invalid', 'caller is required');
        RETURN;
    END IF;
    IF v_limit < 1 THEN
        v_limit := 50;
    END IF;

    SELECT COALESCE(jsonb_agg(to_jsonb(c) ORDER BY c.chain_root_id DESC), '[]'::jsonb) INTO v_rows
    FROM (
        SELECT DISTINCT ON (h.chain_root_id)
               h.chain_root_id,
               h.id, h.kind, h.status, h.filename, h.mime, h.size,
               h.chain_has_signatures  AS has_signatures,
               h.chain_platform_signed AS platform_signed,
               COALESCE(r.created_at, h.created_at)  AS chain_created_at,
               h.updated_at                          AS destroyed_at
        FROM document.document_facts h
        LEFT JOIN document.document r ON r.id = h.chain_root_id
        WHERE h.owner = v_sub
          AND h.status IN ('expired', 'deleted')
          -- A chain belongs to history only once NOTHING in it is live.
          AND NOT EXISTS (
              SELECT 1 FROM document.document l
              WHERE COALESCE(NULLIF(l.parent_id, ''), l.id) = h.chain_root_id
                AND l.status NOT IN ('expired', 'deleted')
          )
          AND (v_after IS NULL OR h.chain_root_id < v_after)
        ORDER BY h.chain_root_id DESC,
                 (h.kind <> 'source') DESC,
                 h.id DESC
        LIMIT v_limit
    ) c;

    po_data := util.result_success(jsonb_build_object('chains', v_rows));
EXCEPTION
    WHEN SQLSTATE 'P0001' THEN
        RAISE;
    WHEN OTHERS THEN
        RAISE EXCEPTION '%', util.result_error('document:list_history_failed', SQLERRM) USING ERRCODE = 'P0001';
END
$$;

-- document.sweep_history — the second-stage sweep: hard-DELETE terminal metadata
-- rows older than the retention window (data minimization — the record itself is
-- erased after the promised keep period), plus the chain ACL entries that hang
-- off fully-removed chains. Bytes are long gone (the first-stage retention sweep
-- destroyed them); this removes the metadata. Legal-hold rows are never removed.
-- pi_data = { before (timestamptz — rows terminal since before this instant),
--             [limit] }. Returns the number of rows removed.
CREATE OR REPLACE PROCEDURE document.sweep_history(pi_data jsonb, INOUT po_data jsonb)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = document, util, pg_temp
AS $$
DECLARE
    v_before timestamptz := (pi_data->>'before')::timestamptz;
    v_limit  int         := LEAST(COALESCE((pi_data->>'limit')::int, 500), 5000);
    v_count  int;
BEGIN
    IF v_before IS NULL THEN
        po_data := util.result_error('document:invalid', 'before is required');
        RETURN;
    END IF;

    WITH gone AS (
        DELETE FROM document.document d
        WHERE d.id IN (
            SELECT id FROM document.document
            WHERE status IN ('expired', 'deleted')
              AND legal_hold = false
              AND updated_at < v_before
            ORDER BY updated_at ASC
            LIMIT v_limit
        )
        RETURNING COALESCE(NULLIF(d.parent_id, ''), d.id) AS chain_root_id
    )
    SELECT count(*) INTO v_count FROM gone;

    -- Drop ACL entries whose chain has no rows left at all.
    DELETE FROM document.document_acl a
    WHERE NOT EXISTS (
        SELECT 1 FROM document.document d
        WHERE COALESCE(NULLIF(d.parent_id, ''), d.id) = a.chain_root_id
    );

    po_data := util.result_success(jsonb_build_object('removed', v_count));
EXCEPTION
    WHEN SQLSTATE 'P0001' THEN
        RAISE;
    WHEN OTHERS THEN
        RAISE EXCEPTION '%', util.result_error('document:sweep_history_failed', SQLERRM) USING ERRCODE = 'P0001';
END
$$;

-- document.delete_history_chain — a user removes one of their history records
-- early: hard-delete the caller-owned chain's rows (all terminal) + its ACL
-- entries. Refused while any row is live (a live chain is deleted through the
-- normal reference-counted path) or under legal hold.
-- pi_data = { chain_root_id, caller_sub }.
CREATE OR REPLACE PROCEDURE document.delete_history_chain(pi_data jsonb, INOUT po_data jsonb)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = document, util, pg_temp
AS $$
DECLARE
    v_root  text := pi_data->>'chain_root_id';
    v_sub   text := pi_data->>'caller_sub';
    v_count int;
BEGIN
    IF v_root IS NULL OR v_root = '' OR v_sub IS NULL OR v_sub = '' THEN
        po_data := util.result_error('document:invalid', 'chain_root_id and caller_sub are required');
        RETURN;
    END IF;

    IF EXISTS (
        SELECT 1 FROM document.document d
        WHERE COALESCE(NULLIF(d.parent_id, ''), d.id) = v_root
          AND (d.status NOT IN ('expired', 'deleted') OR d.legal_hold)
    ) THEN
        po_data := util.result_error('document:chain_live', 'chain is live or under legal hold');
        RETURN;
    END IF;

    DELETE FROM document.document d
    WHERE COALESCE(NULLIF(d.parent_id, ''), d.id) = v_root
      AND d.owner = v_sub;
    GET DIAGNOSTICS v_count = ROW_COUNT;

    IF v_count = 0 THEN
        po_data := util.result_error('document:not_found', 'no history record for that chain');
        RETURN;
    END IF;

    DELETE FROM document.document_acl a
    WHERE a.chain_root_id = v_root
      AND NOT EXISTS (
          SELECT 1 FROM document.document d
          WHERE COALESCE(NULLIF(d.parent_id, ''), d.id) = a.chain_root_id
      );

    po_data := util.result_success(jsonb_build_object('removed', v_count));
EXCEPTION
    WHEN SQLSTATE 'P0001' THEN
        RAISE;
    WHEN OTHERS THEN
        RAISE EXCEPTION '%', util.result_error('document:delete_history_failed', SQLERRM) USING ERRCODE = 'P0001';
END
$$;

-- document.set_status — atomic, owner-filtered status change against the CHECK
-- enum. pi_data = { id, caller, status }.
CREATE OR REPLACE PROCEDURE document.set_status(pi_data jsonb, INOUT po_data jsonb)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = document, util, pg_temp
AS $$
DECLARE
    v_id     text := pi_data->>'id';
    v_caller text := pi_data->>'caller';
    v_status text := pi_data->>'status';
    v_found  text;
BEGIN
    IF v_id IS NULL OR v_id = '' OR v_caller IS NULL OR v_caller = '' THEN
        po_data := util.result_error('document:invalid', 'id and caller are required');
        RETURN;
    END IF;
    -- The null test is not redundant: this value is read straight from the
    -- request, so an absent key arrives as NULL, and NULL NOT IN (...)
    -- evaluates to NULL rather than true — without it the branch never fires
    -- for a missing field, and the caller gets whatever the write fails with
    -- instead of the precise refusal this check exists to give.
    IF v_status IS NULL OR v_status NOT IN ('received', 'signing', 'signed', 'expired', 'deleted') THEN
        po_data := util.result_error('document:invalid', 'invalid status');
        RETURN;
    END IF;

    UPDATE document.document
       SET status = v_status
     WHERE id = v_id AND owner = v_caller
    RETURNING id INTO v_found;

    IF v_found IS NULL THEN
        po_data := util.result_error('document:not_found', 'no document for that id');
        RETURN;
    END IF;

    po_data := util.result_success(jsonb_build_object('id', v_found, 'status', v_status));
EXCEPTION
    WHEN SQLSTATE 'P0001' THEN
        RAISE;
    WHEN OTHERS THEN
        RAISE EXCEPTION '%', util.result_error('document:set_status_failed', SQLERRM) USING ERRCODE = 'P0001';
END
$$;

-- document.extend_retention — roll retention_until forward on co-sign
-- (rolling extension on co-sign). The new instant comes from Go (it
-- owns the clock); the procedure only moves it FORWARD (never shortens a TTL).
-- pi_data = { id, caller, retention_until }.
CREATE OR REPLACE PROCEDURE document.extend_retention(pi_data jsonb, INOUT po_data jsonb)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = document, util, pg_temp
AS $$
DECLARE
    v_id     text := pi_data->>'id';
    v_caller text := pi_data->>'caller';
    v_until  timestamptz;
    v_new    timestamptz;
BEGIN
    IF v_id IS NULL OR v_id = '' OR v_caller IS NULL OR v_caller = '' THEN
        po_data := util.result_error('document:invalid', 'id and caller are required');
        RETURN;
    END IF;
    IF (pi_data->>'retention_until') IS NULL THEN
        po_data := util.result_error('document:invalid', 'retention_until is required');
        RETURN;
    END IF;
    v_until := (pi_data->>'retention_until')::timestamptz;

    UPDATE document.document
       SET retention_until = GREATEST(retention_until, v_until)
     WHERE id = v_id AND owner = v_caller
    RETURNING retention_until INTO v_new;

    IF v_new IS NULL THEN
        po_data := util.result_error('document:not_found', 'no document for that id');
        RETURN;
    END IF;

    po_data := util.result_success(jsonb_build_object('id', v_id, 'retentionUntil', v_new));
EXCEPTION
    WHEN SQLSTATE 'P0001' THEN
        RAISE;
    WHEN OTHERS THEN
        RAISE EXCEPTION '%', util.result_error('document:extend_retention_failed', SQLERRM) USING ERRCODE = 'P0001';
END
$$;

-- document.remove_access — a participant removes THEIR OWN standing access to a
-- document chain ("remove from my documents"). Reference-counted: the caller's
-- ACL entry is dropped; only when the LAST entry is gone are the chain's bytes
-- purged (every row's storage_ref + encryption_key_ref NULLed, status='deleted'),
-- returning the prior refs so Go can destroy the S3 objects + KMS data keys. A
-- legal hold on ANY row in the chain refuses the whole operation (bytes + access
-- kept). The owner is just one entry — it cannot destroy a document a co-signer
-- still holds. A solo document is a one-entry ACL, so this behaves exactly like
-- the prior owner-filtered delete. pi_data = { doc_id, caller_sub, [caller_serial] }.
CREATE OR REPLACE PROCEDURE document.remove_access(pi_data jsonb, INOUT po_data jsonb)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = document, util, pg_temp
AS $$
DECLARE
    v_doc       text := pi_data->>'doc_id';
    v_sub       text := pi_data->>'caller_sub';
    v_serial    text := pi_data->>'caller_serial';
    v_root      text;
    v_held      boolean;
    v_remaining int;
    v_purged    jsonb;
BEGIN
    IF v_doc IS NULL OR v_doc = '' THEN
        po_data := util.result_error('document:invalid', 'doc_id is required');
        RETURN;
    END IF;
    IF (v_sub IS NULL OR v_sub = '') AND (v_serial IS NULL OR v_serial = '') THEN
        po_data := util.result_error('document:invalid', 'caller is required');
        RETURN;
    END IF;

    -- Resolve the chain root from the document.
    SELECT COALESCE(NULLIF(d.parent_id, ''), d.id) INTO v_root
    FROM document.document d
    WHERE d.id = v_doc;

    -- Absent row OR caller-not-on-the-ACL are deliberately indistinguishable.
    IF v_root IS NULL OR NOT document.acl_allows(v_root, v_sub, v_serial, 'read') THEN
        po_data := util.result_error('document:not_found', 'no document for that id');
        RETURN;
    END IF;

    -- A legal hold anywhere in the chain refuses the whole delete (fail-closed).
    SELECT bool_or(legal_hold) INTO v_held
    FROM document.document
    WHERE id = v_root OR parent_id = v_root;

    IF COALESCE(v_held, false) THEN
        po_data := util.result_error('document:legal_hold', 'document is under legal hold and cannot be deleted');
        RETURN;
    END IF;

    -- Drop the caller's own ACL entries (their sub and/or normalized serial).
    DELETE FROM document.document_acl a
    WHERE a.chain_root_id = v_root
      AND ( (a.principal_kind = 'sub'
                AND v_sub IS NOT NULL AND v_sub <> '' AND a.principal_id = v_sub)
         OR (a.principal_kind = 'serial'
                AND v_serial IS NOT NULL AND v_serial <> '' AND a.principal_id = document.normalize_serial(v_serial)) );

    SELECT count(*) INTO v_remaining FROM document.document_acl WHERE chain_root_id = v_root;

    IF v_remaining > 0 THEN
        -- Others still hold access — keep the bytes; only the caller's access is gone.
        po_data := util.result_success(jsonb_build_object('purged', '[]'::jsonb, 'aclRemaining', v_remaining));
        RETURN;
    END IF;

    -- Last access removed → purge every blob in the chain (source + container).
    WITH chain AS (
        SELECT id, storage_ref, encryption_key_ref
        FROM document.document
        WHERE (id = v_root OR parent_id = v_root) AND status <> 'deleted'
    ),
    updated AS (
        UPDATE document.document d
           SET status = 'deleted', storage_ref = NULL, encryption_key_ref = NULL
          FROM chain c
         WHERE d.id = c.id
        RETURNING c.id, c.storage_ref, c.encryption_key_ref
    )
    SELECT COALESCE(jsonb_agg(jsonb_build_object(
               'id', id, 'storageRef', storage_ref, 'encryptionKeyRef', encryption_key_ref)), '[]'::jsonb)
      INTO v_purged
    FROM updated;

    po_data := util.result_success(jsonb_build_object('purged', v_purged, 'aclRemaining', 0));
EXCEPTION
    WHEN SQLSTATE 'P0001' THEN
        RAISE;
    WHEN OTHERS THEN
        RAISE EXCEPTION '%', util.result_error('document:remove_access_failed', SQLERRM) USING ERRCODE = 'P0001';
END
$$;

-- document.sweep_retention — set-based purge driver. Selects expired,
-- non-legal-hold, not-already-purged documents whose retention_until < `now`,
-- flips them to status='expired', NULLs their storage_ref + encryption_key_ref, and
-- RETURNS the prior {id, storageRef, encryptionKeyRef} list so the Go core.Tasker
-- can destroy the S3 objects + KMS data keys. Retention PARAMS (the `now` instant,
-- batch limit) come from Go. pi_data = { now, [limit] }.
CREATE OR REPLACE PROCEDURE document.sweep_retention(pi_data jsonb, INOUT po_data jsonb)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = document, util, pg_temp
AS $$
DECLARE
    v_now   timestamptz := COALESCE((pi_data->>'now')::timestamptz, now());
    v_limit int         := LEAST(COALESCE((pi_data->>'limit')::int, 500), 5000);
    v_purged jsonb;
BEGIN
    WITH expired AS (
        SELECT id, storage_ref, encryption_key_ref
        FROM document.document
        WHERE retention_until < v_now
          AND legal_hold = false
          AND status <> 'deleted'
          AND status <> 'expired'
        ORDER BY retention_until ASC
        LIMIT v_limit
        FOR UPDATE SKIP LOCKED
    ),
    updated AS (
        UPDATE document.document d
           SET status = 'expired', storage_ref = NULL, encryption_key_ref = NULL
          FROM expired e
         WHERE d.id = e.id
        RETURNING e.id, e.storage_ref, e.encryption_key_ref
    )
    SELECT COALESCE(jsonb_agg(jsonb_build_object(
               'id', id, 'storageRef', storage_ref, 'encryptionKeyRef', encryption_key_ref)), '[]'::jsonb)
      INTO v_purged
    FROM updated;

    po_data := util.result_success(jsonb_build_object('purged', v_purged, 'count', jsonb_array_length(v_purged)));
EXCEPTION
    WHEN SQLSTATE 'P0001' THEN
        RAISE;
    WHEN OTHERS THEN
        RAISE EXCEPTION '%', util.result_error('document:sweep_retention_failed', SQLERRM) USING ERRCODE = 'P0001';
END
$$;

-- document.grant_acl — grant standing access (read / co-sign) on a document's
-- CHAIN to a principal, keyed on the chain root resolved from the document id.
-- Used by the workflow service at send to invite each slot's eIDAS serial; the
-- creator's own access is seeded at upload (document.insert). Idempotent: a
-- re-grant (e.g. a re-send) replaces the principal's rights. A serial principal
-- is stored normalized so the acl_allows match is exact. The caller's authority
-- to grant is enforced at the service boundary (the documents:grant scope, held
-- only by the workflow service) — this procedure only records the grant.
-- pi_data = { doc_id, principal_kind (sub|serial), principal_id, [rights[]],
--             [tenant_id], [granted_by] }.
CREATE OR REPLACE PROCEDURE document.grant_acl(pi_data jsonb, INOUT po_data jsonb)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = document, util, pg_temp
AS $$
DECLARE
    v_doc     text := pi_data->>'doc_id';
    v_kind    text := pi_data->>'principal_kind';
    v_pid     text := pi_data->>'principal_id';
    v_grantor text := NULLIF(pi_data->>'granted_by', '');
    v_tenant  text := NULLIF(pi_data->>'tenant_id', '');
    v_rights  text[];
    v_root    text;
BEGIN
    IF v_doc IS NULL OR v_doc = '' THEN
        po_data := util.result_error('document:invalid', 'doc_id is required');
        RETURN;
    END IF;
    IF v_kind IS NULL OR v_kind NOT IN ('sub', 'serial') THEN
        po_data := util.result_error('document:invalid', 'principal_kind must be sub or serial');
        RETURN;
    END IF;
    IF v_pid IS NULL OR v_pid = '' THEN
        po_data := util.result_error('document:invalid', 'principal_id is required');
        RETURN;
    END IF;

    -- Default rights to {read, cosign}; reject anything outside that set.
    v_rights := ARRAY(SELECT jsonb_array_elements_text(COALESCE(pi_data->'rights', '[]'::jsonb)));
    IF cardinality(v_rights) = 0 THEN
        v_rights := ARRAY['read', 'cosign']::text[];
    END IF;
    IF NOT (v_rights <@ ARRAY['read', 'cosign']::text[]) THEN
        po_data := util.result_error('document:invalid', 'rights must be a subset of {read, cosign}');
        RETURN;
    END IF;

    -- Resolve the chain root from the document (it must exist).
    SELECT COALESCE(NULLIF(d.parent_id, ''), d.id) INTO v_root
    FROM document.document d
    WHERE d.id = v_doc;

    IF v_root IS NULL THEN
        po_data := util.result_error('document:not_found', 'no document for that id');
        RETURN;
    END IF;

    -- Store a serial principal in its canonical form so the match is exact.
    IF v_kind = 'serial' THEN
        v_pid := document.normalize_serial(v_pid);
    END IF;

    INSERT INTO document.document_acl (chain_root_id, principal_kind, principal_id, rights, tenant_id, granted_by)
    VALUES (v_root, v_kind, v_pid, v_rights, v_tenant, COALESCE(v_grantor, v_pid))
    ON CONFLICT (chain_root_id, principal_kind, principal_id)
    DO UPDATE SET rights = EXCLUDED.rights, tenant_id = EXCLUDED.tenant_id,
                  granted_by = EXCLUDED.granted_by, granted_at = now();

    po_data := util.result_success(jsonb_build_object(
        'chainRoot', v_root, 'principalKind', v_kind, 'principalId', v_pid, 'rights', to_jsonb(v_rights)));
EXCEPTION
    WHEN SQLSTATE 'P0001' THEN
        RAISE;
    WHEN OTHERS THEN
        RAISE EXCEPTION '%', util.result_error('document:grant_acl_failed', SQLERRM) USING ERRCODE = 'P0001';
END
$$;

-- document.set_result_freeze — set/clear the chain-level download freeze on the
-- ROOT row, resolved from any row of the chain. While frozen, byte reads of the
-- chain's non-source rows refuse (the signed result is locked during a signing
-- workflow; it opens at the workflow's terminal transition — the source stays
-- readable throughout). The caller's authority is enforced at the service
-- boundary (the same grant scope the workflow service uses to administer
-- access) — this procedure only records the flag. Idempotent.
-- pi_data = { id, frozen }.
CREATE OR REPLACE PROCEDURE document.set_result_freeze(pi_data jsonb, INOUT po_data jsonb)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = document, util, pg_temp
AS $$
DECLARE
    v_id     text    := pi_data->>'id';
    v_frozen boolean := (pi_data->>'frozen')::boolean;
    v_root   text;
BEGIN
    IF v_id IS NULL OR v_id = '' THEN
        po_data := util.result_error('document:invalid', 'id is required');
        RETURN;
    END IF;
    IF v_frozen IS NULL THEN
        po_data := util.result_error('document:invalid', 'frozen is required');
        RETURN;
    END IF;

    -- Resolve the chain root from the document (it must exist).
    SELECT COALESCE(NULLIF(d.parent_id, ''), d.id) INTO v_root
    FROM document.document d
    WHERE d.id = v_id;

    IF v_root IS NULL THEN
        po_data := util.result_error('document:not_found', 'no document for that id');
        RETURN;
    END IF;

    UPDATE document.document SET result_frozen = v_frozen WHERE id = v_root;

    po_data := util.result_success(jsonb_build_object('id', v_root, 'result_frozen', v_frozen));
EXCEPTION
    WHEN SQLSTATE 'P0001' THEN
        RAISE;
    WHEN OTHERS THEN
        RAISE EXCEPTION '%', util.result_error('document:set_result_freeze_failed', SQLERRM) USING ERRCODE = 'P0001';
END
$$;

-- document.replace_container_blob — keep-latest: hard-replace a container's bytes
-- in place on a co-sign, so a chain keeps exactly ONE container (no version pile).
-- Optimistic CAS: the swap commits only if the container's content_hash is still
-- the one the signer based on (expected_hash); if it advanced (a concurrent
-- co-sign committed first) it returns :chain_advanced so the caller reloads the
-- latest and re-merges its already-computed signature. Returns the updated row +
-- the PRIOR blob refs so Go can destroy the superseded S3 object + KMS data key
-- (the Go layer flips the pointer first, then deletes — a failed delete leaves a
-- harmless orphan, never data loss). An archive-timestamped refresh passes its
-- preservation_class as well: the upgrade to long-term preservation is recorded in
-- the SAME write as the swapped bytes, so a refused class leaves the bytes untouched
-- and swapped bytes are always recorded — never a second step that can fail on its
-- own. pi_data = { id, expected_hash, storage_ref, content_hash, size,
-- encryption_key_ref, [preservation_class] }.
CREATE OR REPLACE PROCEDURE document.replace_container_blob(pi_data jsonb, INOUT po_data jsonb)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = document, util, pg_temp
AS $$
DECLARE
    v_id        text := pi_data->>'id';
    v_expected  text := pi_data->>'expected_hash';
    v_presv     text := NULLIF(pi_data->>'preservation_class', '');
    v_cur_hash  text;
    v_cur_kind  text;
    v_old_stor  text;
    v_old_keyr  text;
    v_row       jsonb;
BEGIN
    IF v_id IS NULL OR v_id = '' THEN
        po_data := util.result_error('document:invalid', 'id is required');
        RETURN;
    END IF;
    IF v_expected IS NULL OR v_expected = '' THEN
        po_data := util.result_error('document:invalid', 'expected_hash is required');
        RETURN;
    END IF;
    IF (pi_data->>'storage_ref') IS NULL OR (pi_data->>'content_hash') IS NULL
       OR (pi_data->>'size') IS NULL OR (pi_data->>'encryption_key_ref') IS NULL THEN
        po_data := util.result_error('document:invalid', 'storage_ref, content_hash, size and encryption_key_ref are required');
        RETURN;
    END IF;
    IF v_presv IS NOT NULL AND v_presv NOT IN ('none', 'b_lt', 'preservation') THEN
        po_data := util.result_error('document:invalid', 'invalid preservation_class');
        RETURN;
    END IF;

    -- Lock the row, capture its prior refs + the current hash (the CAS token).
    SELECT content_hash, kind, storage_ref, encryption_key_ref
      INTO v_cur_hash, v_cur_kind, v_old_stor, v_old_keyr
    FROM document.document
    WHERE id = v_id AND status <> 'deleted'
    FOR UPDATE;

    -- Only a SIGNED head form may be replaced in place: an ASiC-E container
    -- (a merged co-signature or an archive-timestamped refresh) or a signed
    -- PDF (an archive-timestamped refresh). A plain source is never replaced.
    IF v_cur_hash IS NULL OR v_cur_kind NOT IN ('container', 'pdf') THEN
        po_data := util.result_error('document:not_found', 'no signed document for that id');
        RETURN;
    END IF;
    IF v_cur_hash <> v_expected THEN
        po_data := util.result_error('document:chain_advanced', 'the container advanced since signing began; reload the latest and retry');
        RETURN;
    END IF;

    UPDATE document.document AS d
       SET storage_ref        = pi_data->>'storage_ref',
           content_hash       = pi_data->>'content_hash',
           size               = (pi_data->>'size')::bigint,
           encryption_key_ref = pi_data->>'encryption_key_ref',
           status             = 'signed',
           -- An archive-timestamped refresh records its preservation class in the
           -- same write as the bytes: one fact with the swap, never a second step.
           preservation_class = COALESCE(v_presv, d.preservation_class),
           -- The platform applied this signature in place — the fact that lets a
           -- root-headed chain (a bundle, or an uploaded file co-signed here)
           -- read as signed-here rather than as a pre-signed upload.
           signed_at          = now()
     WHERE d.id = v_id
    RETURNING to_jsonb(d) INTO v_row;

    po_data := util.result_success(jsonb_build_object(
        'document', v_row,
        'oldStorageRef', v_old_stor,
        'oldEncryptionKeyRef', v_old_keyr));
EXCEPTION
    WHEN SQLSTATE 'P0001' THEN
        RAISE;
    WHEN OTHERS THEN
        RAISE EXCEPTION '%', util.result_error('document:replace_container_blob_failed', SQLERRM) USING ERRCODE = 'P0001';
END
$$;

-- document.bundle_sources — create a multi-document bundle: insert ONE unsigned
-- container row (kind='container', status='received' — the status is what
-- distinguishes it from a signed container) as a fresh chain root, and absorb
-- the loose source rows it was built from. The sources' metadata rows and ACL
-- entries are hard-deleted in the SAME transaction — the files live on inside
-- the container, so no history record is left behind. Returns the new row id +
-- the absorbed blob refs so the caller can destroy the loose blobs AFTER commit
-- (a failed destroy leaves a harmless orphan, never data loss).
-- Every source must be an unsigned upload owned by the caller; a legal hold on
-- any source refuses the whole bundle (fail-closed).
-- pi_data = { caller_sub, source_ids (ordered array, >= 1), tenant_id?,
--             filename, storage_ref, content_hash, mime, size,
--             encryption_key_ref, retention_until, inner_files,
--             preservation_class? }
CREATE OR REPLACE PROCEDURE document.bundle_sources(pi_data jsonb, INOUT po_data jsonb)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = document, util, pg_temp
AS $$
DECLARE
    v_owner    text := pi_data->>'caller_sub';
    v_presv    text := COALESCE(pi_data->>'preservation_class', 'none');
    v_ids      text[];
    v_sid      text;
    v_count    int;
    v_distinct int;
    v_kind     text;
    v_status   text;
    v_sowner   text;
    v_held     boolean;
    v_id       text;
    v_absorbed jsonb;
BEGIN
    IF v_owner IS NULL OR v_owner = '' THEN
        po_data := util.result_error('document:invalid', 'caller_sub is required');
        RETURN;
    END IF;
    IF (pi_data->>'filename') IS NULL OR (pi_data->>'filename') = '' THEN
        po_data := util.result_error('document:invalid', 'filename is required');
        RETURN;
    END IF;
    IF (pi_data->>'storage_ref') IS NULL OR (pi_data->>'content_hash') IS NULL
       OR (pi_data->>'mime') IS NULL OR (pi_data->>'size') IS NULL
       OR (pi_data->>'encryption_key_ref') IS NULL OR (pi_data->>'retention_until') IS NULL THEN
        po_data := util.result_error('document:invalid', 'storage_ref, content_hash, mime, size, encryption_key_ref and retention_until are required');
        RETURN;
    END IF;
    IF jsonb_typeof(pi_data->'source_ids') IS DISTINCT FROM 'array' THEN
        po_data := util.result_error('document:invalid', 'source_ids must be an array');
        RETURN;
    END IF;

    SELECT array_agg(value), count(*), count(DISTINCT value)
      INTO v_ids, v_count, v_distinct
    FROM jsonb_array_elements_text(pi_data->'source_ids');

    -- The ASiC-E container is the universal at-rest form of a signing set: a
    -- single non-PDF file is a legitimate 1-file bundle (only a lone natively
    -- signed PDF stays a plain source). An empty set is not bundleable.
    IF COALESCE(v_count, 0) < 1 THEN
        po_data := util.result_error('document:invalid', 'a bundle needs at least one source document');
        RETURN;
    END IF;
    IF v_distinct <> v_count THEN
        po_data := util.result_error('document:invalid', 'source_ids contains duplicates');
        RETURN;
    END IF;
    IF v_presv NOT IN ('none', 'b_lt', 'preservation') THEN
        po_data := util.result_error('document:invalid', 'invalid preservation_class');
        RETURN;
    END IF;

    -- Validate + lock every source before any write. Absent, foreign-owned and
    -- deleted rows are deliberately indistinguishable (no-IDOR).
    FOREACH v_sid IN ARRAY v_ids LOOP
        SELECT kind, status, owner, legal_hold
          INTO v_kind, v_status, v_sowner, v_held
        FROM document.document
        WHERE id = v_sid
        FOR UPDATE;

        IF v_sowner IS NULL OR v_sowner <> v_owner OR v_status IN ('deleted', 'expired') THEN
            po_data := util.result_error('document:not_found', 'no document for id ' || v_sid);
            RETURN;
        END IF;
        -- Bundleable: an unsigned source, OR an already-signed file — a signed PDF or
        -- a signed ASiC-E container (an annex such as a counterparty's signed letter).
        -- A signed input rides in as a data object: the new container's signature
        -- covers its bytes, and its own signatures stay intact inside it. An UNSIGNED
        -- container is never an input — that is a draft bundle, which is rebundled.
        IF NOT ((v_kind = 'source' AND v_status = 'received')
             OR (v_kind IN ('pdf', 'container') AND v_status = 'signed')) THEN
            po_data := util.result_error('document:not_bundleable', 'only an unsigned source or an already-signed file (PDF or ASiC-E) can be bundled: ' || v_sid);
            RETURN;
        END IF;
        IF COALESCE(v_held, false) THEN
            po_data := util.result_error('document:legal_hold', 'a source is under legal hold and cannot be absorbed: ' || v_sid);
            RETURN;
        END IF;
    END LOOP;

    -- The bundle row: an unsigned container, a fresh chain root, carrying the
    -- inner-file manifest. Its creator seeds the standing chain ACL, exactly
    -- like a plain upload.
    INSERT INTO document.document (
        owner, tenant_id, kind, parent_id, filename, storage_ref,
        content_hash, mime, size, status, encryption_key_ref,
        preservation_class, retention_until, inner_files, has_signatures
    )
    VALUES (
        v_owner,
        NULLIF(pi_data->>'tenant_id', ''),
        'container',
        NULL,
        pi_data->>'filename',
        pi_data->>'storage_ref',
        pi_data->>'content_hash',
        pi_data->>'mime',
        (pi_data->>'size')::bigint,
        'received',
        pi_data->>'encryption_key_ref',
        v_presv,
        (pi_data->>'retention_until')::timestamptz,
        pi_data->'inner_files',
        false   -- an unsigned bundle carries no signatures (built by BuildUnsigned)
    )
    RETURNING id INTO v_id;

    INSERT INTO document.document_acl (chain_root_id, principal_kind, principal_id, rights, tenant_id, granted_by)
    VALUES (v_id, 'sub', v_owner, ARRAY['read', 'cosign']::text[], NULLIF(pi_data->>'tenant_id', ''), v_owner)
    ON CONFLICT (chain_root_id, principal_kind, principal_id) DO NOTHING;

    -- Absorb: the loose sources' rows + ACL entries go away entirely (hard
    -- delete — the bytes' new home is the bundle, so no history record).
    DELETE FROM document.document_acl WHERE chain_root_id = ANY(v_ids);
    WITH gone AS (
        DELETE FROM document.document d
        WHERE d.id = ANY(v_ids)
        RETURNING d.id, d.storage_ref, d.encryption_key_ref
    )
    SELECT COALESCE(jsonb_agg(jsonb_build_object(
               'id', id, 'storageRef', storage_ref, 'encryptionKeyRef', encryption_key_ref)), '[]'::jsonb)
      INTO v_absorbed
    FROM gone;

    po_data := util.result_success(jsonb_build_object('id', v_id, 'absorbed', v_absorbed));
EXCEPTION
    WHEN SQLSTATE 'P0001' THEN
        RAISE;
    WHEN OTHERS THEN
        RAISE EXCEPTION '%', util.result_error('document:bundle_failed', SQLERRM) USING ERRCODE = 'P0001';
END
$$;

-- document.rebundle_container — replace an UNSIGNED bundle's bytes in place (a
-- draft edit: add / remove / reorder inner files) under the same optimistic CAS
-- as replace_container_blob, refreshing the inner-file manifest. Unlike
-- replace_container_blob it never touches status: only a status='received'
-- container may be rebundled (a signed container is immutable except through
-- signature merges), and it stays 'received'. Newly staged loose sources are
-- absorbed exactly as in bundle_sources. Returns the prior blob refs + the
-- absorbed refs for post-commit destruction.
-- pi_data = { caller_sub, doc_id, expected_hash, storage_ref, content_hash,
--             size, encryption_key_ref, inner_files, absorb_source_ids? }
CREATE OR REPLACE PROCEDURE document.rebundle_container(pi_data jsonb, INOUT po_data jsonb)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = document, util, pg_temp
AS $$
DECLARE
    v_owner    text := pi_data->>'caller_sub';
    v_doc      text := pi_data->>'doc_id';
    v_expected text := pi_data->>'expected_hash';
    v_ids      text[] := ARRAY[]::text[];
    v_sid      text;
    v_kind     text;
    v_status   text;
    v_sowner   text;
    v_held     boolean;
    v_cur_hash text;
    v_old_stor text;
    v_old_keyr text;
    v_row      jsonb;
    v_absorbed jsonb := '[]'::jsonb;
BEGIN
    IF v_owner IS NULL OR v_owner = '' OR v_doc IS NULL OR v_doc = '' THEN
        po_data := util.result_error('document:invalid', 'caller_sub and doc_id are required');
        RETURN;
    END IF;
    IF v_expected IS NULL OR v_expected = '' THEN
        po_data := util.result_error('document:invalid', 'expected_hash is required');
        RETURN;
    END IF;
    IF (pi_data->>'storage_ref') IS NULL OR (pi_data->>'content_hash') IS NULL
       OR (pi_data->>'size') IS NULL OR (pi_data->>'encryption_key_ref') IS NULL THEN
        po_data := util.result_error('document:invalid', 'storage_ref, content_hash, size and encryption_key_ref are required');
        RETURN;
    END IF;

    SELECT content_hash, kind, status, owner, legal_hold, storage_ref, encryption_key_ref
      INTO v_cur_hash, v_kind, v_status, v_sowner, v_held, v_old_stor, v_old_keyr
    FROM document.document
    WHERE id = v_doc
    FOR UPDATE;

    IF v_sowner IS NULL OR v_sowner <> v_owner OR v_status IN ('deleted', 'expired') THEN
        po_data := util.result_error('document:not_found', 'no document for that id');
        RETURN;
    END IF;
    IF v_kind <> 'container' OR v_status <> 'received' THEN
        po_data := util.result_error('document:not_bundleable', 'only an unsigned bundle can be rebundled');
        RETURN;
    END IF;
    IF COALESCE(v_held, false) THEN
        po_data := util.result_error('document:legal_hold', 'document is under legal hold and cannot be rebundled');
        RETURN;
    END IF;
    IF v_cur_hash <> v_expected THEN
        po_data := util.result_error('document:chain_advanced', 'the bundle changed since it was loaded; reload the latest and retry');
        RETURN;
    END IF;

    IF jsonb_typeof(pi_data->'absorb_source_ids') = 'array' THEN
        SELECT COALESCE(array_agg(value), ARRAY[]::text[]) INTO v_ids
        FROM jsonb_array_elements_text(pi_data->'absorb_source_ids');
    END IF;

    FOREACH v_sid IN ARRAY v_ids LOOP
        SELECT kind, status, owner, legal_hold
          INTO v_kind, v_status, v_sowner, v_held
        FROM document.document
        WHERE id = v_sid
        FOR UPDATE;

        IF v_sowner IS NULL OR v_sowner <> v_owner OR v_status IN ('deleted', 'expired') THEN
            po_data := util.result_error('document:not_found', 'no document for id ' || v_sid);
            RETURN;
        END IF;
        -- Bundleable: an unsigned source, OR an already-signed file — a signed PDF or
        -- a signed ASiC-E container (an annex such as a counterparty's signed letter).
        -- A signed input rides in as a data object: the new container's signature
        -- covers its bytes, and its own signatures stay intact inside it. An UNSIGNED
        -- container is never an input — that is a draft bundle, which is rebundled.
        IF NOT ((v_kind = 'source' AND v_status = 'received')
             OR (v_kind IN ('pdf', 'container') AND v_status = 'signed')) THEN
            po_data := util.result_error('document:not_bundleable', 'only an unsigned source or an already-signed file (PDF or ASiC-E) can be bundled: ' || v_sid);
            RETURN;
        END IF;
        IF COALESCE(v_held, false) THEN
            po_data := util.result_error('document:legal_hold', 'a source is under legal hold and cannot be absorbed: ' || v_sid);
            RETURN;
        END IF;
    END LOOP;

    UPDATE document.document AS d
       SET storage_ref        = pi_data->>'storage_ref',
           content_hash       = pi_data->>'content_hash',
           size               = (pi_data->>'size')::bigint,
           encryption_key_ref = pi_data->>'encryption_key_ref',
           inner_files        = pi_data->'inner_files',
           has_signatures     = false   -- a draft edit leaves the bundle unsigned
     WHERE d.id = v_doc
    RETURNING to_jsonb(d) INTO v_row;

    IF array_length(v_ids, 1) IS NOT NULL THEN
        DELETE FROM document.document_acl WHERE chain_root_id = ANY(v_ids);
        WITH gone AS (
            DELETE FROM document.document d
            WHERE d.id = ANY(v_ids)
            RETURNING d.id, d.storage_ref, d.encryption_key_ref
        )
        SELECT COALESCE(jsonb_agg(jsonb_build_object(
                   'id', id, 'storageRef', storage_ref, 'encryptionKeyRef', encryption_key_ref)), '[]'::jsonb)
          INTO v_absorbed
        FROM gone;
    END IF;

    po_data := util.result_success(jsonb_build_object(
        'document', v_row,
        'oldStorageRef', v_old_stor,
        'oldEncryptionKeyRef', v_old_keyr,
        'absorbed', v_absorbed));
EXCEPTION
    WHEN SQLSTATE 'P0001' THEN
        RAISE;
    WHEN OTHERS THEN
        RAISE EXCEPTION '%', util.result_error('document:rebundle_failed', SQLERRM) USING ERRCODE = 'P0001';
END
$$;

-- document.chain_retention — when the bytes of a chain stop being downloadable.
--
-- Answers one question for the service that administers a chain's sharing: what is
-- the LAST moment any live row of this chain can still be read? The workflow that
-- tracks these documents keeps its own record only as long as that download exists,
-- and it cannot work the answer out for itself — retention rolls forward every time
-- a signature lands, so any value it copied earlier is already a lower bound.
--
-- Deliberately NOT owner-scoped and byte-free. It is reached with the chain-sharing
-- authority (the same one that grants access and freezes the result), returns no
-- content, no owner and no personal data — only an instant and whether anything is
-- still stored. Rows whose storage is already destroyed are ignored: a purged row's
-- retention_until is in the past and says nothing about what remains.
--
-- `retention_until` is NULL in the answer when the chain holds no live bytes at all
-- (everything purged, or nothing but tombstones) — which the caller reads as "there
-- is no download left to outlive".
-- pi_data = { id }.
CREATE OR REPLACE PROCEDURE document.chain_retention(pi_data jsonb, INOUT po_data jsonb)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = document, util, pg_temp
AS $$
DECLARE
    v_id    text := pi_data->>'id';
    v_root  text;
    v_until timestamptz;
    v_live  integer;
BEGIN
    IF v_id IS NULL OR v_id = '' THEN
        po_data := util.result_error('document:invalid', 'id is required');
        RETURN;
    END IF;

    SELECT COALESCE(NULLIF(d.parent_id, ''), d.id) INTO v_root
    FROM document.document d
    WHERE d.id = v_id;

    IF v_root IS NULL THEN
        po_data := util.result_error('document:not_found', 'no document for that id');
        RETURN;
    END IF;

    SELECT max(d.retention_until), count(*)
      INTO v_until, v_live
    FROM document.document d
    WHERE COALESCE(NULLIF(d.parent_id, ''), d.id) = v_root
      AND d.storage_ref IS NOT NULL;

    po_data := util.result_success(jsonb_build_object(
        'chainRoot', v_root, 'retentionUntil', v_until, 'liveRows', v_live));
EXCEPTION
    WHEN SQLSTATE 'P0001' THEN
        RAISE;
    WHEN OTHERS THEN
        RAISE EXCEPTION '%', util.result_error('document:chain_retention_failed', SQLERRM) USING ERRCODE = 'P0001';
END
$$;

-- Ownership: every procedure runs as the table owner.

-- EXECUTE-only: revoke from PUBLIC, grant only to the service role.
REVOKE ALL ON PROCEDURE document.insert(jsonb, jsonb)                 FROM PUBLIC;
REVOKE ALL ON PROCEDURE document.get(jsonb, jsonb)                    FROM PUBLIC;
REVOKE ALL ON PROCEDURE document.get_container_by_parent(jsonb, jsonb) FROM PUBLIC;
REVOKE ALL ON PROCEDURE document.get_latest_signed_pdf_by_chain(jsonb, jsonb) FROM PUBLIC;
REVOKE ALL ON PROCEDURE document.list(jsonb, jsonb)                   FROM PUBLIC;
REVOKE ALL ON PROCEDURE document.list_chains(jsonb, jsonb)            FROM PUBLIC;
REVOKE ALL ON PROCEDURE document.get_chain(jsonb, jsonb)              FROM PUBLIC;
REVOKE ALL ON PROCEDURE document.list_history(jsonb, jsonb)           FROM PUBLIC;
REVOKE ALL ON PROCEDURE document.sweep_history(jsonb, jsonb)          FROM PUBLIC;
REVOKE ALL ON PROCEDURE document.delete_history_chain(jsonb, jsonb)   FROM PUBLIC;
REVOKE ALL ON PROCEDURE document.set_status(jsonb, jsonb)             FROM PUBLIC;
REVOKE ALL ON PROCEDURE document.extend_retention(jsonb, jsonb)       FROM PUBLIC;
REVOKE ALL ON PROCEDURE document.remove_access(jsonb, jsonb)          FROM PUBLIC;
REVOKE ALL ON PROCEDURE document.sweep_retention(jsonb, jsonb)        FROM PUBLIC;
REVOKE ALL ON PROCEDURE document.grant_acl(jsonb, jsonb)              FROM PUBLIC;
REVOKE ALL ON PROCEDURE document.set_result_freeze(jsonb, jsonb)      FROM PUBLIC;
REVOKE ALL ON PROCEDURE document.chain_retention(jsonb, jsonb)        FROM PUBLIC;
REVOKE ALL ON PROCEDURE document.replace_container_blob(jsonb, jsonb) FROM PUBLIC;
REVOKE ALL ON PROCEDURE document.bundle_sources(jsonb, jsonb)          FROM PUBLIC;
REVOKE ALL ON PROCEDURE document.rebundle_container(jsonb, jsonb)      FROM PUBLIC;

GRANT EXECUTE ON PROCEDURE document.insert(jsonb, jsonb)                 TO document_public;
GRANT EXECUTE ON PROCEDURE document.get(jsonb, jsonb)                    TO document_public;
GRANT EXECUTE ON PROCEDURE document.get_container_by_parent(jsonb, jsonb) TO document_public;
GRANT EXECUTE ON PROCEDURE document.get_latest_signed_pdf_by_chain(jsonb, jsonb) TO document_public;
GRANT EXECUTE ON PROCEDURE document.list(jsonb, jsonb)                   TO document_public;
GRANT EXECUTE ON PROCEDURE document.list_chains(jsonb, jsonb)            TO document_public;
GRANT EXECUTE ON PROCEDURE document.get_chain(jsonb, jsonb)              TO document_public;
GRANT EXECUTE ON PROCEDURE document.list_history(jsonb, jsonb)           TO document_public;
GRANT EXECUTE ON PROCEDURE document.sweep_history(jsonb, jsonb)          TO document_public;
GRANT EXECUTE ON PROCEDURE document.delete_history_chain(jsonb, jsonb)   TO document_public;
GRANT EXECUTE ON PROCEDURE document.set_status(jsonb, jsonb)             TO document_public;
GRANT EXECUTE ON PROCEDURE document.extend_retention(jsonb, jsonb)       TO document_public;
GRANT EXECUTE ON PROCEDURE document.remove_access(jsonb, jsonb)          TO document_public;
GRANT EXECUTE ON PROCEDURE document.sweep_retention(jsonb, jsonb)        TO document_public;
GRANT EXECUTE ON PROCEDURE document.grant_acl(jsonb, jsonb)              TO document_public;
GRANT EXECUTE ON PROCEDURE document.set_result_freeze(jsonb, jsonb)      TO document_public;
GRANT EXECUTE ON PROCEDURE document.chain_retention(jsonb, jsonb)        TO document_public;
GRANT EXECUTE ON PROCEDURE document.replace_container_blob(jsonb, jsonb) TO document_public;
GRANT EXECUTE ON PROCEDURE document.bundle_sources(jsonb, jsonb)          TO document_public;
GRANT EXECUTE ON PROCEDURE document.rebundle_container(jsonb, jsonb)      TO document_public;

-- ACL helper functions: owned by the migrating role, invoked only inside the procedures
-- above (no service-role EXECUTE — document_public never calls them directly).
REVOKE ALL ON FUNCTION document.normalize_serial(text)             FROM PUBLIC;
REVOKE ALL ON FUNCTION document.acl_allows(text, text, text, text) FROM PUBLIC;

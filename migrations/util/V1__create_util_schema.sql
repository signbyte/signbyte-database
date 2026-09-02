-- V1: shared `util` schema.
--
-- Provides the cross-cutting primitives the data-layer pattern depends on: ULID
-- id generation (`generate_ulid()`) and the structured JSONB result envelope
-- (`result_success` / `result_error`) used by every SECURITY DEFINER procedure.
-- These live in `util` so each domain schema can reuse them without duplication.

-- Ownership is implicit: the migration connects as the database owner role, so
-- every schema and object created here is owned by that role. SECURITY DEFINER
-- procedures run as the owner, so the runtime service roles never need table
-- access. The owner is provisioned at bootstrap (the DB owner / POSTGRES_USER);
-- it is used ONLY to run migrations, never as a service runtime identity, and no
-- role or credential is ever created inside a migration.

CREATE SCHEMA IF NOT EXISTS util;

-- pgcrypto is installed INTO util, never the default (public) schema: no routine
-- in this data layer may carry `public` on its search_path, and an extension in
-- `public` would force exactly that on every caller of generate_ulid(). Keeping
-- it here lets the whole layer resolve names without ever entering a schema that
-- anything else can write to. The schema must exist before the extension can be
-- placed in it, hence the order.
CREATE EXTENSION IF NOT EXISTS pgcrypto WITH SCHEMA util;

-- generate_ulid() — a lexicographically sortable, 26-char Crockford-Base32 ULID
-- (48-bit ms timestamp + 80 bits of CSPRNG entropy). Used as the primary-key
-- generator across the domain schemas.
CREATE OR REPLACE FUNCTION util.generate_ulid()
RETURNS text
LANGUAGE plpgsql
VOLATILE
-- Pinned to util (where pgcrypto lives) with pg_temp last, so gen_random_bytes
-- resolves no matter which schema's procedure called this, and a caller's temp
-- objects can never shadow a name here.
SET search_path = util, pg_temp
AS $$
DECLARE
    -- Both byte buffers are cast explicitly: an untyped literal assigned to a
    -- bytea local relies on an implicit text→bytea coercion, which static
    -- analysis flags. Same values, stated types.
    encoding  bytea = '0123456789ABCDEFGHJKMNPQRSTVWXYZ'::bytea;
    timestamp bytea = E'\\000\\000\\000\\000\\000\\000'::bytea;
    output    text  = '';
    unix_time bigint;
    ulid      bytea;
BEGIN
    unix_time = (EXTRACT(EPOCH FROM clock_timestamp()) * 1000)::bigint;
    timestamp = SET_BYTE(timestamp, 0, (unix_time >> 40)::bit(8)::integer);
    timestamp = SET_BYTE(timestamp, 1, (unix_time >> 32)::bit(8)::integer);
    timestamp = SET_BYTE(timestamp, 2, (unix_time >> 24)::bit(8)::integer);
    timestamp = SET_BYTE(timestamp, 3, (unix_time >> 16)::bit(8)::integer);
    timestamp = SET_BYTE(timestamp, 4, (unix_time >> 8)::bit(8)::integer);
    timestamp = SET_BYTE(timestamp, 5, unix_time::bit(8)::integer);

    -- 10 bytes of entropy.
    ulid = timestamp || util.gen_random_bytes(10);

    -- Encode 16 bytes → 26 Base32 chars (RFC: ULID spec).
    output = output || CHR(GET_BYTE(encoding, (GET_BYTE(ulid, 0) & 224) >> 5));
    output = output || CHR(GET_BYTE(encoding, (GET_BYTE(ulid, 0) & 31)));
    output = output || CHR(GET_BYTE(encoding, (GET_BYTE(ulid, 1) & 248) >> 3));
    output = output || CHR(GET_BYTE(encoding, ((GET_BYTE(ulid, 1) & 7) << 2) | ((GET_BYTE(ulid, 2) & 192) >> 6)));
    output = output || CHR(GET_BYTE(encoding, (GET_BYTE(ulid, 2) & 62) >> 1));
    output = output || CHR(GET_BYTE(encoding, ((GET_BYTE(ulid, 2) & 1) << 4) | ((GET_BYTE(ulid, 3) & 240) >> 4)));
    output = output || CHR(GET_BYTE(encoding, ((GET_BYTE(ulid, 3) & 15) << 1) | ((GET_BYTE(ulid, 4) & 128) >> 7)));
    output = output || CHR(GET_BYTE(encoding, (GET_BYTE(ulid, 4) & 124) >> 2));
    output = output || CHR(GET_BYTE(encoding, ((GET_BYTE(ulid, 4) & 3) << 3) | ((GET_BYTE(ulid, 5) & 224) >> 5)));
    output = output || CHR(GET_BYTE(encoding, (GET_BYTE(ulid, 5) & 31)));
    output = output || CHR(GET_BYTE(encoding, (GET_BYTE(ulid, 6) & 248) >> 3));
    output = output || CHR(GET_BYTE(encoding, ((GET_BYTE(ulid, 6) & 7) << 2) | ((GET_BYTE(ulid, 7) & 192) >> 6)));
    output = output || CHR(GET_BYTE(encoding, (GET_BYTE(ulid, 7) & 62) >> 1));
    output = output || CHR(GET_BYTE(encoding, ((GET_BYTE(ulid, 7) & 1) << 4) | ((GET_BYTE(ulid, 8) & 240) >> 4)));
    output = output || CHR(GET_BYTE(encoding, ((GET_BYTE(ulid, 8) & 15) << 1) | ((GET_BYTE(ulid, 9) & 128) >> 7)));
    output = output || CHR(GET_BYTE(encoding, (GET_BYTE(ulid, 9) & 124) >> 2));
    output = output || CHR(GET_BYTE(encoding, ((GET_BYTE(ulid, 9) & 3) << 3) | ((GET_BYTE(ulid, 10) & 224) >> 5)));
    output = output || CHR(GET_BYTE(encoding, (GET_BYTE(ulid, 10) & 31)));
    output = output || CHR(GET_BYTE(encoding, (GET_BYTE(ulid, 11) & 248) >> 3));
    output = output || CHR(GET_BYTE(encoding, ((GET_BYTE(ulid, 11) & 7) << 2) | ((GET_BYTE(ulid, 12) & 192) >> 6)));
    output = output || CHR(GET_BYTE(encoding, (GET_BYTE(ulid, 12) & 62) >> 1));
    output = output || CHR(GET_BYTE(encoding, ((GET_BYTE(ulid, 12) & 1) << 4) | ((GET_BYTE(ulid, 13) & 240) >> 4)));
    output = output || CHR(GET_BYTE(encoding, ((GET_BYTE(ulid, 13) & 15) << 1) | ((GET_BYTE(ulid, 14) & 128) >> 7)));
    output = output || CHR(GET_BYTE(encoding, (GET_BYTE(ulid, 14) & 124) >> 2));
    output = output || CHR(GET_BYTE(encoding, ((GET_BYTE(ulid, 14) & 3) << 3) | ((GET_BYTE(ulid, 15) & 224) >> 5)));
    output = output || CHR(GET_BYTE(encoding, (GET_BYTE(ulid, 15) & 31)));

    RETURN output;
END
$$;

-- result_success(data) → {"result":"success","data":<data>}
CREATE OR REPLACE FUNCTION util.result_success(pi_data jsonb DEFAULT '{}'::jsonb)
RETURNS jsonb
LANGUAGE sql
IMMUTABLE
-- Body references only built-ins (pg_catalog is searched first regardless), so
-- nothing but pg_temp is needed — pinned all the same, because "every routine
-- pins a search_path" is a rule a linter can check and a habit is not.
SET search_path = pg_temp
AS $$
    SELECT jsonb_build_object('result', 'success', 'data', COALESCE(pi_data, '{}'::jsonb));
$$;

-- result_error(code, message) → {"result":"error","code":<code>,"message":<msg>}
CREATE OR REPLACE FUNCTION util.result_error(pi_code text, pi_message text DEFAULT '')
RETURNS jsonb
LANGUAGE sql
IMMUTABLE
SET search_path = pg_temp
AS $$
    SELECT jsonb_build_object('result', 'error', 'code', pi_code, 'message', pi_message);
$$;

-- Least privilege: nothing in util is public; the owner owns it, so every
-- schema's SECURITY DEFINER procedures (which also run as the owner) can call
-- these helpers without extra grants.
REVOKE ALL ON SCHEMA util FROM PUBLIC;
REVOKE ALL ON ALL FUNCTIONS IN SCHEMA util FROM PUBLIC;

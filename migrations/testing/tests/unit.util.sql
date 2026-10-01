-- SQL unit tests for the shared `util` schema (util/V1 and its repeatable
-- helpers): the ULID generator every domain schema's primary keys are minted
-- with, the JSONB result envelope helpers every SECURITY DEFINER procedure
-- answers through, and the version token of a section of configuration. Same
-- self-contained DO-block shape as the other unit tests — seed-then-assert,
-- one RAISE EXCEPTION per failed assertion; a clean run prints only NOTICEs.
--
-- Run as the owner (util grants nothing to PUBLIC by design):
--   psql "$DSN" -f migrations/testing/tests/unit.util.sql
do $$
declare
  v_a      text;
  v_b      text;
  v_count  int;
  r        record;
begin
  ------------------------------------------------------------------
  -- generate_ulid: 26 characters, Crockford Base32 only (no I, L, O, U).
  ------------------------------------------------------------------
  v_a := util.generate_ulid();
  if v_a is null then raise exception 'generate_ulid returned NULL'; end if;
  if length(v_a) is distinct from 26 then
    raise exception 'expected a 26-char ULID, got % chars: %', length(v_a), v_a;
  end if;
  if v_a !~ '^[0-9A-HJKMNP-TV-Z]{26}$' then
    raise exception 'ULID carries characters outside Crockford Base32: %', v_a;
  end if;

  ------------------------------------------------------------------
  -- The leading 10 characters encode the 48-bit millisecond timestamp, so a
  -- later call sorts strictly after an earlier one: ids are time-ordered, which
  -- is the property the newest-first list procedures rely on.
  ------------------------------------------------------------------
  perform pg_sleep(0.05);
  v_b := util.generate_ulid();
  -- Assert the second id's shape before ordering the two, for the same reason
  -- the first one's is asserted: both comparisons below are ordering operators,
  -- and a NULL on either side makes them NULL rather than true, so a generator
  -- that returned nothing would slip through both of them silently.
  if length(v_b) is distinct from 26 then
    raise exception 'expected a 26-char ULID from the second call, got % chars: %', length(v_b), v_b;
  end if;
  if left(v_b, 10) <= left(v_a, 10) then
    raise exception 'expected the timestamp prefix to advance between calls: % then %', v_a, v_b;
  end if;
  if v_b <= v_a then
    raise exception 'expected ULIDs to be lexicographically sortable: % then %', v_a, v_b;
  end if;

  ------------------------------------------------------------------
  -- The trailing 80 bits are entropy: ids minted inside one millisecond must
  -- still be unique (they are primary keys).
  ------------------------------------------------------------------
  select count(distinct util.generate_ulid()) into v_count from generate_series(1, 1000);
  if v_count is distinct from 1000 then
    raise exception 'expected 1000 distinct ULIDs, got %', v_count;
  end if;

  ------------------------------------------------------------------
  -- result_success / result_error: the exact envelope services parse.
  ------------------------------------------------------------------
  if util.result_success(jsonb_build_object('id', 'x')) is distinct from '{"result":"success","data":{"id":"x"}}'::jsonb then
    raise exception 'unexpected result_success envelope: %', util.result_success(jsonb_build_object('id', 'x'));
  end if;
  -- No data, and an explicit NULL, both answer an empty data object.
  if util.result_success() is distinct from '{"result":"success","data":{}}'::jsonb then
    raise exception 'expected an empty data object by default, got: %', util.result_success();
  end if;
  if util.result_success(null) is distinct from '{"result":"success","data":{}}'::jsonb then
    raise exception 'expected an empty data object for NULL data, got: %', util.result_success(null);
  end if;

  if util.result_error('membership:invalid', 'actor is required')
     is distinct from '{"result":"error","code":"membership:invalid","message":"actor is required"}'::jsonb then
    raise exception 'unexpected result_error envelope: %', util.result_error('membership:invalid', 'actor is required');
  end if;
  -- The message is optional; the code never is.
  if util.result_error('membership:invalid') is distinct from '{"result":"error","code":"membership:invalid","message":""}'::jsonb then
    raise exception 'expected an empty message by default, got: %', util.result_error('membership:invalid');
  end if;

  ------------------------------------------------------------------
  -- config_token: the version of a section of configuration. Readers keep
  -- tokens they were given and compare them for equality later, so the bytes
  -- a token is computed from can never move: the section's schema name, a
  -- line break, the scope, a line break and the section's text, hashed as
  -- UTF-8. Asserted twice — against that formula written out here, for both
  -- sections that carry a token today, and against literal tokens (an
  -- independent SHA-256 of the same bytes gives the same ones), so a change
  -- to the helper cannot pass by changing the formula beside it too.
  ------------------------------------------------------------------
  for r in
    select s.schema_name, i.scope, i.section
      from (values ('flowbyte-config/1'), ('flowbyte-features-config/1')) s(schema_name),
           (values ('tenant-a', '{"b": [1, 2], "a": "x"}'::jsonb),
                   ('tenant-ā', '{"label": "Frēzēšana"}'::jsonb),
                   ('tenant-a', '{}'::jsonb)) i(scope, section)
  loop
    if util.config_token(r.schema_name, r.scope, r.section) is distinct from
       'sha256:' || encode(sha256(convert_to(r.schema_name || chr(10) || r.scope || chr(10) || r.section::text, 'UTF8')), 'hex') then
      raise exception 'config_token(%, %, %) is not the hash of schema, scope and section: %',
        r.schema_name, r.scope, r.section, util.config_token(r.schema_name, r.scope, r.section);
    end if;
  end loop;

  if util.config_token('flowbyte-config/1', 'tenant-a', '{"b": [1, 2], "a": "x"}')
     is distinct from 'sha256:050f8c3c22280028e3ea6da5f045d1b5388bc28fb59b32d7a8e6b84a1df958bc' then
    raise exception 'config_token moved an engine token: %', util.config_token('flowbyte-config/1', 'tenant-a', '{"b": [1, 2], "a": "x"}');
  end if;
  if util.config_token('flowbyte-config/1', 'tenant-ā', '{"label": "Frēzēšana"}')
     is distinct from 'sha256:0d01ab8e3ab9fc6df236c3417759647784f6452f88200232fa5256655a030623' then
    raise exception 'config_token moved an engine token over non-ASCII text: %', util.config_token('flowbyte-config/1', 'tenant-ā', '{"label": "Frēzēšana"}');
  end if;
  if util.config_token('flowbyte-features-config/1', 'tenant-a', '{"b": [1, 2], "a": "x"}')
     is distinct from 'sha256:a8b43018e155ec29529be160901ac7684a8cdebbfc5a77d9af3c6e7d87141d7f' then
    raise exception 'config_token moved a register token: %', util.config_token('flowbyte-features-config/1', 'tenant-a', '{"b": [1, 2], "a": "x"}');
  end if;
  if util.config_token('flowbyte-features-config/1', 'tenant-a', '{}')
     is distinct from 'sha256:dc9afb5f0d4a7271959eabbfa9f81db2f3d27b61fb1d6a8180ddc7f87334c62a' then
    raise exception 'config_token moved a register token over an empty section: %', util.config_token('flowbyte-features-config/1', 'tenant-a', '{}');
  end if;

  -- The schema name keeps two sections apart and the scope keeps two holders
  -- apart: the same section under either a different name or a different scope
  -- is a different token.
  if util.config_token('flowbyte-config/1', 'tenant-a', '{}')
     is not distinct from util.config_token('flowbyte-features-config/1', 'tenant-a', '{}') then
    raise exception 'two sections share a token';
  end if;
  if util.config_token('flowbyte-config/1', 'tenant-a', '{}')
     is not distinct from util.config_token('flowbyte-config/1', 'tenant-b', '{}') then
    raise exception 'two scopes share a token';
  end if;

  raise notice 'unit.util.sql: ALL ASSERTIONS PASSED';
end $$;

select 'unit.util.sql: PASS' as result;

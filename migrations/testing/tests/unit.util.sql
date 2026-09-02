-- SQL unit tests for the shared `util` schema (util/V1): the ULID generator
-- every domain schema's primary keys are minted with, and the JSONB result
-- envelope helpers every SECURITY DEFINER procedure answers through. Same
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

  raise notice 'unit.util.sql: ALL ASSERTIONS PASSED';
end $$;

select 'unit.util.sql: PASS' as result;

-- Unit test: a tenant's membership history, newest first, a page at a time. A
-- tenant holding well over a thousand lines answers its newest hundred first and
-- says older ones exist; walking it page by page with `before` returns every
-- line exactly once in order, thirty lines sharing one moment included; the
-- chart's lines are found by their family however old they are and however many
-- other lines are newer; a page never exceeds 500; the service filter and the
-- time window page the same way; another tenant's lines never appear; a bad
-- limit and a `before` naming no line of this history are refused. Narrowed to
-- one person it answers what they wrote and what no person wrote about them,
-- page by page, and never what another person wrote about them; narrowed to
-- whoever runs the deployment it answers the lines no person and no service
-- wrote; a service's own lines are found by its key.
--   psql -v ON_ERROR_STOP=1 -f migrations/testing/tests/unit.rolebyte_history.sql

-- Calls one register procedure and returns its answer, a refusal it raises
-- (its structured error is the exception's message) included.
CREATE OR REPLACE FUNCTION pg_temp.rb(p_proc text, p_in jsonb) RETURNS jsonb
LANGUAGE plpgsql AS $$
DECLARE
    v jsonb;
BEGIN
    EXECUTE format('CALL rolebyte.%I($1, NULL::jsonb)', p_proc) INTO v USING p_in;
    RETURN v;
EXCEPTION
    WHEN sqlstate 'P0001' THEN
        RETURN SQLERRM::jsonb;
END $$;

-- The call must succeed; returns its data.
CREATE OR REPLACE FUNCTION pg_temp.ok(p_proc text, p_in jsonb, p_why text) RETURNS jsonb
LANGUAGE plpgsql AS $$
DECLARE
    v jsonb := pg_temp.rb(p_proc, p_in);
BEGIN
    IF v->>'result' IS DISTINCT FROM 'success' THEN
        RAISE EXCEPTION '% failed: %', p_why, v;
    END IF;
    RETURN v->'data';
END $$;

-- The call must be refused with this code.
CREATE OR REPLACE FUNCTION pg_temp.refused(p_proc text, p_in jsonb, p_code text, p_why text) RETURNS void
LANGUAGE plpgsql AS $$
DECLARE
    v jsonb := pg_temp.rb(p_proc, p_in);
BEGIN
    IF v->>'result' IS DISTINCT FROM 'error' OR v->>'code' IS DISTINCT FROM p_code THEN
        RAISE EXCEPTION '% should be refused %: %', p_why, p_code, v;
    END IF;
END $$;

-- The line ids of a page, in the order it gives them.
CREATE OR REPLACE FUNCTION pg_temp.ids(p_page jsonb) RETURNS text[]
LANGUAGE sql AS $$
    SELECT COALESCE(array_agg(e->>'id' ORDER BY n), '{}')
      FROM jsonb_array_elements(p_page->'events') WITH ORDINALITY x(e, n);
$$;

-- Every line of a read, walked page by page: each page asks for the lines
-- before the last one it was given, until a page says no older lines exist.
CREATE OR REPLACE FUNCTION pg_temp.walk(p_in jsonb, p_limit int, p_why text) RETURNS text[]
LANGUAGE plpgsql AS $$
DECLARE
    v_all   text[] := '{}';
    v_in    jsonb := p_in || jsonb_build_object('limit', p_limit::text);
    v_page  jsonb;
    v_ids   text[];
    v_pages int := 0;
BEGIN
    LOOP
        v_page := pg_temp.ok('history', v_in, p_why);
        v_ids := pg_temp.ids(v_page);
        v_pages := v_pages + 1;
        IF v_pages > 1 AND cardinality(v_ids) = 0 THEN
            RAISE EXCEPTION '%: the page before said more, and page % is empty', p_why, v_pages;
        END IF;
        IF cardinality(v_ids) > p_limit THEN
            RAISE EXCEPTION '%: page % holds % lines, more than %', p_why, v_pages, cardinality(v_ids), p_limit;
        END IF;
        v_all := v_all || v_ids;
        EXIT WHEN NOT (v_page->>'more')::boolean;
        IF cardinality(v_ids) <> p_limit THEN
            RAISE EXCEPTION '%: page % says more exist but holds only % lines', p_why, v_pages, cardinality(v_ids);
        END IF;
        v_in := v_in || jsonb_build_object('before', v_ids[cardinality(v_ids)]);
        IF v_pages > 1000 THEN
            RAISE EXCEPTION '%: the walk never ends', p_why;
        END IF;
    END LOOP;
    RETURN v_all;
END $$;

DO $$
DECLARE
    v_ta       text;
    v_tb       text;
    v_base     timestamptz := now() - interval '2 days';
    v_tie      timestamptz := now() - interval '1 day';
    v_expected text[];
    v_got      text[];
    v_page     jsonb;
    v_b_line   text;
    v_events   bigint;
    v          jsonb;
    v_anna     text := 'sub:' || util.generate_ulid();
    v_p        text := 'sub:' || util.generate_ulid();
    v_p_id     text;
    v_invite   text;
BEGIN
    -- ---------------------------------------------------------------- fixture
    v := pg_temp.ok('tenant_open', jsonb_build_object('actor', 'op:test', 'name', 'History A',
        'administrator', jsonb_build_object('subjectKey', v_anna, 'displayName', 'Anna Ozola')), 'open A');
    v_ta := v->'tenant'->>'id';
    v := pg_temp.ok('tenant_open', jsonb_build_object('actor', 'op:test', 'name', 'History B',
        'administrator', jsonb_build_object('subjectKey', 'sub:' || util.generate_ulid(), 'displayName', 'Bēla Liepa')), 'open B');
    v_tb := v->'tenant'->>'id';

    -- A busy year in A: 1,200 lines a second apart, roles given on even seconds,
    -- people invited on odd ones, and three chart lines among them, the newest
    -- of which sits past the first thousand. Thirty more lines share one moment.
    INSERT INTO rolebyte.event (id, at, actor, tenant_id, user_id, kind, payload)
    SELECT util.generate_ulid(), v_base + n * interval '1 second', 'adm:test', v_ta, NULL,
           CASE WHEN n IN (50, 600, 1150) THEN CASE WHEN n = 600 THEN 'chartPersonPlaced' ELSE 'chartPositionAdded' END
                WHEN n % 2 = 0 THEN 'roleGranted'
                ELSE 'userInvited' END,
           CASE WHEN n % 2 = 0 AND n NOT IN (50, 600, 1150) THEN jsonb_build_object('service', 'hsvc', 'n', n)
                ELSE jsonb_build_object('n', n) END
      FROM generate_series(1, 1200) n;
    INSERT INTO rolebyte.event (id, at, actor, tenant_id, user_id, kind, payload)
    SELECT util.generate_ulid(), v_tie, 'adm:test', v_ta, NULL, 'userInvited', jsonb_build_object('tie', n)
      FROM generate_series(1, 30) n;
    INSERT INTO rolebyte.event (id, at, actor, tenant_id, user_id, kind, payload)
    SELECT util.generate_ulid(), v_base + n * interval '1 second', 'adm:test', v_tb, NULL, 'chartPositionAdded',
           jsonb_build_object('service', 'hsvc', 'n', n)
      FROM generate_series(1, 10) n;
    SELECT id INTO v_b_line FROM rolebyte.event WHERE tenant_id = v_tb ORDER BY at DESC, id DESC LIMIT 1;

    -- Pēteris, invited to A by Anna: the lines Anna wrote about him are hers.
    -- Then his arrival, written by the sign-in service; two lines he wrote; one
    -- the deployment wrote about him; one a service wrote on its own; and a
    -- line he wrote in B.
    v_p_id := pg_temp.ok('user_invite', jsonb_build_object('actor', v_anna, 'tenantId', v_ta,
        'subjectKey', v_p, 'displayName', 'Pēteris Kalns'), 'invite Pēteris')->>'id';
    SELECT id INTO v_invite FROM rolebyte.event WHERE tenant_id = v_ta AND user_id = v_p_id AND kind = 'userInvited';
    INSERT INTO rolebyte.event (id, at, actor, tenant_id, user_id, kind, payload) VALUES
        (util.generate_ulid(), v_base + interval '10 seconds', 'svc:authbyte', v_ta, v_p_id, 'claimAttached',
         '{"mark":"arrival"}'),
        (util.generate_ulid(), v_base + interval '20 seconds', v_p, v_ta, NULL, 'tenantRoleDefined',
         '{"mark":"p-own-1"}'),
        (util.generate_ulid(), v_base + interval '30 seconds', v_p, v_ta, v_p_id, 'roleGranted',
         '{"mark":"p-own-2"}'),
        (util.generate_ulid(), v_base + interval '40 seconds', 'op:test', v_ta, v_p_id, 'administratorSetByOperator',
         '{"mark":"op-on-p"}'),
        (util.generate_ulid(), v_base + interval '50 seconds', 'svc:flowbyte', v_ta, NULL, 'tenantRolePlacementsSet',
         '{"mark":"svc"}'),
        (util.generate_ulid(), v_base + interval '60 seconds', v_p, v_tb, NULL, 'tenantRoleDefined',
         '{"mark":"p-in-b"}');

    SELECT array_agg(id ORDER BY at DESC, id DESC) INTO v_expected FROM rolebyte.event WHERE tenant_id = v_ta;
    IF cardinality(v_expected) < 1230 THEN
        RAISE EXCEPTION 'the fixture holds % lines in A', cardinality(v_expected);
    END IF;
    SELECT count(*) INTO v_events FROM rolebyte.event;

    -- ------------------------------- (1) the newest hundred first, and a word for more
    v_page := pg_temp.ok('history', jsonb_build_object('tenantId', v_ta), 'A, as the old callers ask');
    IF pg_temp.ids(v_page) IS DISTINCT FROM v_expected[1:100] THEN
        RAISE EXCEPTION 'the first page is the newest hundred lines, newest first: %', (pg_temp.ids(v_page))[1:3];
    END IF;
    IF (v_page->>'more')::boolean IS NOT TRUE THEN
        RAISE EXCEPTION 'older lines exist, and the page says so: %', v_page->'more';
    END IF;

    -- ------------------- (2) the chart's lines, however old and however many are newer
    v_page := pg_temp.ok('history', jsonb_build_object('tenantId', v_ta, 'kindPrefix', 'chart'), 'A''s chart lines');
    IF (SELECT array_agg(e->'payload'->>'n' ORDER BY n) FROM jsonb_array_elements(v_page->'events') WITH ORDINALITY x(e, n))
       IS DISTINCT FROM ARRAY['1150', '600', '50'] THEN
        RAISE EXCEPTION 'the chart''s three lines, newest first: %', v_page;
    END IF;
    IF (v_page->>'more')::boolean IS NOT FALSE THEN
        RAISE EXCEPTION 'no older chart line exists: %', v_page->'more';
    END IF;
    --      A page that holds exactly the lines left says nothing older exists.
    v_page := pg_temp.ok('history', jsonb_build_object('tenantId', v_ta, 'kindPrefix', 'chart', 'limit', '3'), 'three of three');
    IF jsonb_array_length(v_page->'events') <> 3 OR (v_page->>'more')::boolean IS NOT FALSE THEN
        RAISE EXCEPTION 'a page of exactly the three chart lines says no more: %', v_page->'more';
    END IF;
    v_page := pg_temp.ok('history', jsonb_build_object('tenantId', v_ta, 'kindPrefix', 'chart', 'limit', '2'), 'two of three');
    IF jsonb_array_length(v_page->'events') <> 2 OR (v_page->>'more')::boolean IS NOT TRUE THEN
        RAISE EXCEPTION 'a page of two of the three chart lines says more: %', v_page->'more';
    END IF;

    -- ------------------------------- (3) every line exactly once, page by page
    v_got := pg_temp.walk(jsonb_build_object('tenantId', v_ta), 7, 'walk A by sevens');
    IF v_got IS DISTINCT FROM v_expected THEN
        RAISE EXCEPTION 'walking A by sevens gives % lines, % expected, or another order',
            cardinality(v_got), cardinality(v_expected);
    END IF;
    v_got := pg_temp.walk(jsonb_build_object('tenantId', v_ta), 13, 'walk A by thirteens');
    IF v_got IS DISTINCT FROM v_expected THEN
        RAISE EXCEPTION 'walking A by thirteens gives another answer';
    END IF;

    -- ------------------------------------------------- (4) a page is never over 500
    v_page := pg_temp.ok('history', jsonb_build_object('tenantId', v_ta, 'limit', '999999'), 'a huge limit');
    IF cardinality(pg_temp.ids(v_page)) <> 500 OR (v_page->>'more')::boolean IS NOT TRUE THEN
        RAISE EXCEPTION 'a huge limit reads 500 lines and says more: % %', cardinality(pg_temp.ids(v_page)), v_page->'more';
    END IF;
    v_page := pg_temp.ok('history', jsonb_build_object('tenantId', v_ta, 'limit', 5), 'a limit given as a number');
    IF pg_temp.ids(v_page) IS DISTINCT FROM v_expected[1:5] THEN
        RAISE EXCEPTION 'a limit of 5 as a JSON number reads the newest five';
    END IF;

    -- ------------------------------- (5) the service filter and the window page alike
    SELECT array_agg(id ORDER BY at DESC, id DESC) INTO v_expected
      FROM rolebyte.event WHERE tenant_id = v_ta AND payload->>'service' = 'hsvc';
    v_got := pg_temp.walk(jsonb_build_object('tenantId', v_ta, 'service', 'hsvc'), 50, 'walk A''s hsvc lines');
    IF v_got IS DISTINCT FROM v_expected OR cardinality(v_got) <> 597 THEN
        RAISE EXCEPTION 'A''s hsvc lines walked by fifties: % of %', cardinality(v_got), cardinality(v_expected);
    END IF;
    SELECT array_agg(id ORDER BY at DESC, id DESC) INTO v_expected
      FROM rolebyte.event WHERE tenant_id = v_ta
       AND at >= v_base + interval '100 seconds' AND at < v_base + interval '200 seconds';
    v_got := pg_temp.walk(jsonb_build_object('tenantId', v_ta,
        'from', (v_base + interval '100 seconds')::text, 'to', (v_base + interval '200 seconds')::text), 9, 'walk a window');
    IF v_got IS DISTINCT FROM v_expected OR cardinality(v_got) <> 100 THEN
        RAISE EXCEPTION 'a hundred-second window walked by nines: %', cardinality(v_got);
    END IF;

    -- ------------------------------------- (6) each tenant reads only its own lines
    v_got := pg_temp.walk(jsonb_build_object('tenantId', v_tb), 4, 'walk B');
    IF v_got IS DISTINCT FROM (SELECT array_agg(id ORDER BY at DESC, id DESC) FROM rolebyte.event WHERE tenant_id = v_tb) THEN
        RAISE EXCEPTION 'B reads its own lines and none of A''s';
    END IF;
    v_page := pg_temp.ok('history', jsonb_build_object('tenantId', 'no-such-tenant'), 'a tenant with no lines');
    IF v_page->'events' IS DISTINCT FROM '[]'::jsonb OR (v_page->>'more')::boolean IS NOT FALSE THEN
        RAISE EXCEPTION 'a history with no lines is empty and says so: %', v_page;
    END IF;

    -- ------------------------------------------------- (6b) one person's story
    --      What he wrote and what no person wrote about him, newest first, by twos.
    SELECT array_agg(id ORDER BY at DESC, id DESC) INTO v_expected
      FROM rolebyte.event WHERE tenant_id = v_ta AND payload->>'mark' IN ('arrival', 'p-own-1', 'p-own-2', 'op-on-p');
    v_got := pg_temp.walk(jsonb_build_object('tenantId', v_ta, 'actor', v_p), 2, 'walk Pēteris''s story');
    IF cardinality(v_expected) IS DISTINCT FROM 4 OR v_got IS DISTINCT FROM v_expected THEN
        RAISE EXCEPTION 'his story is his two lines, his arrival and the deployment''s act on him: % of %',
            cardinality(v_got), cardinality(v_expected);
    END IF;
    IF v_invite IS NULL OR v_invite = ANY (v_got) THEN
        RAISE EXCEPTION 'the line Anna wrote about him is hers, not his';
    END IF;
    --      Anna's acts include inviting him.
    v_got := pg_temp.walk(jsonb_build_object('tenantId', v_ta, 'actor', v_anna), 50, 'walk Anna''s story');
    IF NOT (v_invite = ANY (v_got))
       OR EXISTS (SELECT 1 FROM rolebyte.event WHERE id = ANY (v_got) AND payload->>'mark' IS NOT NULL) THEN
        RAISE EXCEPTION 'Anna''s story holds her invitation and none of the marked lines';
    END IF;
    --      Narrowed further by family, it keeps narrowing.
    v_page := pg_temp.ok('history', jsonb_build_object('tenantId', v_ta, 'actor', v_p, 'kindPrefix', 'tenantRole'),
        'his tenant-role lines');
    IF (SELECT array_agg(e->'payload'->>'mark') FROM jsonb_array_elements(v_page->'events') e)
       IS DISTINCT FROM ARRAY['p-own-1'] THEN
        RAISE EXCEPTION 'his tenant-role lines are the one he wrote: %', v_page;
    END IF;
    --      In B he is no member: only what he wrote there.
    v_page := pg_temp.ok('history', jsonb_build_object('tenantId', v_tb, 'actor', v_p), 'his line in B');
    IF (SELECT array_agg(e->'payload'->>'mark') FROM jsonb_array_elements(v_page->'events') e)
       IS DISTINCT FROM ARRAY['p-in-b'] THEN
        RAISE EXCEPTION 'in B his story is the one line he wrote there: %', v_page;
    END IF;
    --      Somebody who never acted here has no story here.
    v_page := pg_temp.ok('history', jsonb_build_object('tenantId', v_ta, 'actor', 'sub:' || util.generate_ulid()),
        'a stranger');
    IF v_page->'events' IS DISTINCT FROM '[]'::jsonb OR (v_page->>'more')::boolean IS NOT FALSE THEN
        RAISE EXCEPTION 'a stranger''s story is empty: %', v_page;
    END IF;
    --      A service's own lines, by its key.
    v_page := pg_temp.ok('history', jsonb_build_object('tenantId', v_ta, 'actor', 'svc:flowbyte'), 'a service');
    IF (SELECT array_agg(e->'payload'->>'mark') FROM jsonb_array_elements(v_page->'events') e)
       IS DISTINCT FROM ARRAY['svc'] THEN
        RAISE EXCEPTION 'a service''s story is the lines it wrote: %', v_page;
    END IF;
    --      Whoever runs the deployment: every line neither a person nor a service
    --      wrote — the operator's tools here — and nothing else, walked by 97s.
    SELECT array_agg(id ORDER BY at DESC, id DESC) INTO v_expected
      FROM rolebyte.event WHERE tenant_id = v_ta AND actor IN ('op:test', 'adm:test');
    v_got := pg_temp.walk(jsonb_build_object('tenantId', v_ta, 'actor', 'operator'), 97, 'walk the operator''s lines');
    IF v_got IS DISTINCT FROM v_expected THEN
        RAISE EXCEPTION 'the operator''s lines walked by 97s: % of %', cardinality(v_got), cardinality(v_expected);
    END IF;
    IF NOT EXISTS (SELECT 1 FROM rolebyte.event WHERE id = ANY (v_got) AND payload->>'mark' = 'op-on-p') THEN
        RAISE EXCEPTION 'the deployment''s act on Pēteris is among its lines';
    END IF;

    -- ------------------------------------------------------------- (7) refusals
    PERFORM pg_temp.refused('history', jsonb_build_object('tenantId', v_ta, 'actor', 'nobody'),
        'membership:invalid', 'an actor that is neither a typed key nor operator');
    PERFORM pg_temp.refused('history', jsonb_build_object('tenantId', v_ta, 'actor', 'SUB:01ABC'),
        'membership:invalid', 'a type tag in capitals');
    PERFORM pg_temp.refused('history', jsonb_build_object('tenantId', v_ta, 'limit', '0'), 'membership:invalid', 'a limit of 0');
    PERFORM pg_temp.refused('history', jsonb_build_object('tenantId', v_ta, 'limit', '-3'), 'membership:invalid', 'a negative limit');
    PERFORM pg_temp.refused('history', jsonb_build_object('tenantId', v_ta, 'limit', 'ten'), 'membership:invalid', 'a word for a limit');
    PERFORM pg_temp.refused('history', jsonb_build_object('tenantId', v_ta, 'limit', '2.5'), 'membership:invalid', 'a fraction');
    PERFORM pg_temp.refused('history', jsonb_build_object('tenantId', v_ta, 'limit', '12345678901'), 'membership:invalid', 'a limit too long to be one');
    PERFORM pg_temp.refused('history', jsonb_build_object('tenantId', v_ta, 'before', util.generate_ulid()),
        'membership:invalid', 'a before naming no line');
    PERFORM pg_temp.refused('history', jsonb_build_object('tenantId', v_ta, 'before', v_b_line),
        'membership:invalid', 'a before naming another tenant''s line');
    PERFORM pg_temp.refused('history', jsonb_build_object('tenantId', v_ta, 'from', 'yesterday-ish'),
        'membership:invalid', 'a window that is not a time');
    PERFORM pg_temp.refused('history', '{}', 'membership:invalid', 'no tenant');

    IF (SELECT count(*) FROM rolebyte.event) IS DISTINCT FROM v_events THEN
        RAISE EXCEPTION 'reading the history wrote a line';
    END IF;

    RAISE NOTICE 'unit.rolebyte_history: all assertions passed';
END $$;

-- Unit test: the day a member was last given access. Reading a person's answer
-- to check what they may do writes nothing; answering it to issue their access
-- dates the one membership it is issued for with today's day (UTC): the company
-- the caller names, or, when it names none, the person's only active membership;
-- a person in several companies who names none is dated nowhere. Never an ended
-- membership, an invitation nobody took up, a membership of a suspended tenant,
-- a company the person is not in, and nothing for a stranger. The second answer
-- of a day writes nothing at all; a date from an earlier day moves to today and a
-- later one is never moved back. The answer itself is the same before and after
-- the write, and no history line is written for it.
--   psql -v ON_ERROR_STOP=1 -f migrations/testing/tests/unit.rolebyte_last_signed_in.sql

-- Calls one register procedure; the call must succeed; returns its data.
CREATE OR REPLACE FUNCTION pg_temp.ok(p_proc text, p_in jsonb, p_why text) RETURNS jsonb
LANGUAGE plpgsql AS $$
DECLARE
    v jsonb;
BEGIN
    EXECUTE format('CALL rolebyte.%I($1, NULL::jsonb)', p_proc) INTO v USING p_in;
    IF v->>'result' IS DISTINCT FROM 'success' THEN
        RAISE EXCEPTION '% failed: %', p_why, v;
    END IF;
    RETURN v->'data';
END $$;

-- The register's answer for a subject, whole, as the identity provider asks
-- for it when it issues the person's access.
CREATE OR REPLACE FUNCTION pg_temp.resolved(p_subject text) RETURNS text
LANGUAGE sql AS $$
    SELECT pg_temp.ok('resolve', jsonb_build_object('subjectKey', p_subject, 'issuing', true), 'resolve')::text;
$$;

-- The same, for the company the access is issued for (any JSON value as named).
CREATE OR REPLACE FUNCTION pg_temp.resolved_for(p_subject text, p_tenant jsonb) RETURNS text
LANGUAGE sql AS $$
    SELECT pg_temp.ok('resolve', jsonb_build_object('subjectKey', p_subject, 'issuing', true,
        'issuingTenant', p_tenant), 'resolve for a company')::text;
$$;

-- The same answer read for the register's own check of who may do what.
CREATE OR REPLACE FUNCTION pg_temp.checked(p_subject text, p_in jsonb) RETURNS text
LANGUAGE sql AS $$
    SELECT pg_temp.ok('resolve', jsonb_build_object('subjectKey', p_subject) || p_in, 'resolve to check')::text;
$$;

-- Every member row as it is stored: its physical place changes with any write,
-- even one that leaves every value as it was, so an unchanged fingerprint means
-- nothing was written.
CREATE OR REPLACE FUNCTION pg_temp.rows() RETURNS text
LANGUAGE sql AS $$
    SELECT string_agg(id || ':' || ctid::text || ':' || COALESCE(last_signed_in_on::text, '-'), ',' ORDER BY id)
      FROM rolebyte.user_account;
$$;

-- The day stored on one member row.
CREATE OR REPLACE FUNCTION pg_temp.day(p_user text) RETURNS date
LANGUAGE sql AS $$
    SELECT last_signed_in_on FROM rolebyte.user_account WHERE id = p_user;
$$;

DO $$
DECLARE
    v_today   date := (now() AT TIME ZONE 'UTC')::date;
    v_anna    text := 'sub:' || util.generate_ulid();
    v_bela    text := 'sub:' || util.generate_ulid();
    v_cilda   text := 'sub:' || util.generate_ulid();
    v_ilze    text := 'sub:' || util.generate_ulid();
    v_toms    text := 'sub:' || util.generate_ulid();
    v_juris   text := 'sub:' || util.generate_ulid();
    v_ta      text;
    v_tb      text;
    v_tc      text;
    v_ilze_a  text;
    v_ilze_b  text;
    v_ilze_c  text;
    v_toms_a  text;
    v_juris_a text;
    v_answer  text;
    v_rows    text;
    v_events  bigint;
    v         jsonb;
BEGIN
    IF (SELECT data_type FROM information_schema.columns
         WHERE table_schema = 'rolebyte' AND table_name = 'user_account' AND column_name = 'last_signed_in_on')
       IS DISTINCT FROM 'date' THEN
        RAISE EXCEPTION 'the register keeps a day, never a time';
    END IF;

    -- ---------------------------------------------------------------- fixture
    -- Three tenants. Ilze is a member of all three; C is then suspended. Toms's
    -- access in A ends; Juris is invited to A and never signs in.
    v := pg_temp.ok('tenant_open', jsonb_build_object('actor', 'op:test', 'name', 'Day A',
        'administrator', jsonb_build_object('subjectKey', v_anna, 'displayName', 'Anna Ozola')), 'open A');
    v_ta := v->'tenant'->>'id';
    v := pg_temp.ok('tenant_open', jsonb_build_object('actor', 'op:test', 'name', 'Day B',
        'administrator', jsonb_build_object('subjectKey', v_bela, 'displayName', 'Bēla Liepa')), 'open B');
    v_tb := v->'tenant'->>'id';
    v := pg_temp.ok('tenant_open', jsonb_build_object('actor', 'op:test', 'name', 'Day C',
        'administrator', jsonb_build_object('subjectKey', v_cilda, 'displayName', 'Cilda Egle')), 'open C');
    v_tc := v->'tenant'->>'id';

    v_ilze_a := pg_temp.ok('user_invite', jsonb_build_object('actor', v_anna, 'tenantId', v_ta, 'subjectKey', v_ilze,
        'displayName', 'Ilze Krūmiņa'), 'invite Ilze to A')->>'id';
    v_ilze_b := pg_temp.ok('user_invite', jsonb_build_object('actor', v_bela, 'tenantId', v_tb, 'subjectKey', v_ilze,
        'displayName', 'Ilze Krūmiņa'), 'invite Ilze to B')->>'id';
    v_ilze_c := pg_temp.ok('user_invite', jsonb_build_object('actor', v_cilda, 'tenantId', v_tc, 'subjectKey', v_ilze,
        'displayName', 'Ilze Krūmiņa'), 'invite Ilze to C')->>'id';
    PERFORM pg_temp.ok('claim_attach', jsonb_build_object('actor', 'idp:test', 'subjectKey', v_ilze), 'Ilze signs in');
    UPDATE rolebyte.tenant SET status = 'suspended' WHERE id = v_tc;

    v_toms_a := pg_temp.ok('user_invite', jsonb_build_object('actor', v_anna, 'tenantId', v_ta, 'subjectKey', v_toms,
        'displayName', 'Toms Egle'), 'invite Toms')->>'id';
    PERFORM pg_temp.ok('claim_attach', jsonb_build_object('actor', 'idp:test', 'subjectKey', v_toms), 'Toms signs in');
    PERFORM pg_temp.ok('user_revoke', jsonb_build_object('actor', v_anna, 'tenantId', v_ta, 'userId', v_toms_a), 'Toms leaves');

    v_juris_a := pg_temp.ok('user_invite', jsonb_build_object('actor', v_anna, 'tenantId', v_ta, 'subjectKey', v_juris,
        'displayName', 'Juris Kalns'), 'invite Juris')->>'id';

    IF pg_temp.day(v_ilze_a) IS NOT NULL OR pg_temp.day(v_ilze_b) IS NOT NULL OR pg_temp.day(v_toms_a) IS NOT NULL THEN
        RAISE EXCEPTION 'inviting and signing in are not given access: nobody is dated before an answer';
    END IF;

    -- ------------------- (0) reading the answer to check a caller is not signing in
    v_rows := pg_temp.rows();
    v_answer := pg_temp.checked(v_ilze, '{}');
    PERFORM pg_temp.checked(v_ilze, '{"issuing": false}');
    PERFORM pg_temp.checked(v_ilze, '{"issuing": "true"}');
    IF pg_temp.rows() IS DISTINCT FROM v_rows THEN
        RAISE EXCEPTION 'an answer read without issuing access wrote a row';
    END IF;

    -- ------------------------------ (1) an answer dates the membership it is issued for
    SELECT count(*) INTO v_events FROM rolebyte.event;
    -- Ilze is in two active companies and names none: nobody is dated.
    IF pg_temp.resolved(v_ilze) IS DISTINCT FROM v_answer THEN
        RAISE EXCEPTION 'issuing access answers exactly what a check reads';
    END IF;
    IF pg_temp.day(v_ilze_a) IS NOT NULL OR pg_temp.day(v_ilze_b) IS NOT NULL THEN
        RAISE EXCEPTION 'a person in two companies who names none is dated nowhere: % %',
            pg_temp.day(v_ilze_a), pg_temp.day(v_ilze_b);
    END IF;
    -- Naming A dates A only; naming B afterwards dates B.
    IF pg_temp.resolved_for(v_ilze, to_jsonb(v_ta)) IS DISTINCT FROM v_answer THEN
        RAISE EXCEPTION 'naming a company changes nothing of the answer';
    END IF;
    IF pg_temp.day(v_ilze_a) IS DISTINCT FROM v_today OR pg_temp.day(v_ilze_b) IS NOT NULL THEN
        RAISE EXCEPTION 'naming A dates A only: % %', pg_temp.day(v_ilze_a), pg_temp.day(v_ilze_b);
    END IF;
    PERFORM pg_temp.resolved_for(v_ilze, to_jsonb(v_tb));
    IF pg_temp.day(v_ilze_a) IS DISTINCT FROM v_today OR pg_temp.day(v_ilze_b) IS DISTINCT FROM v_today THEN
        RAISE EXCEPTION 'naming B dates B, A unchanged: % %', pg_temp.day(v_ilze_a), pg_temp.day(v_ilze_b);
    END IF;
    IF pg_temp.day(v_ilze_c) IS NOT NULL THEN
        RAISE EXCEPTION 'a suspended tenant gives no access, so C is not dated';
    END IF;

    -- ------------------------------ (2) the second answer of the day writes nothing
    v_rows := pg_temp.rows();
    IF pg_temp.resolved(v_ilze) IS DISTINCT FROM v_answer THEN
        RAISE EXCEPTION 'the answer is the same whether or not the day was written';
    END IF;
    IF pg_temp.rows() IS DISTINCT FROM v_rows THEN
        RAISE EXCEPTION 'a second answer the same day wrote a row';
    END IF;

    -- ------------------- (3) an earlier day moves to today; a later one never moves back
    UPDATE rolebyte.user_account SET last_signed_in_on = v_today - 41 WHERE id = v_ilze_a;
    UPDATE rolebyte.user_account SET last_signed_in_on = v_today + 1 WHERE id = v_ilze_b;
    PERFORM pg_temp.resolved_for(v_ilze, to_jsonb(v_ta));
    PERFORM pg_temp.resolved_for(v_ilze, to_jsonb(v_tb));
    IF pg_temp.day(v_ilze_a) IS DISTINCT FROM v_today THEN
        RAISE EXCEPTION 'a day 41 days back moves to today: %', pg_temp.day(v_ilze_a);
    END IF;
    IF pg_temp.day(v_ilze_b) IS DISTINCT FROM v_today + 1 THEN
        RAISE EXCEPTION 'a later day is never moved back: %', pg_temp.day(v_ilze_b);
    END IF;

    -- ------------------------- (4) ended, untaken and unknown access dates nothing
    v_rows := pg_temp.rows();
    PERFORM pg_temp.resolved(v_toms);
    PERFORM pg_temp.resolved(v_juris);
    PERFORM pg_temp.resolved('sub:' || util.generate_ulid());
    IF pg_temp.rows() IS DISTINCT FROM v_rows THEN
        RAISE EXCEPTION 'an ended membership, an untaken invitation or a stranger wrote a row';
    END IF;
    IF pg_temp.day(v_toms_a) IS NOT NULL OR pg_temp.day(v_juris_a) IS NOT NULL THEN
        RAISE EXCEPTION 'Toms and Juris are not dated';
    END IF;

    -- ------------------------------------------- (5) the day is not a history line
    IF (SELECT count(*) FROM rolebyte.event) IS DISTINCT FROM v_events THEN
        RAISE EXCEPTION 'being given access writes no history line';
    END IF;

    -- ------------------------------ (6) the company the access is for, and no other
    -- Dace is in A and B; Edgars is in A only.
    DECLARE
        v_dace    text := 'sub:' || util.generate_ulid();
        v_edgars  text := 'sub:' || util.generate_ulid();
        v_dace_a  text;
        v_dace_b  text;
        v_edgars_a text;
        v_with    text;
    BEGIN
        v_dace_a := pg_temp.ok('user_invite', jsonb_build_object('actor', v_anna, 'tenantId', v_ta, 'subjectKey', v_dace,
            'displayName', 'Dace Ruka'), 'invite Dace to A')->>'id';
        v_dace_b := pg_temp.ok('user_invite', jsonb_build_object('actor', v_bela, 'tenantId', v_tb, 'subjectKey', v_dace,
            'displayName', 'Dace Ruka'), 'invite Dace to B')->>'id';
        v_edgars_a := pg_temp.ok('user_invite', jsonb_build_object('actor', v_anna, 'tenantId', v_ta, 'subjectKey', v_edgars,
            'displayName', 'Edgars Vilks'), 'invite Edgars')->>'id';
        PERFORM pg_temp.ok('claim_attach', jsonb_build_object('actor', 'idp:test', 'subjectKey', v_dace), 'Dace signs in');
        PERFORM pg_temp.ok('claim_attach', jsonb_build_object('actor', 'idp:test', 'subjectKey', v_edgars), 'Edgars signs in');

        -- One company at a time.
        PERFORM pg_temp.resolved_for(v_dace, to_jsonb(v_ta));
        IF pg_temp.day(v_dace_a) IS DISTINCT FROM v_today OR pg_temp.day(v_dace_b) IS NOT NULL THEN
            RAISE EXCEPTION 'Dace naming A: A today, B empty: % %', pg_temp.day(v_dace_a), pg_temp.day(v_dace_b);
        END IF;
        PERFORM pg_temp.resolved_for(v_dace, to_jsonb(v_tb));
        IF pg_temp.day(v_dace_a) IS DISTINCT FROM v_today OR pg_temp.day(v_dace_b) IS DISTINCT FROM v_today THEN
            RAISE EXCEPTION 'Dace naming B: B today, A unchanged: % %', pg_temp.day(v_dace_a), pg_temp.day(v_dace_b);
        END IF;

        -- Two companies, none named, nothing written (absent, null and empty alike).
        UPDATE rolebyte.user_account SET last_signed_in_on = NULL WHERE id IN (v_dace_a, v_dace_b);
        PERFORM pg_temp.resolved(v_dace);
        PERFORM pg_temp.resolved_for(v_dace, 'null'::jsonb);
        PERFORM pg_temp.resolved_for(v_dace, to_jsonb(''::text));
        IF pg_temp.day(v_dace_a) IS NOT NULL OR pg_temp.day(v_dace_b) IS NOT NULL THEN
            RAISE EXCEPTION 'no company named, two companies: nothing written';
        END IF;

        -- One company, none named: dated.
        PERFORM pg_temp.resolved(v_edgars);
        IF pg_temp.day(v_edgars_a) IS DISTINCT FROM v_today THEN
            RAISE EXCEPTION 'the only company is dated: %', pg_temp.day(v_edgars_a);
        END IF;

        -- A company they are not in: nothing written, A still answered.
        UPDATE rolebyte.user_account SET last_signed_in_on = NULL WHERE id = v_edgars_a;
        v_rows := pg_temp.rows();
        v_with := pg_temp.resolved_for(v_edgars, to_jsonb(v_tb));
        IF pg_temp.rows() IS DISTINCT FROM v_rows THEN
            RAISE EXCEPTION 'a company the person is not in wrote a row';
        END IF;
        IF (SELECT count(*) FROM jsonb_array_elements(v_with::jsonb->'memberships') m
             WHERE m->>'tenantId' = v_ta) IS DISTINCT FROM 1 THEN
            RAISE EXCEPTION 'the answer still lists A: %', v_with;
        END IF;

        -- A number is taken as absent (two companies: nothing; one: dated).
        PERFORM pg_temp.resolved_for(v_dace, to_jsonb(7));
        PERFORM pg_temp.resolved_for(v_dace, '{"id": 1}'::jsonb);
        IF pg_temp.day(v_dace_a) IS NOT NULL OR pg_temp.day(v_dace_b) IS NOT NULL THEN
            RAISE EXCEPTION 'a number is absent; Dace has two companies: nothing written';
        END IF;
        PERFORM pg_temp.resolved_for(v_edgars, to_jsonb(7));
        IF pg_temp.day(v_edgars_a) IS DISTINCT FROM v_today THEN
            RAISE EXCEPTION 'a number is absent; Edgars has one company: dated';
        END IF;

        -- Not issuing, a company named: nothing written.
        UPDATE rolebyte.user_account SET last_signed_in_on = NULL WHERE id IN (v_dace_a, v_edgars_a);
        v_rows := pg_temp.rows();
        PERFORM pg_temp.ok('resolve', jsonb_build_object('subjectKey', v_dace, 'issuing', false,
            'issuingTenant', v_ta), 'not issuing');
        PERFORM pg_temp.ok('resolve', jsonb_build_object('subjectKey', v_dace,
            'issuingTenant', v_ta), 'not issuing, no flag');
        IF pg_temp.rows() IS DISTINCT FROM v_rows THEN
            RAISE EXCEPTION 'an answer not issuing wrote a row';
        END IF;

        -- A date already today: the row is not written again.
        PERFORM pg_temp.resolved_for(v_dace, to_jsonb(v_ta));
        v_rows := pg_temp.rows();
        PERFORM pg_temp.resolved_for(v_dace, to_jsonb(v_ta));
        IF pg_temp.rows() IS DISTINCT FROM v_rows THEN
            RAISE EXCEPTION 'a membership already dated today was written again';
        END IF;

        -- Company not active, or account not active: nothing written.
        UPDATE rolebyte.user_account SET last_signed_in_on = NULL WHERE id IN (v_ilze_c, v_toms_a);
        v_rows := pg_temp.rows();
        PERFORM pg_temp.resolved_for(v_ilze, to_jsonb(v_tc));
        PERFORM pg_temp.resolved_for(v_toms, to_jsonb(v_ta));
        IF pg_temp.rows() IS DISTINCT FROM v_rows THEN
            RAISE EXCEPTION 'a suspended company or an ended account was dated';
        END IF;

        -- The answer is the same with and without a company named.
        IF pg_temp.checked(v_dace, '{}') IS DISTINCT FROM pg_temp.resolved_for(v_dace, to_jsonb(v_tb))
           OR pg_temp.checked(v_dace, '{}') IS DISTINCT FROM pg_temp.resolved(v_dace) THEN
            RAISE EXCEPTION 'the answer differs when a company is named';
        END IF;
    END;

    RAISE NOTICE 'unit.rolebyte_last_signed_in: all assertions passed';
END $$;

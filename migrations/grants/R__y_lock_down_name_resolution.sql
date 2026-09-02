-- R (repeatable): remove the two things that let a caller influence how names
-- resolve inside a privileged procedure body.
--
-- Applies in the `grants` location, which the migrate loop runs LAST, and the
-- `R__y_` prefix puts it after the grant file — so every schema and role this
-- reasons about already exists.
--
-- Database-name free: both statements act on whatever database the migration is
-- running against (current_database()), so the same file deploys under any name.

-- 1. Nothing may create temporary objects except the owner.
--
-- PostgreSQL grants TEMPORARY on a database to PUBLIC by default, so every role
-- -- including each EXECUTE-only service role -- could create temp tables. That
-- matters because the temporary schema is searched FIRST for relation names when
-- it is not named explicitly in a search_path: a role able to create a temp table
-- could shadow a real one inside any routine that did not pin its path, and the
-- body would then read or write the caller's object while running with the
-- owner's privileges. No service here needs temporary objects, so the capability
-- is removed rather than merely guarded against.
DO $$
BEGIN
    EXECUTE format('REVOKE TEMPORARY ON DATABASE %I FROM PUBLIC', current_database());
END
$$ LANGUAGE plpgsql;

-- 2. The database's own default search_path resolves nothing.
--
-- Every routine in this layer pins its own search_path, so none of them depends
-- on the session default. Setting the database default to pg_temp alone means a
-- routine that FORGETS to pin one cannot quietly inherit a usable path and appear
-- to work: it fails on first call, in test, instead of resolving through whatever
-- its caller happened to have set. The rule stops being something a reviewer has
-- to notice.
--
-- Safe for the migrations themselves: every object they create or reference is
-- schema-qualified, and each procedure declares the path its own body needs.
-- Operators, built-in functions and types keep resolving because pg_catalog is
-- searched implicitly ahead of the path unless it is named explicitly.
--
-- Consequence for humans: an interactive session must schema-qualify, or set a
-- search_path for itself. That is intended -- unqualified ad-hoc SQL against this
-- data layer is precisely what should not be casually possible.
DO $$
BEGIN
    EXECUTE format('ALTER DATABASE %I SET search_path = pg_temp', current_database());
END
$$ LANGUAGE plpgsql;

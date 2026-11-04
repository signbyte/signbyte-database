-- V5: `util.labels_refusal()` is STABLE, not IMMUTABLE.
--
-- Its refusal sentence lists the languages the app speaks with
-- array_to_string, which PostgreSQL declares STABLE, so the function may not
-- promise more than that. Nothing stores or indexes its answer (no constraint,
-- index or generated column calls it), so only the declaration changes; its
-- callers that declared themselves IMMUTABLE say STABLE in their own files.

ALTER FUNCTION util.labels_refusal(jsonb) STABLE;

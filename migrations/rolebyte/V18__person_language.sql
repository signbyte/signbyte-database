-- V18: a person's own language, kept for the person rather than for any of their
-- memberships.
--
-- A membership is one person in one tenant, so a choice the person makes about
-- their own screen — the language it speaks — cannot live on it: a person in two
-- tenants would hold two answers to one question. One row per person instead,
-- keyed by their platform subject (`sub:<person id>`, the `sub` of every token
-- issued for them), the same in every tenant they belong to. Only a person has
-- one: a service account's key, or a key of any kind this register does not
-- define, is refused, by the same rule the membership register keeps.
--
-- `language` NULL means the person reads the deployment's language. Which
-- languages may be chosen is the procedures' to keep, not a constraint's: which
-- languages the app speaks is decided in one place, and a constraint here would
-- have to repeat it.
--
-- The row is part of the person: whatever erases a person takes it with them.
CREATE TABLE IF NOT EXISTS rolebyte.person_setting (
    subject_key text        NOT NULL PRIMARY KEY,
    language    text        NULL,
    changed_at  timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT person_setting_subject_key_person
        CHECK (starts_with(subject_key, 'sub:') AND rolebyte.is_typed_subject_key(subject_key))
);

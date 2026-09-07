-- V1: `rolebyte` schema — the schema shell + service-role access.
--
-- The membership model (tenants, users, per-service role definitions, role
-- assignments, and the append-only change history) lands in later migrations,
-- one logical change per version. This baseline creates the schema and wires
-- the least-privilege access path: the service connects with the EXECUTE-only
-- `rolebyte_public` role (provisioned by the host database's bring-up, no
-- credentials in SQL) and can only invoke procedures explicitly granted to it.
--
-- This migration set ships INSIDE the rolebyte repository and is applied by
-- the host database's one-step migration runner as the `rolebyte` location.
-- It depends on the host's shared `util` schema (id generation + the result
-- envelope), which the runner applies first.

CREATE SCHEMA IF NOT EXISTS rolebyte;

REVOKE ALL ON SCHEMA rolebyte FROM PUBLIC;
GRANT USAGE ON SCHEMA rolebyte TO rolebyte_public;

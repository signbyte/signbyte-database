-- V5: a tenant may attach the directory it trusts as its own.
--
-- An organisation whose people sign in through their own directory — a work
-- account, no invitation typed for each person — names that directory here: the
-- issuer of the identity provider the tenant trusts. A person who signs in
-- through that issuer is admitted to the tenant as a member on their first login,
-- with no grants at all, until an administrator gives them a role. People from
-- any other issuer, and people the tenant did not invite, are admitted nowhere.
--
-- The issuer is stored exactly as attached and matched by plain equality, which is
-- how identity providers compare an issuer: one spelling, no normalisation. It is
-- an address, not a secret, so it travels with the tenant's configuration
-- document like the rest of the tenant's setup.
--
-- One directory belongs to at most one tenant. Two tenants attaching the same
-- issuer would make every login from it a question the register cannot answer
-- (which tenant admits this person?), so the second attachment is refused
-- rather than stored.
ALTER TABLE rolebyte.tenant ADD COLUMN IF NOT EXISTS directory_issuer text NULL;

CREATE UNIQUE INDEX IF NOT EXISTS tenant_directory_issuer_key
    ON rolebyte.tenant (directory_issuer)
    WHERE directory_issuer IS NOT NULL;

-- The ONE home of what an issuer may look like: an absolute http(s) URL with no
-- whitespace, no query and no fragment — the shape an identity provider's
-- discovery document states its issuer in. No other rule is applied here: a
-- trailing slash, letter case and the path are the provider's to decide, and the
-- register stores what it is given. Called from the constraint below and from the
-- attaching procedure, so a widening is one edit.
CREATE OR REPLACE FUNCTION rolebyte.is_directory_issuer(p_issuer text)
RETURNS boolean
LANGUAGE sql
IMMUTABLE
RETURNS NULL ON NULL INPUT
SET search_path = pg_temp
AS $$
    SELECT length(p_issuer) <= 512
       AND p_issuer ~ '^https?://[^[:space:]/?#]+(/[^[:space:]?#]*)?$';
$$;

-- Least privilege: called only inside the SECURITY DEFINER procedures, which run
-- as the owner, so the register's EXECUTE-only role needs no grant.
REVOKE ALL ON FUNCTION rolebyte.is_directory_issuer(text) FROM PUBLIC;

-- A present issuer must have that shape; an absent one is unconstrained (a CHECK
-- that evaluates to NULL passes). Guarded for replay.
DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_constraint
         WHERE conname = 'tenant_directory_issuer_shape'
           AND conrelid = 'rolebyte.tenant'::regclass
    ) THEN
        ALTER TABLE rolebyte.tenant
            ADD CONSTRAINT tenant_directory_issuer_shape
            CHECK (rolebyte.is_directory_issuer(directory_issuer));
    END IF;
END $$;

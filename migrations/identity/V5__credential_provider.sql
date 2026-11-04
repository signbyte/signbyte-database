-- V5: a credential is keyed by the provider it came from and its handle.
--
-- A sign-in's handle (`idp_sub`) is the identifier its provider gave the person.
-- OpenID Connect promises such an identifier is unique and never reassigned
-- within the provider that issued it, and promises nothing across providers:
-- only the provider together with the identifier names one person. Keyed by the
-- handle alone, two people at two providers who happen to share a handle would be
-- one person here, and a provider that lets its users choose their handle could
-- sign one of them in as the other.
--
-- So the credential gains `provider`, the identifier of the provider the
-- credential came from, and the key becomes the provider with the handle.
--
-- Every credential stored so far came through a deployment's one provider. They
-- keep the empty provider, which a deployment reads as its first one: no stored
-- row is rewritten, and a deployment with one provider goes on writing the empty
-- provider exactly as before.
--
-- The length bound is generous for any issuer identifier and keeps the column a
-- name, not a document.
--
-- Idempotent: the column, its check and the new key are added only where missing.
ALTER TABLE identity.credential ADD COLUMN IF NOT EXISTS provider text NOT NULL DEFAULT '';

DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_constraint
                    WHERE conrelid = 'identity.credential'::regclass AND conname = 'credential_provider_length') THEN
        ALTER TABLE identity.credential ADD CONSTRAINT credential_provider_length CHECK (char_length(provider) <= 1024);
    END IF;
END $$;

-- The key: from the handle alone to the provider with the handle. Replaced only
-- while it is still the one-column key, so a replay leaves it as it is.
DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM pg_constraint
                WHERE conrelid = 'identity.credential'::regclass AND contype = 'p'
                  AND conname = 'credential_pkey' AND cardinality(conkey) = 1) THEN
        ALTER TABLE identity.credential DROP CONSTRAINT credential_pkey;
        ALTER TABLE identity.credential ADD CONSTRAINT credential_pkey PRIMARY KEY (provider, idp_sub);
    END IF;
END $$;

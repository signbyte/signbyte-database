-- V4: a sign-in keeps the email its directory sent.
--
-- A person who signs in through their organisation's directory carries no national
-- code, so nothing about them told two people of one name apart. The directory
-- sends their email address at every sign-in; it is kept on the credential it came
-- with and renewed each time, so what an administrator is shown is what the
-- directory says now. It is shown, never matched on: a person is still never
-- resolved by an address.
--
-- A credential that came with no address (a card, a mobile identity, a directory
-- that sends none) holds the empty string. The length bound is the longest address
-- the mail standards allow; the procedures keep nothing that is not an address.
--
-- Idempotent: the column and its check are added only where missing.
ALTER TABLE identity.credential ADD COLUMN IF NOT EXISTS email text NOT NULL DEFAULT '';

DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_constraint
                    WHERE conrelid = 'identity.credential'::regclass AND conname = 'credential_email_length') THEN
        ALTER TABLE identity.credential ADD CONSTRAINT credential_email_length CHECK (char_length(email) <= 320);
    END IF;
END $$;

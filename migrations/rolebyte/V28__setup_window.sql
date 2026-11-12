-- V28: the setup window. For a short time one service account can be a member of one
-- company that nobody has signed in to yet, holding that company's configuration
-- permissions and nothing else, so the company can be given its first configuration.
--
-- `setup_until` marks an account's row as a setup account's row, for ever: such a row
-- is a member only while its window is open and never otherwise. A window is open
-- while the row is active, `setup_until` is in the future and nobody of the company has
-- ever signed in (see `rolebyte.setup_window_open`). Only a service
-- account (a key that starts with `svc:`) can carry the mark; a person's row and
-- every row that exists today stay null.
ALTER TABLE rolebyte.user_account ADD COLUMN IF NOT EXISTS setup_until timestamptz NULL;

COMMENT ON COLUMN rolebyte.user_account.setup_until IS
    'Set only on a service account''s row that a setup window made: the time the window ends. A row with a value here is a member only while its window is open (nobody of the company has ever signed in and this time is in the future), and never otherwise. Null on every other row.';

DO $$ BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_constraint
                    WHERE conname = 'user_account_setup_until_service'
                      AND conrelid = 'rolebyte.user_account'::regclass) THEN
        ALTER TABLE rolebyte.user_account
            ADD CONSTRAINT user_account_setup_until_service
            CHECK (setup_until IS NULL OR starts_with(subject_key, 'svc:'));
    END IF;
END $$;

-- V19: an administrator's note on a member.
--
-- Two people of one name are told apart by what names them where they sign in;
-- beside that, an administrator may keep a few words of their own about a member
-- of the tenant they administer ("the one at the Riga site"). The note belongs to
-- the membership — one tenant's administrators write it and read it, and another
-- tenant never sees it — so it is a column of the member row.
--
-- It is personal data written by a person, so it is kept short (1000 characters)
-- and lives only here: the history records that a note changed, never what it
-- says, because the history cannot be rewritten and a note's words in it could
-- never be erased.
--
-- Idempotent: the column and its check are added only where missing. Adding a
-- column with a constant default rewrites nothing.
ALTER TABLE rolebyte.user_account ADD COLUMN IF NOT EXISTS note text NOT NULL DEFAULT '';

DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_constraint
                    WHERE conrelid = 'rolebyte.user_account'::regclass AND conname = 'user_account_note_length') THEN
        ALTER TABLE rolebyte.user_account ADD CONSTRAINT user_account_note_length CHECK (char_length(note) <= 1000);
    END IF;
END $$;

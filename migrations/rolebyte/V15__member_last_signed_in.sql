-- V15: the day a member was last given access.
--
-- One date per member, written by the token-issue read when it answers the
-- member's access, and at most once a day: a later answer the same day finds the
-- date already there and writes nothing. The day only, never the time, because
-- what an administrator needs from it is who has stopped coming, and a day
-- answers that without keeping a record of anybody's sign-ins.
--
-- NULL until the first answer after this migration: nothing earlier recorded it,
-- so a member who has not signed in since reads as never, not as a guess.
ALTER TABLE rolebyte.user_account
    ADD COLUMN IF NOT EXISTS last_signed_in_on date NULL;

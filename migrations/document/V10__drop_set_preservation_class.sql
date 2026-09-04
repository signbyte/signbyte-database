-- The archive-timestamp fact is now recorded by document.replace_container_blob in the
-- same write as the swapped bytes (its optional preservation_class input), so the
-- separate set_preservation_class procedure has no caller left. It is dropped here, not
-- merely removed from the repeatable file: a repeatable migration re-creates only what
-- its file still defines, so removing the definition alone would leave the old
-- procedure standing in every already-migrated database.
DROP PROCEDURE IF EXISTS document.set_preservation_class(jsonb, jsonb);

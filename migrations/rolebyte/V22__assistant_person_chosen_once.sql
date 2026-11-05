-- V22: an assistant's person is chosen when it is added, and never changed after.
--
-- To give an assistant to someone else, it is removed and a new one is added for
-- them, so everything an assistant did means one person. The procedure that
-- gave an assistant to another person is dropped here, as the repeatable file no
-- longer makes it; the events it wrote stay in the register's history.
DROP PROCEDURE IF EXISTS rolebyte.assistant_person_set(jsonb, jsonb);

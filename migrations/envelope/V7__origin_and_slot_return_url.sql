-- V7: where an envelope came from, and where each signer goes back to.
--
-- An envelope is not always started by a person in the portal. A document system can
-- prepare one on behalf of its own user and hand the signer to the portal by link. The
-- portal then has to be able to say WHO asked for the signature and offer a way BACK once
-- the signer is done — without knowing anything about the system that asked beyond what
-- is recorded here.
--
--   origin_name        the requesting system's display name, shown to the signer
--                      ("Requested by …"). It is the name the system was REGISTERED
--                      under, written by the service that verified that registration —
--                      never free text taken from a request body, or the link becomes a
--                      way to impersonate a requester.
--   origin_return_url  the default address the signer's browser is offered after the
--                      ceremony. The writing service admits only registered destinations
--                      (https, no credentials in the URL, no fragment); this column stores
--                      what it admitted.
--   origin_ref         the requesting system's own reference for this envelope (an order
--                      or contract number), echoed back to it and shown nowhere else.
--
--   signer_slot.return_url  a per-signer override of the envelope's default return: two
--                      people signing one document may have come from two different
--                      screens. Same admission rule as the default. NULL means "use the
--                      envelope's".
--
-- All four are nullable with no default — a metadata-only add, no table rewrite. An
-- envelope started in the portal simply has none of them, and every reader must render
-- correctly with them absent: no requester line, no return action.
ALTER TABLE envelope.envelope    ADD COLUMN IF NOT EXISTS origin_name       text;
ALTER TABLE envelope.envelope    ADD COLUMN IF NOT EXISTS origin_return_url text;
ALTER TABLE envelope.envelope    ADD COLUMN IF NOT EXISTS origin_ref        text;
ALTER TABLE envelope.signer_slot ADD COLUMN IF NOT EXISTS return_url        text;

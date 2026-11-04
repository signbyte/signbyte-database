-- V6: the card's sign-ins are kept under a provider of their own, `webeid`.
--
-- A card sign-in's handle is the card holder's identity code. Until now the card
-- wrote the empty provider, which is also the deployment's first upstream
-- provider's. So a sign-in at that provider carrying no code, whose handle
-- happened to equal a card holder's code, was resolved to the card holder: a
-- provider that lets its users choose their own identifier could sign one of
-- them in as anybody holding a card. Kept under a provider of its own, the
-- card's handles share a namespace with no other provider's.
--
-- The provider is named for the engine that reads the card, not for "the card":
-- a card read some other way arrives through that way's provider.
--
-- A card credential is one the card's sign-in method (`webEid`) wrote, or one
-- whose handle is its own person's identity code: no upstream's handle is that,
-- so such a row under the empty provider is a card's whose method a sign-in
-- through that provider since overwrote, the very case this closes. It moves
-- too, keeping the method it now holds, which is the record of that sign-in.
-- Nothing else is moved.
--
-- A credential may already be stored under `webeid` when the service that writes
-- it ran before this migration: the same card signed in again then wrote a second
-- row for the same person. That older duplicate is removed, never merged; a
-- duplicate naming a different person is not this migration's to decide, and the
-- key then stops it.
--
-- Idempotent: a replay finds no card credential under the empty provider.
DELETE FROM identity.credential AS c
 WHERE c.provider = ''
   AND (c.login_method = 'webEid'
        OR c.idp_sub = (SELECT p.national_id FROM identity.person p WHERE p.person_sub = c.person_sub))
   AND EXISTS (SELECT 1 FROM identity.credential w
                WHERE w.provider = 'webeid' AND w.idp_sub = c.idp_sub AND w.person_sub = c.person_sub);

UPDATE identity.credential AS c
   SET provider = 'webeid'
 WHERE c.provider = ''
   AND (c.login_method = 'webEid'
        OR c.idp_sub = (SELECT p.national_id FROM identity.person p WHERE p.person_sub = c.person_sub));

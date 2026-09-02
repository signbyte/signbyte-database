# Security policy

This repository holds the database schemas and procedures of a platform for
**qualified electronic signatures**: the identity store, the signed-document
metadata, the signing and envelope state, and the append-only evidence trails.
A defect here is a defect in what every service of the platform trusts.

Please report security problems privately. Do not open a public issue or
discussion for anything that could be exploited before a fix exists.

## How to report

Use **[private vulnerability reporting](https://github.com/signbyte/signbyte-database/security/advisories/new)**
on this repository. The report stays visible only to you and the maintainers until
an advisory is published, and it gives us one place to co-ordinate a fix with you.

Please include, as far as you can establish it:

- what the problem is, and what an attacker gains from it;
- the smallest set of steps that reproduces it, and against which version or commit;
- the configuration it needs, if it only appears under particular settings;
- whether you have told anyone else, and whether a disclosure date already binds you.

## What happens next

- We acknowledge a report within **five working days**.
- We tell you whether we can reproduce it, and what we think its severity is, as soon as we know.
- We keep you updated while a fix is prepared, and we agree a disclosure date with you. Our default
  is to publish an advisory once a fix is available, and in any case within **90 days** of the
  report — earlier if the problem is already public or being exploited.
- We credit you in the advisory unless you would rather stay anonymous.

There is no bug-bounty programme. We are grateful anyway, and we say so publicly.

## What we consider most serious

- a service role reaching data outside the procedures granted to it (a table, another schema);
- a procedure that lets a caller read or alter another tenant's or another person's rows;
- any path that updates or deletes a row in an append-only evidence table, or breaks its hash
  chain or seal without detection;
- a `SECURITY DEFINER` routine with an unpinned `search_path` or another privilege-escalation path;
- a migration that silently changes an already-applied version.

Denial of service and findings that need an already-compromised database owner are in scope but
lower priority.

## Scope

This policy covers the SQL and scripts in this repository. Deployments operated by someone other
than us are their operator's responsibility — ask them.

## Releases

Security fixes land at the source this repository is generated from and reach the default branch
here on the next publish; once version tags exist this section will name the versions that
receive them.

# Append-only declarations

One file per schema location, `<location>.list`, one `schema.table` per line
(`#` comments allowed). A table listed here must carry a trigger that fires on
UPDATE and DELETE — the guard between a break-glass session and silently
rewritten evidence. `testing/verify.sh` hands the concatenation of every file
present to `testing/assert-hardening.sql`, which skips tables the deployment did
not migrate, so the same assertion runs for every shape. Adding an append-only
table means adding it to its location's file, deliberately.

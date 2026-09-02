#!/bin/env sh
# Fail the build on any error-level plpgsql_check finding in /tmp/output.txt.
#
# It must also fail when there is nothing to check. Grepping a file that does
# not exist, or an empty one, finds no errors — so the naive form reported
# success both when the analysis was clean and when it never ran, which are the
# two states a static-analysis gate exists to tell apart. A caller that wrote
# its output somewhere else, or whose query died, would have been told it
# passed.
#
# The caller (testing/sql-tests.sh) already proves the analysis ran, by running
# psql under ON_ERROR_STOP and asserting the database holds PL/pgSQL routines at
# all. These checks are the same guarantee at this end of the pipe, for anyone
# who runs this script by hand.
OUT=/tmp/output.txt

if [ ! -f "$OUT" ]; then
  echo "FAILED!!! $OUT does not exist — the analysis did not run, or wrote elsewhere" >&2
  exit 1
fi
if [ ! -s "$OUT" ]; then
  echo "FAILED!!! $OUT is empty — the analysis produced no output at all" >&2
  exit 1
fi

if [ "$(grep level "$OUT" | grep -c 'error')" -ge 1 ]
then echo "FAILED!!!"
     cat "$OUT"
     exit 1
else
   cat "$OUT"
   exit 0
fi

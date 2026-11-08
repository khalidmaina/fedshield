#!/bin/bash
# SIMULATED internal discovery (lab only): TCP connect checks against other lab hosts on
# common service ports.
# Usage: scan.sh <seconds>
set -u
END=$(( SECONDS + ${1:-300} ))
TICK="/tmp/.s-tick.$$"; mkfifo "$TICK" && exec 7<>"$TICK"
TARGETS="fs-web-1 fs-web-2 fs-db-1 fs-db-2 fs-build-1 fs-dev-1"
PORTS="21 22 23 25 80 110 139 443 445 3306 3389 5432 6379 8080 9200"

while (( SECONDS < END )); do
  for t in $TARGETS; do
    [ "$t" = "$HOSTNAME" ] && continue
    for p in $PORTS; do
      nc -z -w 1 "$t" "$p" > /dev/null 2>&1
    done
    (( SECONDS < END )) || break
  done
  read -r -t 2 -u 7 _ || true
done
rm -f "$TICK"

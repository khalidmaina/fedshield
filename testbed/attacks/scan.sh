#!/bin/bash
# SIMULATED internal discovery (lab only): TCP connect checks against other lab
# containers on common service ports.
# Usage: scan.sh <seconds>
DUR=${1:-300}; END=$((SECONDS + DUR))
TARGETS="fs-web-1 fs-web-2 fs-db-1 fs-db-2 fs-build-1 fs-dev-1"
PORTS="21 22 23 25 80 110 139 443 445 3306 3389 5432 6379 8080 9200"
while [ $SECONDS -lt $END ]; do
  for t in $TARGETS; do
    for p in $PORTS; do
      nc -z -w 1 "$t" "$p" > /dev/null 2>&1
    done
    [ $SECONDS -ge $END ] && break
  done
  sleep 2
done

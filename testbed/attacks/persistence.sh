#!/bin/bash
# SIMULATED persistence (lab only): writes a cron entry, a hidden script and a
# .bashrc line inside this container, then removes them at the end.
# Usage: persistence.sh <seconds>
DUR=${1:-300}; END=$((SECONDS + DUR))
while [ $SECONDS -lt $END ]; do
  printf '#!/bin/sh\necho updater\n' > /tmp/.updater.sh
  chmod +x /tmp/.updater.sh
  echo "*/5 * * * * root /tmp/.updater.sh" > /etc/cron.d/updater
  grep -q ".updater.sh" /root/.bashrc 2>/dev/null || echo "/tmp/.updater.sh >/dev/null 2>&1" >> /root/.bashrc
  /tmp/.updater.sh > /dev/null
  sleep $((RANDOM % 5 + 3))
done
rm -f /tmp/.updater.sh /etc/cron.d/updater
sed -i '/.updater.sh/d' /root/.bashrc 2>/dev/null

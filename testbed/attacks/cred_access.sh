#!/bin/bash
# SIMULATED credential access (lab only): reads account files and looks for SSH keys inside
# this container. A fake key is planted first; nothing leaves the container.
# Usage: cred_access.sh <seconds>
set -u
END=$(( SECONDS + ${1:-300} ))
TICK="/tmp/.c-tick.$$"; mkfifo "$TICK" && exec 7<>"$TICK"
mkdir -p /root/.ssh
[ -f /root/.ssh/id_rsa ] || echo "FAKE-KEY-FOR-LAB" > /root/.ssh/id_rsa

while (( SECONDS < END )); do
  cat /etc/shadow /etc/gshadow > /dev/null 2>&1
  cat /etc/passwd > /dev/null
  ls -la /root/.ssh > /dev/null 2>&1
  cat /root/.ssh/id_rsa > /dev/null 2>&1
  find / -xdev -maxdepth 4 -name "id_rsa*" 2>/dev/null | head -5 > /dev/null
  read -r -t $(( RANDOM % 4 + 2 )) -u 7 _ || true
done
rm -f "$TICK"

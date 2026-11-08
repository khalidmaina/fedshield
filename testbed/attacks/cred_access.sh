#!/bin/bash
# SIMULATED credential access (lab only): reads account files and looks for SSH keys
# inside this container. Nothing leaves the container.
# Usage: cred_access.sh <seconds>
DUR=${1:-300}; END=$((SECONDS + DUR))
mkdir -p /root/.ssh && [ -f /root/.ssh/id_rsa ] || echo "FAKE-KEY-FOR-LAB" > /root/.ssh/id_rsa
while [ $SECONDS -lt $END ]; do
  cat /etc/shadow > /dev/null 2>&1
  cat /etc/passwd > /dev/null
  cat /etc/gshadow > /dev/null 2>&1
  ls -la /root/.ssh > /dev/null 2>&1
  cat /root/.ssh/id_rsa > /dev/null 2>&1
  find / -maxdepth 4 -name "id_rsa*" 2>/dev/null | head -5 > /dev/null
  sleep $((RANDOM % 4 + 2))
done

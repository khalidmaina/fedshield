#!/bin/bash
# Starts the benign workload that matches this host's ROLE.
# ROLE: web | db | build | dev     INTENSITY: 1 (light) .. 3 (heavy)
set -u
: "${ROLE:?ROLE must be set}"
: "${INTENSITY:=1}"
export INTENSITY
echo "Host $(hostname) starting role=$ROLE intensity=$INTENSITY"
exec /roles/"$ROLE".sh

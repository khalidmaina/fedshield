#!/bin/bash
# FedShield host agent: the main process of every simulated host.
#
# 1. Starts this host's benign workload (roles/$ROLE.sh) in the background.
# 2. Watches $CONTROL_DIR/$HOSTNAME/request for an attack request ("<id> <attack> <seconds>").
#    When one arrives it starts /attacks/<attack>.sh as its OWN child process and appends
#    "started" and "finished" lines (JSON) to status.jsonl, with wall-clock times taken
#    inside the host and the attack's exit code.
#
# Why an agent instead of `docker exec`: an exec'd process is started by runc from outside
# the container, a trace no real intrusion leaves. Here the attack runs in the host's own
# process tree, and its start and end are measured where it runs.
#
# Why bash builtins only in the loop: the collector records every exec and file open inside
# the host. Waiting with `read -t` on a FIFO and testing files with `[ -f ]` (a stat, which is
# not traced) means the agent's polling adds no events to the telemetry. No Docker
# HEALTHCHECK is used for the same reason: it would run commands inside the host.
#
# Paths can be overridden for tests: ROLE_DIR, ATTACK_DIR, CONTROL_DIR.
set -u
# Fixed locale for the agent, the workload and every attack. Under e.g. ru_RU, bash prints
# $EPOCHREALTIME with a decimal comma (1794496121,986074), which breaks the JSON status lines.
export LC_ALL=C
: "${ROLE:?ROLE must be set (web, db, build or dev)}"
: "${INTENSITY:=1}"
: "${ROLE_DIR:=/fs/roles}"
: "${ATTACK_DIR:=/attacks}"
: "${CONTROL_DIR:=/control}"
export ROLE INTENSITY ROLE_DIR

ATTACKS=" beacon cred_access miner persistence scan "
CTL="$CONTROL_DIR/$HOSTNAME"
mkdir -p "$CTL"

TICK="/tmp/.fs-agent-tick.$$"
mkfifo "$TICK" && exec 3<>"$TICK"
pause() { read -r -t "$1" -u 3 _ || true; }
# /dev/null opened ONCE as fd 4: a `2>/dev/null` inside the loop would open the file on every
# pass (measured: 2 opens per second per host before this fix).
exec 4>/dev/null

status() { printf '%s\n' "$1" >> "$CTL/status.jsonl"; }

stop() {
  trap - TERM INT
  kill 0 2>/dev/null        # our process group: workload, its children, any running attack
  exit 0
}
trap stop TERM INT

printf 'agent: host=%s role=%s intensity=%s\n' "$HOSTNAME" "$ROLE" "$INTENSITY"
"$ROLE_DIR/$ROLE.sh" &
WORKLOAD=$!

ATTACK_PID="" ATTACK_ID="" ATTACK_NAME="" LAST_ID=""

handle_request() {
  local id="" attack="" secs=""
  read -r id attack secs < "$CTL/request" || [ -n "$id" ] || return
  [[ "$id" =~ ^[A-Za-z0-9_-]{1,64}$ ]] || return     # ignore malformed requests
  [ "$id" != "$LAST_ID" ] || return                  # already handled
  LAST_ID="$id"
  if [ -n "$ATTACK_PID" ]; then
    status "{\"id\":\"$id\",\"event\":\"rejected\",\"reason\":\"busy\",\"ts\":$EPOCHREALTIME}"
    return
  fi
  if [[ "$ATTACKS" != *" $attack "* ]] || [ ! -f "$ATTACK_DIR/$attack.sh" ]; then
    status "{\"id\":\"$id\",\"event\":\"rejected\",\"reason\":\"unknown attack\",\"ts\":$EPOCHREALTIME}"
    return
  fi
  if ! [[ "$secs" =~ ^[0-9]+$ ]] || [ "$secs" -lt 1 ] || [ "$secs" -gt 3600 ]; then
    status "{\"id\":\"$id\",\"event\":\"rejected\",\"reason\":\"seconds must be 1-3600\",\"ts\":$EPOCHREALTIME}"
    return
  fi
  local t0=$EPOCHREALTIME
  /bin/bash "$ATTACK_DIR/$attack.sh" "$secs" &
  ATTACK_PID=$! ATTACK_ID="$id" ATTACK_NAME="$attack"
  status "{\"id\":\"$id\",\"event\":\"started\",\"attack\":\"$attack\",\"seconds\":$secs,\"ts\":$t0,\"pid\":$ATTACK_PID}"
}

check_attack() {
  [ -n "$ATTACK_PID" ] || return
  kill -0 "$ATTACK_PID" 2>&4 && return             # still running
  local t1=$EPOCHREALTIME rc
  wait "$ATTACK_PID"; rc=$?
  status "{\"id\":\"$ATTACK_ID\",\"event\":\"finished\",\"attack\":\"$ATTACK_NAME\",\"exit_code\":$rc,\"ts\":$t1}"
  ATTACK_PID="" ATTACK_ID="" ATTACK_NAME=""
}

while true; do
  if ! kill -0 "$WORKLOAD" 2>&4; then
    echo "agent: workload $ROLE exited; stopping so Docker restarts the host" >&2
    exit 1
  fi
  [ -f "$CTL/request" ] && handle_request
  check_attack
  pause 0.5
done

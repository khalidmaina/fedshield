#!/bin/bash
# Helpers shared by the role workloads. Sourced, not run.
#
# Waiting happens with bash builtins (`read -t` on a FIFO), not `sleep` or `awk`, so the
# workload's own pacing does not add exec events to the telemetry: what the collector sees
# is the work itself (web requests, database writes, compiles, file browsing).

ROLE_TICK="/tmp/.fs-role-tick.$$"
mkfifo "$ROLE_TICK" && exec 9<>"$ROLE_TICK"

# pause_ms BASE SPAN: wait BASE milliseconds plus a random 0..SPAN-1 more.
pause_ms() {
  local ms=$(( $1 + RANDOM % $2 ))
  local t
  printf -v t '%d.%03d' $(( ms / 1000 )) $(( ms % 1000 ))
  read -r -t "$t" -u 9 _ || true
}

# one_in N: succeeds with probability 1/N.
one_in() { (( RANDOM % $1 == 0 )); }

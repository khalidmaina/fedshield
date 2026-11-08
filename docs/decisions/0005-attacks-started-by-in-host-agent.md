# 0005. Attacks are started by an in-host agent; the harness leaves no trace in the telemetry

- Status: accepted
- Date: 2026-11-08
- Deciders: Hasib, Khalid

## Context

The Sprint 1 plan left open how simulated attacks are started (a spike). The reference testbed used
`docker exec -d <host> bash /attacks/<attack>.sh`, recorded the label times on the machine outside the host, and
did not record whether the attack actually ran. The collector records every program start (exec), file open and
TCP connection inside the hosts, so anything the harness itself does inside a host becomes part of the data.

## Options

1. `docker exec` from outside (reference).
2. A small agent as each host's main process that starts attacks on request.
3. Docker `HEALTHCHECK`s to watch host health (only relevant to how health is checked).

## Decision

Option 2. `testbed/host/agent.sh` runs the role workload and watches `/control/<host>/request`. It starts the
requested attack as its own child and appends `started` / `finished` lines with times measured inside the host and
the exit code to `status.jsonl`. The host side (`fedshield/control.py`, `scripts/testbed.py`) writes requests and
reads reports through `testbed/control/`.

No Docker `HEALTHCHECK`: it runs a command inside the host every interval. Health is checked from outside with
`docker inspect` and `docker top` (`make testbed-status`).

The agent and the role workloads wait with bash builtins (`read -t` on a FIFO) instead of `sleep`/`awk`, test files
with `[ -f ]` (a stat, not traced), and open `/dev/null` once instead of on every `2>/dev/null`.

## Evidence (measured with bpftrace on 2026-11-08)

- With `2>/dev/null` in the agent loop: **481 opens in 20 s** across 12 idle agents (about 2 per second per host).
  After opening `/dev/null` once: **0 opens and 0 execs in 20 s** (`tests/integration/agent_quiet.bt`).
- With `docker exec`, the attack's parent would be `runc`; with the agent it is `/fs/agent.sh` inside the host.
- All five attacks produce their signal with a zero baseline on the same hosts
  (`tests/integration/attack_signals.bt`, 20 s windows):

| Attack (host) | Signal during the attack | Without attack |
|---|---|---|
| beacon (web-1) | 14 connections to an uncommon port | 0 |
| cred_access (db-2) | 10 opens of `/etc/shadow` / SSH key | 0 |
| miner (build-3) | 5 execs from `/tmp`, 5 connections to the pool port | 0 |
| persistence (dev-1) | 4 writes to `/etc/cron.d`, 4 execs from `/tmp` | 0 |
| scan (web-3) | 912 connections, 692 to uncommon ports | 102 connections, 0 uncommon |

## Consequences

- Labels can use the start and end times the host reports, and a failed attack is visible (exit code).
- `testbed/control/` must exist and belong to the user before the containers start (`make testbed-up` does it);
  if Docker creates it, it belongs to root and requests cannot be written.
- The agent is not the compromised service itself; a real intrusion would usually descend from one (e.g. the web
  server). State this in the thesis as a limitation.
- Beacon on a web host hides inside the normal `curl` traffic except for the port. That is realistic and relevant to
  RQ5: it is exactly the kind of behaviour a poisoned model might learn as normal.

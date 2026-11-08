# Integration checks (run by hand on Ubuntu 24.04)

CI cannot run eBPF or the live testbed, so any pull request that touches `testbed/`, `collector/` or
`fedshield/features.py` runs the matching check below on a real machine and writes the result in the PR.
T1, T3 and T5 are the testbed's acceptance checks (Sprint 1); T2 and T4 belong to the collector (Sprints 2-3).

The bpftrace checks need tracefs, which Ubuntu mounts by default. If bpftrace says a `syscalls` tracepoint is not
found, run `sudo mount -t tracefs nodev /sys/kernel/tracing` once.

## T1 — Testbed comes up healthy

```bash
make testbed-up && sleep 30 && make testbed-status
```

Pass: `13/13 containers healthy` (every host running, never restarted, agent and workload alive; c2-server
running). `docker logs fs-web-1 | head -1` shows `agent: host=fs-web-1 role=web intensity=1`.

## T2 — Collector sees every host and only the hosts (Sprint 2)

To be written with the collector. Pass: exactly the 12 `fs-*` hosts (no `c2-server`, nothing from the machine
itself), about 6 windows per host per minute, lost events 0 or a stated small number.

## T3 — Each attack runs and shows up in the kernel signals

Terminal 1 (counts signals per host for 20 s):

```bash
sudo bpftrace tests/integration/attack_signals.bt
```

Terminal 2, right after starting terminal 1 (each attack on a different host, 25 s):

```bash
python scripts/testbed.py attack fs-web-1 beacon --seconds 25
python scripts/testbed.py attack fs-db-2 cred_access --seconds 25
python scripts/testbed.py attack fs-build-3 miner --seconds 25
python scripts/testbed.py attack fs-dev-1 persistence --seconds 25
python scripts/testbed.py attack fs-web-3 scan --seconds 25
```

Then `python scripts/testbed.py log <host>` shows `started` and `finished` with `exit_code` 0 for each.

| Attack | Pass when (compared with a 20 s run of the same script without attacks) |
|---|---|
| `beacon` | `@conn_uncommon_port` > 0 on that host (port 9000) |
| `cred_access` | `@open_sensitive` > 0 |
| `miner` | `@exec_from_tmp` > 0 and `@conn_uncommon_port` > 0 (port 3333) |
| `persistence` | `@cron_write` > 0 and `@exec_from_tmp` > 0 |
| `scan` | `@conn` and `@conn_uncommon_port` rise sharply |

Reference result (2026-11-08) is in `docs/decisions/0005-attacks-started-by-in-host-agent.md`.

## T4 — Two-hour stability (Sprint 3, before collection starts)

Run a full pilot session. Pass: `make testbed-status` still shows 13/13 healthy with no restarts, every host has a
continuous series of windows, and lost events stay small throughout.

## T5 — The harness adds nothing to the telemetry

With the testbed up and no attack running:

```bash
sudo bpftrace tests/integration/agent_quiet.bt
```

Pass: `@exec: 0` and `@open: 0` after 20 seconds.

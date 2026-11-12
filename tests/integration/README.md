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

With the testbed up:

```bash
make collect DURATION=120                        # sudo python3 collector/collector.py --duration 120
python scripts/features_report.py                # newest data/features/features_*.jsonl
tail -3 data/features/collector_stats.jsonl
```

Pass: `hosts: 12 of 12` with no missing or unexpected hosts, `no gaps`, about 11 windows per host for 120 s (the
first and last partial windows are skipped), `lost events: 0` (or a stated small number), and in the stats lines
`late` 0 and `malformed` 0. The four attack-only features (`exec_from_tmp`, `open_sensitive`, `cron_write`,
`conn_uncommon_port`) are listed as never non-zero when no attack ran.

To see attacks in the features (T3 through the collector), run the T3 attack commands below while collecting
for 90 s, then compare `python scripts/features_report.py --from <attack start> --to <attack end>` with a quiet
range. Reference result: `docs/decisions/0006-collector-design.md`.

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

## T4 — Pilot session (before the campaign)

A full 2-hour run of session 1's schedule, exactly as in `docs/data_protocol.md`, on the collection machine:

```bash
make testbed-up && make testbed-status             # 13/13 healthy
make collect DURATION=7500                         # terminal 1
make session N=1                                   # terminal 2, ~30 s later
# after both have finished:
make features-report && make dataset && make dataset-report
```

Pass: the session summary says `24/24 attacks ran cleanly`; `make testbed-status` still shows 13/13 healthy with no
restarts; the features report shows 12/12 hosts, no gaps, lost events 0 (or a stated small number); `make dataset`
reports no hosts with fewer windows than expected and few ambiguous windows (about 2 per attack: its edges);
`make dataset-report` shows the session's attack windows (about 48 per attack on each host). Then delete the pilot
data (`rm -r data/features data/labels data/processed`) so session 1 is collected again for real.

## T5 — The harness adds nothing to the telemetry

With the testbed up and no attack running:

```bash
sudo bpftrace tests/integration/agent_quiet.bt
```

Pass: `@exec: 0` and `@open: 0` after 20 seconds.

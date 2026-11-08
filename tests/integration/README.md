# Integration checks (run by hand on Ubuntu 24.04)

CI cannot run eBPF or the live testbed, so any pull request that touches `testbed/`, `collector/` or
`fedshield/features.py` runs the matching check below on a real machine and writes the result in the PR.
These checks are the acceptance criteria for the testbed (T1, T3, T4, Sprint 1) and the collector (T2, Sprint 2);
they become scripts as those modules are rebuilt. Commands use the reference file names and may change with our
versions.

## T1 — Testbed comes up

```bash
make testbed-up && sleep 60 && make testbed-status
```

Pass: 13 containers (`fs-web-1..3`, `fs-db-1..3`, `fs-build-1..3`, `fs-dev-1..3`, `c2-server`), all `Up`,
none `Restarting`. `docker logs fs-web-1 | head -1` shows `role=web`.

## T2 — Collector sees every host and only the hosts

```bash
sudo python3 collector/collector.py --duration 120 --out /tmp/fs-check
python3 -c "import json; r=[json.loads(l) for l in open(sorted(__import__('glob').glob('/tmp/fs-check/features_*.jsonl'))[-1])]; print(sorted({x['host'] for x in r})); print(len(r), 'windows')"
tail -1 /tmp/fs-check/collector_stats.jsonl
```

Pass: exactly the 12 `fs-*` hosts (no `c2-server`, nothing from the machine itself); about 12 windows per host;
`lost` is 0 or a stated small number.

## T3 — Each attack shows up in its features

With the collector running (T2 command, longer duration), start one attack for 60 s on one host:

```bash
docker exec -d fs-dev-2 bash /attacks/<attack>.sh 60
```

| Attack | Pass when, compared with the same host's quiet windows |
|---|---|
| `beacon` | `net_tool_exec`, `conn_count` and `conn_uncommon_port` rise (port 9000) |
| `cred_access` | `open_sensitive` > 0 |
| `miner` | `exec_from_tmp` > 0 and `conn_uncommon_port` rises (port 3333) |
| `persistence` | `cron_write` > 0 and `exec_from_tmp` > 0 |
| `scan` | `conn_count`, `conn_unique_dport` and `net_tool_exec` rise sharply |

## T4 — Two-hour stability (before collection starts)

Run a full pilot session (Sprint 3). Pass: no container restarts (`docker ps` shows the same uptime for all),
every host has a continuous series of windows, and `lost` stays small throughout `collector_stats.jsonl`.

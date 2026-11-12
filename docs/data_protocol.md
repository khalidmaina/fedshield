# Data collection protocol

How the 8 sessions are collected, checked, backed up and frozen (design: decision 0003). The hash is filled in at
the data freeze.

## Before the campaign

- [ ] Collector freeze tagged (`v0.2-collector`); integration checks T1, T2, T3, T5 passed on the collection machine
- [ ] Collection machine chosen: ______ (`uname -r`: ______). Every session is collected on it (decision 0008)
- [ ] `bpftrace --version` shows v0.20.2 (decision 0007)
- [ ] Pilot session passed (T4, `tests/integration/README.md`); its data deleted afterwards
- [ ] `data/features/` and `data/labels/` empty (test runs removed)

## Each session (about 2 h 10 min; same machine, nothing else heavy running)

1. `git switch main && git pull`; `git status` must be clean.
2. `make testbed-up`, wait 2 minutes, `make testbed-status` shows 13/13 healthy.
3. Terminal 1: `make collect DURATION=7500` (125 min: covers the session plus start-up).
4. About 30 s later, terminal 2: `make session N=<session number>`. It refuses to start if the testbed is not healthy,
   the collector is not writing, or the session was already recorded. Answer `y`.
5. Leave both running. The session ends after 120 minutes and prints a summary: all 24 attacks must have run
   cleanly. If not, note it below; failed attacks are excluded from the dataset, not mislabelled.
6. When the collector has stopped: `make features-report` (12/12 hosts, no gaps, lost events 0 or noted).
7. Back up `data/features/` and `data/labels/` to two places (external drive + cloud) and add a row below.

Sessions run in order 1 to 8. Session 8 is the holdout: it is never used to train or tune anything.

## Session log

| Session | Split | Date | Commit | Attacks ok / 24 | Lost events | Backed up (2 places) | Notes |
|---|---|---|---|---|---|---|---|
| 1 | train | | | | | | |
| 2 | train | | | | | | |
| 3 | train | | | | | | |
| 4 | train | | | | | | |
| 5 | val | | | | | | |
| 6 | test | | | | | | |
| 7 | test | | | | | | |
| 8 | holdout | | | | | | |

## Data freeze (after session 8)

```bash
make dataset            # data/processed/host_windows.csv + manifest.json
make dataset-report     # RQ5 line must read 12/12 and 11+ evaluable in both regions
```

- File: `data/processed/host_windows.csv`
- SHA-256 (from `manifest.json`): `________________`
- Sessions included: 1-8 (holdout: 8)
- Tag: `v0.3-dataset`

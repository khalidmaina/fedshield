# Data collection protocol

How sessions are collected, checked, backed up and frozen. Completed in Sprint 3; the hash is filled at the data
freeze (end of Sprint 4).

## Before the campaign (Sprint 3)

- [ ] Collector freeze tagged (`v0.2-collector`); integration checks T1-T4 passed
- [ ] Rotation decided (`docs/decisions/0003-attack-rotation.md`); number of sessions fixed
- [ ] One session held out for the SIEM replay (never used for training)
- [ ] Collection machine chosen: ______ (`uname -r`: ______). Every session is collected on it (decision 0008):
      counts depend on CPU speed and network setup

## Each session

1. `git pull` on `main`; note the commit: `git rev-parse --short HEAD`
2. Start the testbed, wait 2 minutes, check `make testbed-status`
3. Terminal 1: `make collect DURATION=7200` (its first line in `collector_stats.jsonl` records bpftrace, kernel,
   OS and Python; bpftrace must be v0.20.2, see decision 0007)
4. Wait 15 s, terminal 2: `python scripts/run_schedule.py --schedule testbed/schedules/session_NN.yaml`
5. After it ends: `python scripts/build_dataset.py && python scripts/dataset_report.py`
6. Back up `data/` to two places (external drive + cloud) and add a row below

## Session log

| Session | Date | Commit | Duration | Windows per host | Lost events | Backed up (2 places) | Notes |
|---|---|---|---|---|---|---|---|
| | | | | | | | |

## Data freeze (end of Sprint 4)

- File: `data/processed/host_windows.csv`
- SHA-256: `________________` (`sha256sum data/processed/host_windows.csv`)
- Sessions included: ...
- Held-out session for SIEM replay: ...

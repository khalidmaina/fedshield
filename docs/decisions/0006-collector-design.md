# 0006. Collector: stream events to userspace, write counts only, measure loss and overhead per window

- Status: accepted
- Date: 2026-11-12
- Deciders: Hasib, Khalid

## Context

The collector turns kernel activity inside the 12 testbed hosts into 19 counts per host per 10-second window
(proposal Section 4.1). Two designs were possible:

1. **Stream** one line per event from bpftrace to a Python process, which builds the windows (reference design).
2. **Aggregate in the kernel**: count in eBPF maps and print only the counts every 10 s.

Option 2 sends less data to userspace, but puts every feature definition into bpftrace's limited language (path
matching, unique counts per window, map size limits) and is hard to unit-test. Option 1 is only safe if the event
rate stays well within what bpftrace and Python can carry.

The review of the reference collector also found four defects: it counted every thread exit as a process exit, it
looked for bpftrace's "Lost N events" message on stderr (bpftrace prints it on stdout, so loss was always reported
as 0), it emitted the incomplete first window, and it measured only userspace CPU (the eBPF programs' own cost is
charged to the traced processes).

## Decision

Stream events (option 1), with these rules:

- **Kernel filter:** only processes whose UTS hostname starts with `fs-` produce lines. The machine itself and the
  c2-server are never seen.
- **Minimal lines:** only the fields the features need (`E|ns|host|comm|path`, `O|…|flags|comm|path`,
  `C|…|dport|comm|daddr`, `X|…|comm`); the free-text field is last, so a `|` in a path cannot shift fields.
- **Counts only on disk:** paths, addresses and command names live in memory for one window; rows hold the 19 counts,
  `host`, `window_start`, `window_sec` and `lost_events`. A unit test fails if any raw value reaches a file.
- **Process exits only** (`pid == tid` on `sched_process_exit`).
- **Complete windows only,** aligned to the clock (…:00, …:10). The window running at start and at stop is skipped.
  A window is written 2 s after it ends; events arriving after that are dropped and counted as `late`.
- **Loss per window:** "Lost N events" lines (stdout) are charged to the window in which they arrive and appear as
  `lost_events` in that window's rows and in `collector_stats.jsonl`.
- **Overhead per window** in `collector_stats.jsonl`: CPU of the collector and of bpftrace (`/proc/<pid>/stat`), and
  time the kernel spent in our eBPF programs (`run_time_ns` from `/proc/<bpftrace>/fdinfo`, with
  `kernel.bpf_stats_enabled` switched on for the run and restored afterwards).

## Evidence (testbed on Ubuntu 24.04.5, bpftrace 0.20.2, 2 vCPU, 2026-11-12)

| Measurement | Result |
|---|---|
| Event volume, 12 idle hosts | ~1,600 events/s: 94% opens, 5% execs, 1% connections |
| Exits per 20 s: all threads vs processes | 1,556 vs 1,214 (threads inflated `exit_count` by 28%) |
| 45 s run, idle | 12/12 hosts, no gaps, 0 lost, 0 late, 0 malformed |
| 95 s run, 5 attacks for 30 s | ~2,100 events/s, 0 lost, 0 late |
| Overhead in that run (per core) | collector 3.4%, bpftrace 3.0%, in-kernel eBPF 2.4% (6.4 µs per event) |

Attack windows vs quiet windows of the same host (medians, 95 s run):

| Host, attack | Feature | Quiet | Attack |
|---|---|---|---|
| web-1, beacon | `conn_uncommon_port` | 0 | 7 |
| db-2, cred_access | `open_sensitive` | 0 | 7.5 |
| build-3, miner | `exec_from_tmp` | 0 | 2.5 |
| dev-1, persistence | `cron_write` | 0 | 1.5 |
| web-3, scan | `conn_uncommon_port` | 0 | 234.5 |

## Consequences

- At ~2,000 events/s with 0 loss, streaming is safe on this testbed; in-kernel aggregation is the route if the event
  rate grows by orders of magnitude, and is worth naming as future work.
- The overhead figures are for one collector serving 12 containers on one kernel. Per-host overhead for RQ7 still
  needs the single-host measurement planned for Sprint 12.
- Opens are taken from `openat` only (what glibc uses); `open`, `openat2` and UDP traffic are not observed. State it.
- Collector freeze (end of Sprint 2): after merging, `collector/`, `fedshield/features.py`, `testbed/host/` and
  `testbed/attacks/` change only through a new decision note, because changes invalidate collected sessions.

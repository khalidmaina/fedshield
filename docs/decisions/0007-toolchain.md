# 0007. Toolchain: bpftrace 0.20.2 (official static build) on Ubuntu 22.04 or 24.04 with kernel 6.8

- Status: accepted (refines the OS choice in 0001)
- Date: 2026-11-12
- Deciders: Hasib, Khalid

## Context

Decision 0001 chose Ubuntu 24.04. The first collection run on Khalid's machine showed it runs **Ubuntu 22.04.5 with
the HWE kernel 6.8** (the same kernel series as 24.04), system Python 3.10, and Python 3.12 installed separately for
the venv. On 22.04, `apt install bpftrace` gives **0.14.0**; the collector was built and verified with **0.20.2**
(Sprint 2). Versions differ in details that change the data (0.14 ignores `BPFTRACE_MAX_STRLEN`, so paths are cut at
64 characters instead of 128). After the collector freeze, all sessions must come from one verified toolchain.

## Options

1. Upgrade the machine to Ubuntu 24.04.
2. Use 22.04's bpftrace 0.14 and re-verify the collector against it.
3. Keep 22.04 and install bpftrace's official, statically linked 0.20.2 release binary.

## Decision

Option 3. `scripts/install_bpftrace.sh` downloads bpftrace v0.20.2 from the bpftrace GitHub release, checks its
SHA-256 (`44857efb90a4d3f7cb2495695c1b03b60736d3e286ba1f9cf1b8bc048f9e0adf`) and installs it to
`/usr/local/bin`. The static binary does not use the distribution's libraries, so 22.04 and 24.04 run the same build.
Do not install bpftrace from apt on 22.04.

The collector now:

- refuses to start with a clear message if bpftrace is missing, and warns if its version is not v0.20.2;
- explains the "tracepoint not found" error (tracing filesystem not mounted);
- writes a `start` record to `collector_stats.jsonl` with the bpftrace version, kernel, OS and Python of the run, and
  a `stop` record with the totals; window records now carry `"event": "window"`.

These changes do not touch how windows or counts are computed (`fedshield.bt` and `features.py` are unchanged), so
the collector freeze holds.

## Evidence (2026-11-12)

The official binary reports `bpftrace v0.20.2` and is statically linked. In an Ubuntu 22.04 root filesystem with its
system Python 3.10 and this binary, the collector on the live testbed produced 12/12 hosts, no gaps, 0 lost, 0 late,
0 malformed, and the same per-host medians as on 24.04 (e.g. `fs-build-1` 72 and `fs-build-2` 144 execs per window).

## Consequences

- One toolchain for both team machines, whatever their Ubuntu release; each session records it, so a mismatch is
  visible in the data instead of discovered later.
- The kernel stays a variable: Khalid's 6.8 matches 24.04's; record `uname -r` for every machine used to collect.
- The collector runs with system Python (3.10 on 22.04, 3.12 on 24.04); its code uses nothing newer than 3.10.

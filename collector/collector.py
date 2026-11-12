#!/usr/bin/env python3
"""FedShield collector: kernel events from the testbed hosts -> 10-second feature windows.

Run as root with the SYSTEM Python (the virtual environment is not needed):

    sudo python3 collector/collector.py                    # until Ctrl+C
    sudo python3 collector/collector.py --duration 7200    # one 2-hour session

Writes to data/features/ (owned by the user who ran sudo):

    features_YYYYMMDD.jsonl   one row per host per complete window: host, window_start, the 19
                              counts, and lost_events (events the kernel dropped in that window)
    collector_stats.jsonl     one line per written window: events, malformed and late lines,
                              lost events, and overhead (CPU of the collector and of bpftrace,
                              and time the kernel spent running our eBPF programs)

Nothing else is written: paths, addresses and command names stay in memory for one window.
"""
import argparse
import json
import os
import platform
import shutil
import signal
import subprocess
import sys
import threading
import time

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, REPO)
from fedshield.features import Windower, parse_event  # noqa: E402

BPF_STATS = "/proc/sys/kernel/bpf_stats_enabled"
STDERR_NOISE = ("RLIMIT_MEMLOCK", "is deprecated")
TESTED_BPFTRACE = "v0.20.2"          # the version the collector was verified with (decision 0007)
CLK_TCK = os.sysconf("SC_CLK_TCK")


# ---------------------------------------------------------------- overhead measurement

def process_cpu_seconds(pid):
    """User + system CPU seconds used so far by one process (from /proc/<pid>/stat)."""
    try:
        with open(f"/proc/{pid}/stat") as f:
            fields = f.read().rsplit(")", 1)[1].split()
        return (int(fields[11]) + int(fields[12])) / CLK_TCK
    except (OSError, IndexError, ValueError):
        return 0.0


def bpf_program_stats(pid):
    """(run_time_ns, run_cnt) summed over the eBPF programs loaded by ``pid``.

    The kernel only counts these while kernel.bpf_stats_enabled = 1. Read from
    /proc/<pid>/fdinfo of each bpf-prog file descriptor, so bpftool is not needed.
    """
    run_ns = runs = 0
    try:
        fds = os.listdir(f"/proc/{pid}/fd")
    except OSError:
        return 0, 0
    for fd in fds:
        try:
            if os.readlink(f"/proc/{pid}/fd/{fd}") != "anon_inode:bpf-prog":
                continue
            with open(f"/proc/{pid}/fdinfo/{fd}") as f:
                for line in f:
                    key, _, value = line.partition(":")
                    if key == "run_time_ns":
                        run_ns += int(value)
                    elif key == "run_cnt":
                        runs += int(value)
        except (OSError, ValueError):
            continue
    return run_ns, runs


def set_bpf_stats(enabled):
    """Turn the kernel's eBPF run-time accounting on or off; return the previous value (or None)."""
    try:
        with open(BPF_STATS) as f:
            previous = f.read().strip()
        with open(BPF_STATS, "w") as f:
            f.write("1" if enabled else "0")
        return previous
    except OSError:
        return None


class Overhead:
    """Differences in CPU use and eBPF run time since the previous call to ``step``."""

    def __init__(self, bpftrace_pid):
        self.pid = bpftrace_pid
        self.last = self._now()

    def _now(self):
        t = os.times()
        run_ns, runs = bpf_program_stats(self.pid)
        return {"collector_cpu_s": t.user + t.system, "bpftrace_cpu_s": process_cpu_seconds(self.pid),
                "bpf_run_s": run_ns / 1e9, "bpf_runs": runs}

    def step(self):
        now = self._now()
        delta = {k: round(now[k] - self.last[k], 6) for k in now}
        self.last = now
        return delta


def toolchain(bpftrace):
    """Versions that must stay fixed across sessions; recorded at the start of every run."""
    try:
        out = subprocess.run([bpftrace, "--version"], capture_output=True, text=True, timeout=10).stdout.split()
        version = out[-1] if out else "unknown"
    except (OSError, subprocess.TimeoutExpired):
        version = "unknown"
    os_name = "unknown"
    try:
        with open("/etc/os-release") as f:
            for line in f:
                if line.startswith("PRETTY_NAME="):
                    os_name = line.split("=", 1)[1].strip().strip('"')
    except OSError:
        pass
    return {"bpftrace": version, "kernel": platform.release(), "os": os_name,
            "python": platform.python_version()}


# ---------------------------------------------------------------- output files

class Output:
    """Appends rows to features_<day of the window>.jsonl and stats to collector_stats.jsonl."""

    def __init__(self, out_dir):
        self.dir = out_dir
        self.owner = self._sudo_owner()
        os.makedirs(out_dir, exist_ok=True)
        self._chown(out_dir)
        self.files = {}
        self.stats = self._open("collector_stats.jsonl")

    @staticmethod
    def _sudo_owner():
        uid, gid = os.environ.get("SUDO_UID"), os.environ.get("SUDO_GID")
        return (int(uid), int(gid)) if uid and gid else None

    def _chown(self, path):
        if self.owner and os.geteuid() == 0:
            os.chown(path, *self.owner)

    def _open(self, name):
        path = os.path.join(self.dir, name)
        new = not os.path.exists(path)
        f = open(path, "a", buffering=1)
        if new:
            self._chown(path)
        return f

    def rows(self, rows):
        for r in rows:
            day = time.strftime("%Y%m%d", time.localtime(r["window_start"]))
            if day not in self.files:
                self.files[day] = self._open(f"features_{day}.jsonl")
            self.files[day].write(json.dumps(r) + "\n")

    def stat(self, record):
        self.stats.write(json.dumps(record) + "\n")

    def close(self):
        for f in [*self.files.values(), self.stats]:
            f.close()


# ---------------------------------------------------------------- main

def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--out", default=os.path.join(REPO, "data", "features"))
    ap.add_argument("--duration", type=int, default=0, help="stop after N seconds (0 = until Ctrl+C)")
    ap.add_argument("--window", type=int, default=10, help="window length in seconds")
    ap.add_argument("--grace", type=float, default=2.0, help="seconds to wait for late lines")
    ap.add_argument("--bt", default=os.path.join(REPO, "collector", "fedshield.bt"))
    ap.add_argument("--bpftrace", default="bpftrace", help=argparse.SUPPRESS)        # tests use a fake
    ap.add_argument("--no-bpf-stats", action="store_true",
                    help="do not switch on kernel eBPF run-time accounting")
    ap.add_argument("--allow-non-root", action="store_true", help=argparse.SUPPRESS)  # tests only
    args = ap.parse_args()

    if os.geteuid() != 0 and not args.allow_non_root:
        sys.exit("Run as root: sudo python3 collector/collector.py")
    bpftrace = shutil.which(args.bpftrace)
    if bpftrace is None:
        sys.exit(f"collector: bpftrace is not installed (or not on root's PATH). Install the tested version "
                 f"{TESTED_BPFTRACE} with: ./scripts/install_bpftrace.sh   (see docs/decisions/0007)")
    tools = toolchain(bpftrace)
    if tools["bpftrace"] != TESTED_BPFTRACE:
        print(f"collector: WARNING: bpftrace {tools['bpftrace']} found, but the collector was verified with "
              f"{TESTED_BPFTRACE}. Sessions collected with other versions may not be comparable "
              f"(./scripts/install_bpftrace.sh installs {TESTED_BPFTRACE}).", file=sys.stderr, flush=True)

    out = Output(args.out)
    previous_bpf_stats = None if args.no_bpf_stats else set_bpf_stats(True)

    start = time.time()
    out.stat({"event": "start", "ts": round(start, 3), "window_sec": args.window, **tools})
    ns_offset = time.time_ns() - time.monotonic_ns()          # bpftrace nsecs is CLOCK_MONOTONIC
    env = dict(os.environ, BPFTRACE_MAX_STRLEN="128", BPFTRACE_PERF_RB_PAGES="256", LC_ALL="C")
    proc = subprocess.Popen([bpftrace, "-B", "line", args.bt], stdout=subprocess.PIPE,
                            stderr=subprocess.PIPE, text=True, env=env, bufsize=1)

    windower = Windower(start, window_sec=args.window, grace_sec=args.grace)
    lock = threading.Lock()
    count = {"events": 0, "malformed": 0, "lost": 0}
    stop = threading.Event()

    def read_events():
        for line in proc.stdout:
            if line.startswith("Lost "):                       # bpftrace reports drops on stdout
                try:
                    n = int(line.split()[1])
                except (IndexError, ValueError):
                    n = 0
                with lock:
                    windower.note_lost(n, time.time())
                    count["lost"] += n
                continue
            if line.startswith("Attaching") or not line.strip():   # banner, and blank lines at exit
                continue
            ev = parse_event(line, ns_offset)
            with lock:
                if ev is None:
                    count["malformed"] += 1
                elif windower.add(ev):
                    count["events"] += 1

    problems = set()

    def read_errors():
        for line in proc.stderr:
            if "tracepoint not found" in line:
                problems.add("tracefs")
            if not any(s in line for s in STDERR_NOISE):
                sys.stderr.write("[bpftrace] " + line)

    reader = threading.Thread(target=read_events, daemon=True)
    reader.start()
    threading.Thread(target=read_errors, daemon=True).start()
    for sig in (signal.SIGINT, signal.SIGTERM):
        signal.signal(sig, lambda *_: stop.set())

    overhead = Overhead(proc.pid)
    last = {"t": start, **count, "late": 0}
    windows_written = 0

    def write(rows, now):
        nonlocal windows_written
        if not rows:
            return
        out.rows(rows)
        with lock:
            snap = {**count, "late": windower.late}
        starts = sorted({r["window_start"] for r in rows})
        windows_written += len(starts)
        out.stat({"event": "window", "ts": round(now, 3), "window_start": starts[-1], "windows": len(starts),
                  "hosts": len({r["host"] for r in rows}), "interval_s": round(now - last["t"], 3),
                  **{k: snap[k] - last[k] for k in ("events", "malformed", "lost", "late")},
                  **overhead.step()})
        last.update(t=now, **snap)

    print(f"collector: writing windows of {args.window} s to {args.out}"
          f"{'' if args.duration == 0 else f' for {args.duration} s'}; Ctrl+C to stop", flush=True)
    next_report = start + 60
    while not stop.is_set():
        stop.wait(1.0)
        now = time.time()
        with lock:
            rows = windower.flush(now)
        write(rows, now)
        if proc.poll() is not None:
            time.sleep(0.2)                                     # let the error reader see bpftrace's last lines
            print(f"collector: bpftrace exited with code {proc.returncode}", file=sys.stderr)
            if "tracefs" in problems:
                print("collector: the kernel's tracing filesystem is not mounted. Run once:\n"
                      "  sudo mount -t tracefs nodev /sys/kernel/tracing", file=sys.stderr)
            break
        if args.duration and now - start >= args.duration:
            break
        if now >= next_report:
            with lock:
                c = dict(count)
            print(f"collector: {windows_written} windows, {c['events']} events, "
                  f"{c['lost']} lost, {windower.late} late", flush=True)
            next_report += 60

    stop_time = time.time()
    proc.terminate()
    try:
        proc.wait(timeout=5)
    except subprocess.TimeoutExpired:
        proc.kill()
    reader.join(timeout=5)                                     # take the lines still in the pipe
    with lock:
        rows = windower.flush(stop_time, final=True)
    write(rows, stop_time)
    out.stat({"event": "stop", "ts": round(stop_time, 3), "windows": windows_written, "events": count["events"],
              "lost": count["lost"], "late": windower.late, "malformed": count["malformed"],
              "bpftrace_exit": proc.returncode})
    out.close()
    if previous_bpf_stats is not None:
        set_bpf_stats(previous_bpf_stats == "1")
    print(f"collector: stopped. {windows_written} windows, {count['events']} events, {count['lost']} lost, "
          f"{windower.late} late, {count['malformed']} malformed", flush=True)
    return 0 if proc.returncode in (0, -signal.SIGTERM, None) or windows_written else 1


if __name__ == "__main__":
    sys.exit(main())

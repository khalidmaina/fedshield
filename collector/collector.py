#!/usr/bin/env python3
"""FedShield collector: runs bpftrace, turns events into 10-second feature windows.

Run with the SYSTEM python (not the venv), as root:
    sudo python3 collector/collector.py --out data/features

Only window-level counts are written to disk (no raw paths or addresses), which is
the data-minimisation rule of the proposal. Use --raw-sample to also keep a small
sample of raw events for debugging.
"""
import argparse
import json
import os
import random
import signal
import subprocess
import sys
import threading
import time

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, REPO)
from fedshield.features import WindowAggregator, parse_bpftrace_line  # noqa: E402


def owner_ids():
    """Files are created by root; give them back to the user who ran sudo."""
    uid, gid = os.environ.get("SUDO_UID"), os.environ.get("SUDO_GID")
    return (int(uid), int(gid)) if uid and gid else None


def open_append(path, ids):
    new = not os.path.exists(path)
    f = open(path, "a", buffering=1)
    if new and ids:
        os.chown(path, *ids)
    return f


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", default=os.path.join(REPO, "data", "features"))
    ap.add_argument("--window", type=int, default=10, help="window length in seconds")
    ap.add_argument("--bt", default=os.path.join(REPO, "collector", "fedshield.bt"))
    ap.add_argument("--raw-sample", type=float, default=0.0,
                    help="fraction of raw events to keep for debugging (0 = none)")
    ap.add_argument("--duration", type=int, default=0, help="stop after N seconds (0 = run until Ctrl+C)")
    args = ap.parse_args()

    if os.geteuid() != 0:
        sys.exit("Run with sudo: sudo python3 collector/collector.py")
    ids = owner_ids()
    os.makedirs(args.out, exist_ok=True)
    if ids:
        os.chown(args.out, *ids)

    # bpftrace 'nsecs' is CLOCK_MONOTONIC; convert to wall-clock time.
    ns_offset = time.time_ns() - time.monotonic_ns()
    env = dict(os.environ, BPFTRACE_MAX_STRLEN="128", BPFTRACE_PERF_RB_PAGES="256")
    proc = subprocess.Popen(["bpftrace", "-B", "line", args.bt], stdout=subprocess.PIPE,
                            stderr=subprocess.PIPE, text=True, env=env, bufsize=1)

    agg = WindowAggregator(window_sec=args.window)
    lock = threading.Lock()
    stats = {"events": 0, "lost": 0, "malformed": 0, "windows": 0}
    stop = threading.Event()

    def read_stderr():
        for line in proc.stderr:
            if "Lost" in line and "events" in line:
                try:
                    with lock:
                        stats["lost"] += int(line.split("Lost")[1].split()[0])
                except (IndexError, ValueError):
                    pass
            elif "RLIMIT_MEMLOCK" not in line and "deprecated" not in line:
                sys.stderr.write("[bpftrace] " + line)

    threading.Thread(target=read_stderr, daemon=True).start()

    def handle_signal(signum, frame):
        stop.set()

    signal.signal(signal.SIGINT, handle_signal)
    signal.signal(signal.SIGTERM, handle_signal)

    day = time.strftime("%Y%m%d")
    feat_f = open_append(os.path.join(args.out, f"features_{day}.jsonl"), ids)
    stat_f = open_append(os.path.join(args.out, "collector_stats.jsonl"), ids)
    raw_f = open_append(os.path.join(args.out, f"raw_sample_{day}.jsonl"), ids) if args.raw_sample > 0 else None

    def flusher():
        nonlocal feat_f, day
        last_stats = time.time()
        while not stop.is_set():
            time.sleep(1)
            now = time.time()
            with lock:
                rows = agg.flush(now)
                stats["windows"] += len(rows)
                snapshot = dict(stats)
            if time.strftime("%Y%m%d") != day:      # new file every day
                day = time.strftime("%Y%m%d")
                feat_f.close()
                feat_f = open_append(os.path.join(args.out, f"features_{day}.jsonl"), ids)
            for r in rows:
                feat_f.write(json.dumps(r) + "\n")
            if now - last_stats >= 10:
                snapshot["ts"] = now
                stat_f.write(json.dumps(snapshot) + "\n")
                last_stats = now
            if args.duration and now - start >= args.duration:
                stop.set()
                proc.terminate()

    start = time.time()
    t = threading.Thread(target=flusher, daemon=True)
    t.start()
    print(f"FedShield collector running. Writing windows to {args.out}. Press Ctrl+C to stop.", flush=True)

    for line in proc.stdout:
        if stop.is_set():
            break
        if line.startswith("Attaching"):
            continue
        ev = parse_bpftrace_line(line, ns_offset)
        with lock:
            if ev is None:
                stats["malformed"] += 1
                continue
            stats["events"] += 1
            agg.add(ev)
        if raw_f and random.random() < args.raw_sample:
            raw_f.write(json.dumps(ev) + "\n")

    proc.terminate()
    try:
        proc.wait(timeout=5)
    except subprocess.TimeoutExpired:
        proc.kill()
    stop.set()
    t.join(timeout=3)
    with lock:
        for r in agg.flush(time.time()):   # write windows that are already complete
            feat_f.write(json.dumps(r) + "\n")
    feat_f.close()
    stat_f.close()
    if raw_f:
        raw_f.close()
    print("Collector stopped. Stats:", stats, flush=True)


if __name__ == "__main__":
    main()

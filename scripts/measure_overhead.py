#!/usr/bin/env python3
"""Measures the CPU and memory cost of the collector (bpftrace + collector.py) and
the whole VM, once per second.

Usage (venv active):
    python scripts/measure_overhead.py --label with_collector --duration 600
    python scripts/measure_overhead.py --label without_collector --duration 600
Output: results/overhead/<label>.csv and <label>.json (means, 95th percentiles,
lost events from the collector's statistics file).
"""
import argparse
import json
import os
import time

import pandas as pd
import psutil

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def collector_procs():
    procs = []
    for p in psutil.process_iter(["pid", "cmdline"]):
        cmd = " ".join(p.info["cmdline"] or [])
        if "fedshield.bt" in cmd or "collector/collector.py" in cmd:
            procs.append(p)
    return procs


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--label", required=True)
    ap.add_argument("--duration", type=int, default=600)
    ap.add_argument("--out", default=os.path.join(REPO, "results", "overhead"))
    args = ap.parse_args()
    os.makedirs(args.out, exist_ok=True)
    procs = collector_procs()
    print(f"Found {len(procs)} collector processes:", [p.pid for p in procs])
    for p in procs:
        p.cpu_percent(None)
    psutil.cpu_percent(None)
    ncpu = psutil.cpu_count()
    rows = []
    for i in range(args.duration):
        time.sleep(1)
        cpu, rss = 0.0, 0.0
        for p in procs:
            try:
                cpu += p.cpu_percent(None)
                rss += p.memory_info().rss
            except psutil.NoSuchProcess:
                pass
        rows.append({"t": i + 1, "collector_cpu_pct_of_one_core": cpu,
                     "collector_cpu_pct_of_vm": cpu / ncpu, "collector_rss_mb": rss / 2**20,
                     "vm_cpu_pct": psutil.cpu_percent(None), "vm_mem_used_mb": psutil.virtual_memory().used / 2**20})
        if (i + 1) % 60 == 0:
            print(f"{i + 1}s  collector CPU {cpu / ncpu:.2f}% of VM, VM CPU {rows[-1]['vm_cpu_pct']:.1f}%", flush=True)
    df = pd.DataFrame(rows)
    df.to_csv(os.path.join(args.out, f"{args.label}.csv"), index=False)
    summ = {c: {"mean": float(df[c].mean()), "p95": float(df[c].quantile(0.95))} for c in df.columns if c != "t"}
    stats_file = os.path.join(REPO, "data", "features", "collector_stats.jsonl")
    if os.path.exists(stats_file):
        with open(stats_file) as f:
            lines = [json.loads(x) for x in f if x.strip()]
        if lines:
            last = lines[-1]
            summ["collector_events_total"] = last["events"]
            summ["collector_lost_total"] = last["lost"]
            summ["lost_fraction"] = last["lost"] / max(1, last["events"] + last["lost"])
    with open(os.path.join(args.out, f"{args.label}.json"), "w") as f:
        json.dump(summ, f, indent=2)
    print(json.dumps(summ, indent=2))


if __name__ == "__main__":
    main()

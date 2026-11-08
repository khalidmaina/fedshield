#!/usr/bin/env python3
"""Runs simulated attacks on testbed hosts at scheduled times and records labels.

Usage (from the repository root, with the venv active):
    python scripts/run_schedule.py --schedule testbed/schedules/day_A.yaml

The schedule file lists attacks with a start minute and a duration. Every attack is
started with `docker exec -d <host> bash /attacks/<attack>.sh <seconds>` and one row
(session, host, attack, start_ts, end_ts) is appended to data/labels/labels.csv.
"""
import argparse
import csv
import os
import subprocess
import sys
import time

import yaml

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
ATTACKS = {"beacon", "cred_access", "miner", "persistence", "scan"}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--schedule", required=True)
    ap.add_argument("--labels", default=os.path.join(REPO, "data", "labels", "labels.csv"))
    ap.add_argument("--dry-run", action="store_true", help="print the plan without running")
    args = ap.parse_args()

    with open(args.schedule) as f:
        sch = yaml.safe_load(f)
    session = sch["session"]
    total_min = float(sch["duration_min"])
    items = sorted(sch.get("attacks", []), key=lambda a: a["start_min"])
    for a in items:
        if a["attack"] not in ATTACKS:
            sys.exit(f"Unknown attack {a['attack']}. Allowed: {sorted(ATTACKS)}")
        if a["start_min"] + a["duration_min"] > total_min:
            sys.exit(f"Attack {a} ends after the session ends ({total_min} min)")

    print(f"Session {session}: {total_min} min, {len(items)} attacks")
    for a in items:
        print(f"  +{a['start_min']:>5} min  {a['host']:<11} {a['attack']:<12} {a['duration_min']} min")
    if args.dry_run:
        return

    os.makedirs(os.path.dirname(args.labels), exist_ok=True)
    new = not os.path.exists(args.labels)
    t0 = time.time()
    with open(args.labels, "a", newline="") as f:
        w = csv.writer(f)
        if new:
            w.writerow(["session", "host", "attack", "start_ts", "end_ts"])
        for a in items:
            start_at = t0 + 60 * a["start_min"]
            while time.time() < start_at:
                time.sleep(min(5, start_at - time.time()))
            secs = int(60 * a["duration_min"])
            cmd = ["docker", "exec", "-d", a["host"], "bash", f"/attacks/{a['attack']}.sh", str(secs)]
            subprocess.run(cmd, check=True)
            start = time.time()
            w.writerow([session, a["host"], a["attack"], f"{start:.3f}", f"{start + secs:.3f}"])
            f.flush()
            print(time.strftime("%H:%M:%S"), "started", a["attack"], "on", a["host"], f"for {secs}s", flush=True)
    remaining = t0 + 60 * total_min - time.time()
    if remaining > 0:
        print(f"All attacks started. Waiting {remaining / 60:.1f} min until the session ends...", flush=True)
        time.sleep(remaining)
    print("Session finished:", session)


if __name__ == "__main__":
    main()

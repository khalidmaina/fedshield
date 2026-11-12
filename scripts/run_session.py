#!/usr/bin/env python3
"""Run one 2-hour collection session from its schedule (the collector must already be running).

    # terminal 1                                  # terminal 2, about 30 s later
    make collect DURATION=7500                    make session N=1

Before starting it checks: the schedule is valid, all 13 containers are healthy, the collector
is running and writing, and this session has not been recorded already. It then starts each
attack on time through the hosts' agents and writes data/labels/session_NN.json with what
actually happened (host-reported start/end times and exit codes).
"""
import argparse
import datetime
import json
import os
import subprocess
import sys
import time

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, REPO)
from fedshield.control import testbed_health  # noqa: E402
from fedshield.schedule import validate  # noqa: E402
from fedshield.session import run_session, summarize  # noqa: E402


def collector_running(features_dir, max_age_s=30):
    """Problems with the collector (empty list = running and writing recently)."""
    problems = []
    if subprocess.run(["pgrep", "-f", "collector/collector.py"], capture_output=True).returncode != 0:
        problems.append("the collector is not running (terminal 1: make collect DURATION=7500)")
    stats = os.path.join(features_dir, "collector_stats.jsonl")
    try:
        age = time.time() - os.path.getmtime(stats)
        if age > max_age_s:
            problems.append(f"the collector has not written for {age:.0f} s ({stats})")
    except OSError:
        problems.append(f"no collector output yet in {features_dir}")
    return problems


def git_commit():
    r = subprocess.run(["git", "-C", REPO, "rev-parse", "--short", "HEAD"], capture_output=True, text=True)
    dirty = subprocess.run(["git", "-C", REPO, "status", "--porcelain", "--untracked-files=no"],
                           capture_output=True, text=True).stdout.strip()
    return (r.stdout.strip() or "unknown") + ("-dirty" if dirty else "")


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--session", type=int, help="session number: uses testbed/schedules/session_NN.json")
    ap.add_argument("--schedule", help="path to a schedule file instead")
    ap.add_argument("--labels", default=os.path.join(REPO, "data", "labels"))
    ap.add_argument("--features", default=os.path.join(REPO, "data", "features"),
                    help="collector output folder (to check it is writing)")
    ap.add_argument("--overwrite", action="store_true", help="replace an existing record of this session")
    ap.add_argument("--yes", action="store_true", help="start without asking")
    args = ap.parse_args()
    if not (args.session or args.schedule):
        ap.error("give --session N or --schedule FILE")

    path = args.schedule or os.path.join(REPO, "testbed", "schedules", f"session_{args.session:02d}.json")
    with open(path) as f:
        schedule = json.load(f)
    out = os.path.join(args.labels, f"session_{schedule['session']:02d}.json")

    problems = [f"schedule: {p}" for p in validate(schedule)]
    problems += [f"{name}: {'; '.join(p)}" for name, _, _, p in testbed_health() if p]
    problems += collector_running(args.features)
    if os.path.exists(out) and not args.overwrite:
        problems.append(f"{out} already exists (this session was recorded; use --overwrite to redo it)")
    if problems:
        print("Not starting:\n  - " + "\n  - ".join(problems))
        return 1

    end = datetime.datetime.now() + datetime.timedelta(minutes=schedule["duration_min"])
    print(f"Session {schedule['session']} ({schedule['split']}): {len(schedule['attacks'])} attacks over "
          f"{schedule['duration_min']:g} min, ends about {end:%H:%M}. Keep the collector running until then.")
    if not args.yes and input("Start now? [y/N] ").strip().lower() != "y":
        return 1

    record = None
    try:
        record = run_session(schedule, log=lambda m: print(m, flush=True))
    except KeyboardInterrupt:
        print("\nInterrupted.")
    if record is None:                                   # interrupted before run_session returned
        print("No record written; rerun with --overwrite if needed.")
        return 1

    record.update(commit=git_commit(), schedule_file=os.path.relpath(path, REPO),
                  written=datetime.datetime.now().isoformat(timespec="seconds"))
    os.makedirs(args.labels, exist_ok=True)
    with open(out, "w") as f:
        json.dump(record, f, indent=1)
        f.write("\n")
    s = summarize(record)
    print(f"\nSession {record['session']} {record['status']}: {s['ok']}/{s['planned']} attacks ran cleanly"
          f"; rejected {s['rejected']}, errors {s['errors']}, non-zero exit {s['failed']}, "
          f"unfinished {s['unfinished']}.\nWrote {out}\n"
          f"Check the windows: python scripts/features_report.py --from {record['start_ts']:.0f} "
          f"--to {record['end_ts']:.0f}")
    return 0 if record["status"] == "complete" and s["ok"] == s["planned"] else 1


if __name__ == "__main__":
    sys.exit(main())

#!/usr/bin/env python3
"""Write the session schedules (decision 0003) and show what each host gets in each split.

    python scripts/make_schedule.py                       # all 8 sessions -> testbed/schedules/
    python scripts/make_schedule.py --check               # only print coverage, write nothing
    python scripts/make_schedule.py --sessions 1 --duration-min 12 --attack-min 2 \\
        --max-concurrent 12 --out /tmp/mini              # a short session for testing

The schedules are part of the experiment design: commit testbed/schedules/ to Git.
"""
import argparse
import json
import os
import sys

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, REPO)
from fedshield.schedule import PLAN, coverage, make_schedule, validate  # noqa: E402
from fedshield.topology import ATTACKS, HOSTS  # noqa: E402

SHORT = {"beacon": "B", "cred_access": "C", "miner": "M", "persistence": "P", "scan": "S"}


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--sessions", type=int, nargs="*", default=sorted(PLAN))
    ap.add_argument("--seed", type=int, default=7)
    ap.add_argument("--duration-min", type=float, default=120)
    ap.add_argument("--attack-min", type=float, default=8)
    ap.add_argument("--max-concurrent", type=int, default=4)
    ap.add_argument("--out", default=os.path.join(REPO, "testbed", "schedules"))
    ap.add_argument("--check", action="store_true", help="print coverage only")
    args = ap.parse_args()

    schedules = [make_schedule(s, seed=args.seed, duration_min=args.duration_min, attack_min=args.attack_min,
                               max_concurrent=args.max_concurrent) for s in args.sessions]
    for sch in schedules:
        problems = validate(sch)
        if problems:
            sys.exit(f"session {sch['session']}: " + "; ".join(problems))

    splits = list(dict.fromkeys(sch["split"] for sch in schedules))
    cov = coverage(schedules)
    print("attacks per host and split (" + ", ".join(f"{v}={k}" for k, v in SHORT.items()) + ")")
    print(f"{'host':<11}" + "".join(f"{sp:>17}" for sp in splits))
    for h in HOSTS:
        print(f"{h:<11}" + "".join(
            f"{' '.join(f'{SHORT[a]}{n}' for a, n in sorted(cov[h].get(sp, {}).items())):>17}" for sp in splits))
    missing = [(h, a) for h in HOSTS for a in ATTACKS if a not in cov[h].get("train", {})]
    if "train" in splits:
        print(f"\nevery host has every attack in train: {'yes' if not missing else missing}")

    if args.check:
        return 0
    os.makedirs(args.out, exist_ok=True)
    for sch in schedules:
        path = os.path.join(args.out, f"session_{sch['session']:02d}.json")
        with open(path, "w") as f:
            json.dump(sch, f, indent=1)
            f.write("\n")
    print(f"\nwrote {len(schedules)} schedule(s) to {args.out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())

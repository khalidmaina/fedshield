#!/usr/bin/env python3
"""Creates an attack schedule for one collection session.

Every host is attacked once per session; the attack type rotates from session to
session so that, after 5 sessions, every host has seen every attack type.

Usage:
    python scripts/make_schedule.py --index 1            # writes testbed/schedules/session_01.yaml
    python scripts/make_schedule.py --index 1 --duration 120 --attack-min 8
"""
import argparse
import os

import yaml

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
HOSTS = [f"fs-{r}-{i}" for r in ("web", "db", "build", "dev") for i in (1, 2, 3)]
ATTACKS = ["beacon", "cred_access", "miner", "persistence", "scan"]


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--index", type=int, required=True, help="session number 1, 2, 3, ...")
    ap.add_argument("--duration", type=float, default=120, help="session length in minutes")
    ap.add_argument("--attack-min", type=float, default=8, help="length of each attack in minutes")
    args = ap.parse_args()

    usable = args.duration - 10 - args.attack_min        # first 5 and last 5 minutes stay benign
    step = usable / max(1, len(HOSTS) - 1)
    attacks = []
    for k, host in enumerate(HOSTS):
        attacks.append({
            "host": host,
            "attack": ATTACKS[(k + args.index) % len(ATTACKS)],
            "start_min": round(5 + k * step, 1),
            "duration_min": args.attack_min,
        })
    sch = {"session": f"session_{args.index:02d}", "duration_min": args.duration, "attacks": attacks}
    out = os.path.join(REPO, "testbed", "schedules", f"session_{args.index:02d}.yaml")
    os.makedirs(os.path.dirname(out), exist_ok=True)
    with open(out, "w") as f:
        yaml.safe_dump(sch, f, sort_keys=False)
    print("Wrote", out)


if __name__ == "__main__":
    main()

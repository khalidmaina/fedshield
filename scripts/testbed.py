#!/usr/bin/env python3
"""Testbed control from the host machine.

    python scripts/testbed.py status                              # are all 13 containers healthy?
    python scripts/testbed.py attack fs-web-1 beacon --seconds 60 # start an attack on one host
    python scripts/testbed.py attack fs-db-2 scan --seconds 30 --wait
    python scripts/testbed.py log fs-web-1                        # what that host has reported

Everything here looks at the hosts from outside (docker inspect, docker top) or talks to
their agents through testbed/control/. Nothing is executed inside a host, so these commands
leave no trace in the collected telemetry.
"""
import argparse
import json
import os
import sys
import time

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, REPO)
from fedshield.control import ATTACKS, HOSTS, read_status, start_attack, testbed_health, wait_for  # noqa: E402


def cmd_status(_args):
    health = testbed_health()
    print(f"{'container':<12} {'state':<9} {'started':<20} problems")
    for name, state, started, problems in health:
        print(f"{name:<12} {state:<9} {started:<20} {'; '.join(problems) or 'ok'}")
    bad = sum(bool(p) for *_, p in health)
    print(f"\n{len(health) - bad}/{len(health)} containers healthy")
    return 1 if bad else 0


def cmd_attack(args):
    rec = start_attack(args.host, args.attack, args.seconds)
    if rec["event"] == "rejected":
        print(f"{args.host} rejected the request: {rec.get('reason')}")
        return 1
    print(f"{time.strftime('%H:%M:%S')} {args.attack} started on {args.host} for {args.seconds} s "
          f"(id {rec['id']}, pid {rec.get('pid')})")
    if not args.wait:
        return 0
    end = wait_for(args.host, rec["id"], events=("finished",), timeout=args.seconds + 60)
    if end is None:
        print("no 'finished' report within the expected time")
        return 1
    took = float(end["ts"]) - float(rec["ts"])
    print(f"{time.strftime('%H:%M:%S')} finished after {took:.1f} s, exit code {end['exit_code']}")
    return 0 if end["exit_code"] == 0 else 1


def cmd_log(args):
    for rec in read_status(args.host):
        print(json.dumps(rec))
    return 0


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="cmd", required=True)
    sub.add_parser("status", help="check every container from outside")
    a = sub.add_parser("attack", help="start a simulated attack on one host")
    a.add_argument("host", choices=HOSTS)
    a.add_argument("attack", choices=ATTACKS)
    a.add_argument("--seconds", type=int, default=60)
    a.add_argument("--wait", action="store_true", help="wait until the attack finishes")
    lg = sub.add_parser("log", help="print a host's status reports")
    lg.add_argument("host", choices=HOSTS)
    args = ap.parse_args()
    return {"status": cmd_status, "attack": cmd_attack, "log": cmd_log}[args.cmd](args)


if __name__ == "__main__":
    sys.exit(main())

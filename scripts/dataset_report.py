#!/usr/bin/env python3
"""What the built dataset contains, per split, host and attack, and whether RQ5 can be evaluated.

    python scripts/dataset_report.py                # data/processed/host_windows.csv

RQ5 needs, for any host chosen as compromised, beacon windows in its training data (to poison
with) and beacon windows in the test data of the other hosts, in both regions.
"""
import argparse
import csv
import os
import sys

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, REPO)
from fedshield.topology import ATTACKS, HOSTS, REGION_OF, TARGET_ATTACK  # noqa: E402

SPLITS = ("train", "val", "test", "holdout")


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("csv", nargs="?", default=os.path.join(REPO, "data", "processed", "host_windows.csv"))
    args = ap.parse_args()
    with open(args.csv) as f:
        rows = list(csv.DictReader(f))
    if not rows:
        sys.exit("empty dataset")

    count = {}
    for r in rows:
        key = (r["host"], r["split"], r["label"])
        count[key] = count.get(key, 0) + 1
    splits = [s for s in SPLITS if any(r["split"] == s for r in rows)]
    sessions = sorted({int(r["session"]) for r in rows})
    print(f"{args.csv}: {len(rows)} windows, sessions {sessions}, "
          f"{sum(1 for r in rows if int(r['lost_events']) > 0)} with lost events\n")

    print("windows per host: benign / attack, by split")
    print(f"{'host':<11}" + "".join(f"{s:>16}" for s in splits))
    for h in HOSTS:
        cells = []
        for s in splits:
            benign = count.get((h, s, "benign"), 0)
            attack = sum(count.get((h, s, a), 0) for a in ATTACKS)
            cells.append(f"{benign} / {attack}")
        print(f"{h:<11}" + "".join(f"{c:>16}" for c in cells))

    print("\nattack windows by split")
    for s in splits:
        print(f"  {s:<8}" + "  ".join(f"{a} {sum(count.get((h, s, a), 0) for h in HOSTS)}" for a in ATTACKS))

    test = "test" if "test" in splits else None
    pool = {h for h in HOSTS if count.get((h, "train", TARGET_ATTACK), 0)}
    evaluable = {h for h in HOSTS if test and count.get((h, test, TARGET_ATTACK), 0)}
    by_region = {r: sorted(h for h in evaluable if REGION_OF[h] == r) for r in ("A", "B")}
    print(f"\nRQ5 ({TARGET_ATTACK}): {len(pool)}/12 hosts can be compromised (beacon in train); "
          f"{len(evaluable)}/12 can be evaluated (beacon in test): "
          f"region A {len(by_region['A'])}, region B {len(by_region['B'])}")
    return 0


if __name__ == "__main__":
    sys.exit(main())

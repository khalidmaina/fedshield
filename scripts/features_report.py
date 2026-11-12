#!/usr/bin/env python3
"""Summarise collected feature windows: coverage per host and typical values per role.

    python scripts/features_report.py                         # newest data/features/features_*.jsonl
    python scripts/features_report.py data/features/features_20261112.jsonl
    python scripts/features_report.py FILE --from 1794499470 --to 1794499530   # a time range

Used for integration check T2 (every host, only the hosts, no gaps, no loss) and to eyeball
attack windows (T3). Standard library only.
"""
import argparse
import glob
import json
import os
import statistics
import sys

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, REPO)
from fedshield.control import HOSTS  # noqa: E402
from fedshield.features import FEATURES  # noqa: E402

SHOW = ("exec_count", "open_count", "open_write_count", "conn_count", "exit_count", "unique_comm")


def load(path, t_from=None, t_to=None):
    rows = []
    with open(path) as f:
        for line in f:
            r = json.loads(line)
            if (t_from is None or r["window_start"] >= t_from) and (t_to is None or r["window_start"] < t_to):
                rows.append(r)
    return rows


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("file", nargs="?")
    ap.add_argument("--from", dest="t_from", type=float)
    ap.add_argument("--to", dest="t_to", type=float)
    args = ap.parse_args()
    path = args.file or max(glob.glob(os.path.join(REPO, "data", "features", "features_*.jsonl")), default=None)
    if not path:
        sys.exit("No features file found in data/features/.")
    rows = load(path, args.t_from, args.t_to)
    if not rows:
        sys.exit(f"No windows in {path} for that range.")

    starts = sorted({r["window_start"] for r in rows})
    step = rows[0]["window_sec"]
    expected = (starts[-1] - starts[0]) // step + 1
    hosts = sorted({r["host"] for r in rows})
    lost = {r["window_start"]: r["lost_events"] for r in rows}
    print(f"{path}\n{len(starts)} windows of {step} s from {starts[0]} to {starts[-1] + step} "
          f"({'no gaps' if len(starts) == expected else f'{expected - len(starts)} missing'}), "
          f"lost events: {sum(lost.values())} in {sum(1 for v in lost.values() if v)} window(s)\n")

    missing, extra = sorted(set(HOSTS) - set(hosts)), sorted(set(hosts) - set(HOSTS))
    print(f"hosts: {len(hosts)} of 12" + (f"; missing {missing}" if missing else "")
          + (f"; unexpected {extra}" if extra else ""))
    print(f"\n{'host':<11} {'windows':>7}  " + "  ".join(f"{k:>16}" for k in SHOW) + "   (median per window)")
    for h in hosts:
        hr = [r for r in rows if r["host"] == h]
        print(f"{h:<11} {len(hr):>7}  " + "  ".join(f"{statistics.median(r[k] for r in hr):>16g}" for k in SHOW))

    nonzero = [k for k in FEATURES if any(r[k] for r in rows)]
    quiet = [k for k in FEATURES if k not in nonzero]
    print(f"\nfeatures never non-zero in this range: {', '.join(quiet) if quiet else 'none'}")
    return 0 if not missing and not extra and len(starts) == expected else 1


if __name__ == "__main__":
    sys.exit(main())

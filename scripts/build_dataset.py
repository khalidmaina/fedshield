#!/usr/bin/env python3
"""Build data/processed/host_windows.csv from the feature windows and the session records.

    python scripts/build_dataset.py                 # all sessions in data/labels/
    python scripts/build_dataset.py --include-aborted

Also writes data/processed/manifest.json: sessions used, counts per split and label, dropped
windows, SHA-256 of the CSV and the Git commit. At the data freeze, that hash goes into
docs/data_protocol.md.
"""
import argparse
import csv
import datetime
import glob
import json
import os
import subprocess
import sys

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, REPO)
from fedshield.dataset import COLUMNS, build, sha256_of  # noqa: E402


def read_jsonl(paths):
    rows = []
    for p in paths:
        with open(p) as f:
            rows += [json.loads(line) for line in f if line.strip()]
    return rows


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--features", default=os.path.join(REPO, "data", "features"))
    ap.add_argument("--labels", default=os.path.join(REPO, "data", "labels"))
    ap.add_argument("--out", default=os.path.join(REPO, "data", "processed"))
    ap.add_argument("--min-overlap", type=float, default=0.5)
    ap.add_argument("--include-aborted", action="store_true")
    args = ap.parse_args()

    feature_rows = read_jsonl(sorted(glob.glob(os.path.join(args.features, "features_*.jsonl"))))
    records = []
    for p in sorted(glob.glob(os.path.join(args.labels, "session_*.json"))):
        with open(p) as f:
            records.append(json.load(f))
    if not feature_rows or not records:
        sys.exit(f"Nothing to build: {len(feature_rows)} feature windows, {len(records)} session records.")

    rows, report = build(feature_rows, records, args.min_overlap, args.include_aborted)
    os.makedirs(args.out, exist_ok=True)
    csv_path = os.path.join(args.out, "host_windows.csv")
    with open(csv_path, "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=COLUMNS)
        w.writeheader()
        w.writerows(rows)
    commit = subprocess.run(["git", "-C", REPO, "rev-parse", "--short", "HEAD"], capture_output=True,
                            text=True).stdout.strip() or "unknown"
    manifest = {"created": datetime.datetime.now().isoformat(timespec="seconds"), "commit": commit,
                "rows": len(rows), "sha256": sha256_of(csv_path), "min_overlap": args.min_overlap, **report}
    with open(os.path.join(args.out, "manifest.json"), "w") as f:
        json.dump(manifest, f, indent=1)
        f.write("\n")

    print(f"{len(rows)} windows -> {csv_path}\nsha256 {manifest['sha256']}\n")
    for s in report["sessions"]:
        if "skipped" in s:
            print(f"session {s['session']} ({s['split']}): skipped, {s['skipped']}")
            continue
        got = s["windows_per_host"]
        short = {h: n for h, n in got.items() if n < s["expected_windows_per_host"]}
        print(f"session {s['session']} ({s['split']}): {len(got)} hosts, up to {s['expected_windows_per_host']} "
              f"windows each" + (f"; fewer for {short}" if short else ""))
    d = report["dropped"]
    print(f"\ndropped: {d['ambiguous']} ambiguous (attack edge), {d['excluded']} excluded (failed attack), "
          f"{d['duplicate']} duplicate")
    for split, counts in report["counts"].items():
        attacks = {k: v for k, v in counts.items() if k != "benign"}
        listed = "  ".join(f"{k} {v}" for k, v in sorted(attacks.items()))
        print(f"{split:<8} benign {counts.get('benign', 0):>6}   {listed}")
    return 0


if __name__ == "__main__":
    sys.exit(main())

#!/usr/bin/env python3
"""Joins collector windows with attack labels into one CSV.

Usage:
    python scripts/build_dataset.py
Inputs : data/features/features_*.jsonl, data/labels/labels.csv
Output : data/processed/host_windows.csv

A window is labelled as an attack if at least half of it overlaps an attack interval
on the same host. Windows that overlap an attack by less than half are dropped as
ambiguous, so the boundaries do not create noisy labels.
"""
import argparse
import glob
import json
import os

import pandas as pd

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--features", default=os.path.join(REPO, "data", "features"))
    ap.add_argument("--labels", default=os.path.join(REPO, "data", "labels", "labels.csv"))
    ap.add_argument("--out", default=os.path.join(REPO, "data", "processed", "host_windows.csv"))
    args = ap.parse_args()

    rows = []
    for path in sorted(glob.glob(os.path.join(args.features, "features_*.jsonl"))):
        with open(path) as f:
            for line in f:
                line = line.strip()
                if line:
                    rows.append(json.loads(line))
    if not rows:
        raise SystemExit("No feature windows found. Did the collector run?")
    df = pd.DataFrame(rows).drop_duplicates(["host", "window_start"]).sort_values(["host", "window_start"])
    df["label"], df["attack"], df["ambiguous"] = 0, "", False

    if os.path.exists(args.labels):
        lab = pd.read_csv(args.labels)
        for _, a in lab.iterrows():
            m = df["host"] == a["host"]
            ws = df.loc[m, "window_start"]
            we = ws + df.loc[m, "window_sec"]
            overlap = (we.clip(upper=a["end_ts"]) - ws.clip(lower=a["start_ts"])).clip(lower=0)
            frac = overlap / df.loc[m, "window_sec"]
            idx_attack = frac[frac >= 0.5].index
            idx_amb = frac[(frac > 0) & (frac < 0.5)].index
            df.loc[idx_attack, "label"] = 1
            df.loc[idx_attack, "attack"] = a["attack"]
            df.loc[idx_amb, "ambiguous"] = True
    else:
        print("WARNING: no labels file; all windows are treated as benign.")

    df = df[~(df["ambiguous"] & (df["label"] == 0))].drop(columns=["ambiguous"])
    os.makedirs(os.path.dirname(args.out), exist_ok=True)
    df.to_csv(args.out, index=False)
    print(f"Wrote {len(df)} windows for {df['host'].nunique()} hosts to {args.out}")
    print(df.groupby(["host", "attack"]).size().unstack(fill_value=0).to_string())


if __name__ == "__main__":
    main()

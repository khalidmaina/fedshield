#!/usr/bin/env python3
"""Makes a smaller, cleaned CICIDS2017 file so each experiment loads quickly.

Usage:
    python scripts/prepare_cicids.py --src data/raw/MachineLearningCVE
Output: data/processed/cicids_sample.csv
Keeps a random sample of benign flows and up to --max-attack flows per attack type.
"""
import argparse
import glob
import os

import numpy as np
import pandas as pd

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--src", default=os.path.join(REPO, "data", "raw", "MachineLearningCVE"))
    ap.add_argument("--out", default=os.path.join(REPO, "data", "processed", "cicids_sample.csv"))
    ap.add_argument("--benign", type=int, default=400000)
    ap.add_argument("--max-attack", type=int, default=20000)
    ap.add_argument("--min-attack", type=int, default=500, help="drop attack types with fewer flows")
    ap.add_argument("--seed", type=int, default=1)
    args = ap.parse_args()
    files = sorted(glob.glob(os.path.join(args.src, "*.csv")))
    if not files:
        raise SystemExit(f"No CSV files in {args.src}")
    parts = []
    for f in files:
        print("reading", os.path.basename(f))
        df = pd.read_csv(f, low_memory=False, encoding="latin-1")
        df.columns = [c.strip() for c in df.columns]
        parts.append(df)
    df = pd.concat(parts, ignore_index=True)
    df["Label"] = df["Label"].astype(str).str.strip()
    num = [c for c in df.columns if c != "Label"]
    df[num] = df[num].apply(pd.to_numeric, errors="coerce").replace([np.inf, -np.inf], np.nan)
    df = df.dropna()
    benign = df[df["Label"] == "BENIGN"].sample(n=min(args.benign, (df["Label"] == "BENIGN").sum()),
                                                random_state=args.seed)
    att = []
    for name, g in df[df["Label"] != "BENIGN"].groupby("Label"):
        if len(g) < args.min_attack:
            print(f"skip {name}: only {len(g)} flows")
            continue
        att.append(g.sample(n=min(len(g), args.max_attack), random_state=args.seed))
    out = pd.concat([benign] + att, ignore_index=True)
    os.makedirs(os.path.dirname(args.out), exist_ok=True)
    out.to_csv(args.out, index=False)
    print(f"Wrote {len(out)} flows to {args.out}")
    print(out["Label"].value_counts().to_string())


if __name__ == "__main__":
    main()

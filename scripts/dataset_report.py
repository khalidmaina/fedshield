#!/usr/bin/env python3
"""Shows, for every host, how many windows of each attack fall in the training pool,
validation and test splits. Use it to choose which hosts to compromise in RQ5
(a compromised host needs the target attack in its training pool; evaluation hosts
need it in their test split).

Usage:
    python scripts/dataset_report.py
    python scripts/dataset_report.py --set data.path=data/processed/synthetic_windows.csv
"""
import argparse
import os
import sys

import pandas as pd

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, REPO)
os.chdir(REPO)
from fedshield.config import load_config  # noqa: E402
from fedshield.data import load  # noqa: E402


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--config", default="configs/base.yaml")
    ap.add_argument("--set", nargs="*", default=[])
    args = ap.parse_args()
    cfg = load_config(args.config, args.set)
    clients, feats = load(cfg)
    rows = []
    for c, v in sorted(clients.items()):
        r = {"host": c, "train_benign": len(v.X_train), "val": len(v.X_val), "test": len(v.X_test)}
        for a, x in v.pool.items():
            r[f"pool:{a}"] = len(x)
        for a in set(v.a_test) - {""}:
            r[f"test:{a}"] = int((v.a_test == a).sum())
        rows.append(r)
    df = pd.DataFrame(rows).fillna(0)
    cols = ["host", "train_benign", "val", "test"] + sorted(c for c in df.columns if ":" in c)
    pd.set_option("display.width", 250)
    print(df[cols].to_string(index=False))


if __name__ == "__main__":
    main()

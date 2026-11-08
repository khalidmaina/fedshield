#!/usr/bin/env python3
"""Pivot table (mean +/- std over seeds) from a grid summary, for the thesis.

Usage:
    python scripts/make_table.py --summary results/rq3_robust/summary.csv \
        --rows byzantine.attack --cols aggregation.rule --value hybrid_f1 \
        --out results/summaries/rq3_f1.csv
Prints the table and saves it as CSV.
"""
import argparse
import os

import pandas as pd


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--summary", required=True)
    ap.add_argument("--rows", required=True)
    ap.add_argument("--cols", required=True)
    ap.add_argument("--value", required=True)
    ap.add_argument("--filter", nargs="*", default=[])
    ap.add_argument("--out", default=None)
    ap.add_argument("--digits", type=int, default=3)
    args = ap.parse_args()
    df = pd.read_csv(args.summary)
    for flt in args.filter:
        k, v = flt.split("=", 1)
        df = df[df[k].astype(str) == v]
    mean = df.pivot_table(index=args.rows, columns=args.cols, values=args.value, aggfunc="mean")
    std = df.pivot_table(index=args.rows, columns=args.cols, values=args.value, aggfunc="std").fillna(0)
    d = args.digits
    table = mean.round(d).astype(str) + " +/- " + std.round(d).astype(str)
    print(table.to_string())
    if args.out:
        os.makedirs(os.path.dirname(args.out) or ".", exist_ok=True)
        table.to_csv(args.out)
        print("Saved", args.out)


if __name__ == "__main__":
    main()

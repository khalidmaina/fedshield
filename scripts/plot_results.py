#!/usr/bin/env python3
"""Line plot of one metric against one parameter, one line per group, mean +/- std
over seeds.

Usage:
    python scripts/plot_results.py --summary results/rq5_poison/summary.csv \
        --x poison.pdr --y target_recall_sae_final --hue aggregation.rule \
        --filter variant=no_dp --out figures/rq5_recall.png
"""
import argparse
import os

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt  # noqa: E402
import pandas as pd  # noqa: E402


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--summary", required=True)
    ap.add_argument("--x", required=True)
    ap.add_argument("--y", required=True)
    ap.add_argument("--hue", default=None)
    ap.add_argument("--filter", nargs="*", default=[], help="column=value pairs to keep")
    ap.add_argument("--out", required=True)
    ap.add_argument("--title", default=None)
    args = ap.parse_args()
    df = pd.read_csv(args.summary)
    for flt in args.filter:
        k, v = flt.split("=", 1)
        df = df[df[k].astype(str) == v]
    if df.empty:
        raise SystemExit("No rows left after filtering")
    fig, ax = plt.subplots(figsize=(6, 4))
    groups = df.groupby(args.hue) if args.hue else [("all", df)]
    for name, g in groups:
        s = g.groupby(args.x)[args.y].agg(["mean", "std"]).reset_index().sort_values(args.x)
        ax.errorbar(s[args.x], s["mean"], yerr=s["std"].fillna(0), marker="o", capsize=3, label=str(name))
    ax.set_xlabel(args.x)
    ax.set_ylabel(args.y)
    ax.grid(alpha=0.3)
    if args.hue:
        ax.legend(title=args.hue)
    ax.set_title(args.title or f"{args.y} vs {args.x}")
    os.makedirs(os.path.dirname(args.out) or ".", exist_ok=True)
    fig.tight_layout()
    fig.savefig(args.out, dpi=200)
    print("Saved", args.out)


if __name__ == "__main__":
    main()

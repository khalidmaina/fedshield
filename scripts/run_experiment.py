#!/usr/bin/env python3
"""Runs ONE experiment.

Usage:
    python scripts/run_experiment.py --config configs/base.yaml
    python scripts/run_experiment.py --config configs/base.yaml --set aggregation.rule=krum privacy.track=B
Results go to results/<name>/ (config.yaml, round_log.csv, per_client.csv,
final_metrics.json, privacy.json, and updates.npz / artifacts/ if enabled).
"""
import argparse
import os
import sys

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, REPO)
os.chdir(REPO)
from fedshield.config import load_config  # noqa: E402
from fedshield.fl import run  # noqa: E402


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--config", default="configs/base.yaml")
    ap.add_argument("--set", nargs="*", default=[], help="overrides like aggregation.rule=krum")
    ap.add_argument("--name", default=None, help="name of the results folder")
    args = ap.parse_args()
    cfg = load_config(args.config, args.set)
    if args.name:
        cfg["name"] = args.name
    run_dir = os.path.join(cfg["out_dir"], cfg["name"])
    print("Results folder:", run_dir)
    run(cfg, run_dir=run_dir)


if __name__ == "__main__":
    main()

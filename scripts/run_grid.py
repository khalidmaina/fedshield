#!/usr/bin/env python3
"""Runs a whole experiment grid (many runs) and writes one summary table.

Usage:
    python scripts/run_grid.py --grid configs/grids/rq5_poison.yaml --dry-run   # count runs
    python scripts/run_grid.py --grid configs/grids/rq5_poison.yaml --workers 3
Already finished runs are skipped, so you can stop with Ctrl+C and start again later.
Output: results/<grid name>/<run>/... and results/<grid name>/summary.csv
"""
import argparse
import itertools
import json
import os
import subprocess
import sys
from concurrent.futures import ProcessPoolExecutor, as_completed

import pandas as pd
import yaml

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, REPO)
os.chdir(REPO)
from fedshield.config import load_config, set_dotted  # noqa: E402


def expand(grid_path):
    with open(grid_path) as f:
        g = yaml.safe_load(f)
    base = g.get("base", "configs/base.yaml")
    variants = g.get("variants") or {"default": {}}
    axes = g.get("grid") or {}
    keys = list(axes)
    runs = []
    for vname, vset in variants.items():
        for values in itertools.product(*[axes[k] for k in keys]) if keys else [()]:
            for seed in g.get("seeds", [1]):
                params = {"variant": vname, **dict(zip(keys, values)), "seed": seed}
                cfg = load_config(base)
                for k, v in (g.get("fixed") or {}).items():
                    set_dotted(cfg, k, v)
                for k, v in (vset or {}).items():
                    set_dotted(cfg, k, v)
                for k, v in zip(keys, values):
                    set_dotted(cfg, k, v)
                cfg["seed"] = seed
                runs.append((params, cfg))
    for i, (params, cfg) in enumerate(runs):
        cfg["name"] = f"{g['name']}/run{i:04d}"
        cfg["out_dir"] = "results"
    return g, runs


def one(args):
    params, cfg, threads, post = args
    import torch
    torch.set_num_threads(threads)
    from fedshield.fl import run
    run_dir = os.path.join("results", cfg["name"])
    done = os.path.join(run_dir, "final_metrics.json")
    if not os.path.exists(done):
        run(cfg, run_dir=run_dir, verbose=False)
    with open(done) as f:
        summary = json.load(f)
    if post == "property_inference":
        pi = os.path.join(run_dir, "property_inference.json")
        if not os.path.exists(pi):
            subprocess.run([sys.executable, "scripts/property_inference.py", "--run", run_dir], check=True,
                           capture_output=True)
        with open(pi) as f:
            summary.update({f"pi_{k}": v for k, v in json.load(f).items() if not isinstance(v, list)})
    return {"run": cfg["name"], **params, **summary}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--grid", required=True)
    ap.add_argument("--workers", type=int, default=1, help="parallel runs (use at most CPUs - 1)")
    ap.add_argument("--dry-run", action="store_true")
    args = ap.parse_args()
    g, runs = expand(args.grid)
    print(f"Grid {g['name']}: {len(runs)} runs")
    if args.dry_run:
        for p, c in runs[:10]:
            print("  ", c["name"], p)
        if len(runs) > 10:
            print(f"   ... and {len(runs) - 10} more")
        return
    threads = 1 if args.workers > 1 else max(1, os.cpu_count() or 1)
    jobs = [(p, c, threads, g.get("post")) for p, c in runs]
    rows = []
    out = os.path.join("results", g["name"], "summary.csv")
    os.makedirs(os.path.dirname(out), exist_ok=True)
    with ProcessPoolExecutor(max_workers=args.workers) as ex:
        futs = {ex.submit(one, j): j[1]["name"] for j in jobs}
        for k, fut in enumerate(as_completed(futs), 1):
            try:
                rows.append(fut.result())
                print(f"[{k}/{len(jobs)}] done {futs[fut]}", flush=True)
            except Exception as e:  # keep going; report at the end
                print(f"[{k}/{len(jobs)}] FAILED {futs[fut]}: {e}", flush=True)
            pd.DataFrame(rows).sort_values("run").to_csv(out, index=False)
    print("Summary written to", out)


if __name__ == "__main__":
    main()

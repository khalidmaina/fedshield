#!/usr/bin/env python3
"""Creates a SYNTHETIC host-window dataset with the same columns as the real one.

It is only for checking that the whole pipeline runs before real data exists.
Never report results from it in the thesis.

Usage:
    python scripts/make_synthetic.py                      # 12 hosts, 6 sessions
    python scripts/make_synthetic.py --sessions 3 --windows-per-session 360
Output: data/processed/synthetic_windows.csv
"""
import argparse
import os
import sys

import numpy as np
import pandas as pd

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, REPO)
from fedshield.features import FEATURES  # noqa: E402

HOSTS = [f"fs-{r}-{i}" for r in ("web", "db", "build", "dev") for i in (1, 2, 3)]
INTENSITY = {"fs-web-1": 2, "fs-web-2": 1, "fs-web-3": 3, "fs-db-1": 1, "fs-db-2": 2, "fs-db-3": 3,
             "fs-build-1": 1, "fs-build-2": 2, "fs-build-3": 1, "fs-dev-1": 2, "fs-dev-2": 1, "fs-dev-3": 3}
# mean event counts per 10-second window for intensity 1
BASE = {
    "web":   {"exec_count": 8, "open_count": 120, "open_write_count": 6, "open_etc": 10, "open_proc": 2,
              "conn_count": 8, "exit_count": 8, "open_tmp": 0.2},
    "db":    {"exec_count": 6, "open_count": 90, "open_write_count": 20, "open_etc": 6, "open_proc": 1,
              "conn_count": 0.1, "exit_count": 6, "open_tmp": 0.5},
    "build": {"exec_count": 25, "open_count": 400, "open_write_count": 15, "open_etc": 30, "open_proc": 4,
              "conn_count": 0.05, "exit_count": 25, "open_tmp": 6},
    "dev":   {"exec_count": 5, "open_count": 150, "open_write_count": 4, "open_etc": 12, "open_proc": 40,
              "conn_count": 0.1, "exit_count": 5, "open_tmp": 2},
}
ATTACK = {   # extra mean counts added during an attack window
    "beacon":      {"exec_count": 8, "net_tool_exec": 6, "shell_exec": 2, "conn_count": 6, "conn_uncommon_port": 6,
                    "open_tmp": 3, "open_write_count": 2},
    "cred_access": {"exec_count": 4, "open_count": 30, "open_etc": 8, "open_sensitive": 5},
    "miner":       {"exec_count": 2, "exec_from_tmp": 1, "open_tmp": 3, "conn_count": 1, "conn_uncommon_port": 1,
                    "net_tool_exec": 1},
    "persistence": {"exec_count": 3, "exec_from_tmp": 1, "open_write_count": 4, "cron_write": 1, "open_tmp": 2,
                    "open_etc": 2, "shell_exec": 1},
    "scan":        {"exec_count": 30, "net_tool_exec": 30, "conn_count": 30, "conn_uncommon_port": 25},
}
ATTACKS = list(ATTACK)


def window(rng, role, inten, attack):
    lam = {f: 0.0 for f in FEATURES}
    for k, v in BASE[role].items():
        lam[k] = v * inten
    if attack:
        for k, v in ATTACK[attack].items():
            lam[k] += v
    x = {f: int(rng.poisson(lam[f])) for f in FEATURES}
    x["shell_exec"] += int(rng.binomial(x["exec_count"], 0.3))
    x["exec_unique_paths"] = min(x["exec_count"], int(rng.poisson(3 + 0.3 * x["exec_count"])))
    x["open_unique_paths"] = min(x["open_count"], int(rng.poisson(0.4 * x["open_count"] + 1)))
    x["conn_unique_daddr"] = min(x["conn_count"], 1 + int(rng.poisson(0.2 * x["conn_count"]))) if x["conn_count"] else 0
    x["conn_unique_dport"] = (min(x["conn_count"], 1 + int(rng.poisson(0.3 * x["conn_uncommon_port"])))
                              if x["conn_count"] else 0)
    x["unique_comm"] = min(x["exec_count"] + 2, 2 + int(rng.poisson(0.5 * x["exec_count"])))
    return x


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--sessions", type=int, default=6)
    ap.add_argument("--windows-per-session", type=int, default=720, help="720 windows = 2 hours")
    ap.add_argument("--attack-windows", type=int, default=48, help="48 windows = 8 minutes")
    ap.add_argument("--seed", type=int, default=7)
    ap.add_argument("--out", default=os.path.join(REPO, "data", "processed", "synthetic_windows.csv"))
    args = ap.parse_args()
    rng = np.random.default_rng(args.seed)
    rows, t0, W = [], 1_700_000_000, 10
    for s in range(args.sessions):
        start = t0 + s * 86400
        usable = args.windows_per_session - args.attack_windows - 60
        for k, host in enumerate(HOSTS):
            role = host.split("-")[1]
            atk = ATTACKS[(k + s + 1) % len(ATTACKS)]
            a0 = 30 + int(k * usable / (len(HOSTS) - 1))
            for w in range(args.windows_per_session):
                is_atk = a0 <= w < a0 + args.attack_windows
                r = window(rng, role, INTENSITY[host], atk if is_atk else None)
                r.update({"host": host, "window_start": start + w * W, "window_sec": W,
                          "label": int(is_atk), "attack": atk if is_atk else ""})
                rows.append(r)
    df = pd.DataFrame(rows)[["host", "window_start", "window_sec"] + FEATURES + ["label", "attack"]]
    os.makedirs(os.path.dirname(args.out), exist_ok=True)
    df.to_csv(args.out, index=False)
    print(f"Wrote {len(df)} synthetic windows to {args.out}")


if __name__ == "__main__":
    main()

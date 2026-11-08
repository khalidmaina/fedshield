#!/usr/bin/env python3
"""Live detection: scores each new collector window and writes alerts for Wazuh.

Usage (venv active; the collector must be running in another terminal):
    python scripts/detect_live.py --artifacts results/<run>/artifacts
Replay mode (scores every window of a file at once, e.g. to measure alert volume):
    python scripts/detect_live.py --artifacts results/<run>/artifacts --replay data/features/features_20261104.jsonl

Alerts are JSON lines in /var/log/fedshield/alerts.json, which Wazuh reads.
Create that folder once:  sudo mkdir -p /var/log/fedshield && sudo chown $USER /var/log/fedshield
"""
import argparse
import glob
import json
import os
import sys
import time
import uuid

import joblib
import numpy as np
import torch

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, REPO)
from fedshield.data import scale  # noqa: E402
from fedshield.models import SAE, if_scores, sae_scores  # noqa: E402


class Scorer:
    def __init__(self, art):
        ck = torch.load(os.path.join(art, "global_sae.pt"), weights_only=False)
        self.feats, self.cap = ck["features"], ck["scale_cap"]
        self.model = SAE(ck["d"], ck["hidden"], ck["latent"])
        self.model.load_state_dict(ck["state_dict"])
        self.dets = {}
        for p in glob.glob(os.path.join(art, "detector_*.joblib")):
            host = os.path.basename(p)[len("detector_"):-len(".joblib")]
            self.dets[host] = joblib.load(p)
        if not self.dets:
            raise SystemExit("No detector_*.joblib files; run an experiment with save_artifacts=true")

    def score(self, row):
        det = self.dets.get(row["host"])
        if det is None:
            return None
        x = scale(np.array([[float(row[f]) for f in self.feats]]), self.cap)
        lo, hi = det["n_sae"]
        s_sae = (sae_scores(self.model, x)[0] - lo) / (hi - lo + 1e-12)
        lo, hi = det["n_if"]
        s_if = (if_scores(det["forest"], x)[0] - lo) / (hi - lo + 1e-12)
        s = det["alpha"] * s_sae + (1 - det["alpha"]) * s_if
        return float(s), float(det["thr"]["hybrid"])


def follow(path):
    """Yield new lines appended to a file (like tail -f)."""
    with open(path) as f:
        f.seek(0, os.SEEK_END)
        while True:
            line = f.readline()
            if line:
                yield line
            else:
                time.sleep(0.5)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--artifacts", required=True)
    ap.add_argument("--features", default=os.path.join(REPO, "data", "features"))
    ap.add_argument("--alerts", default="/var/log/fedshield/alerts.json")
    ap.add_argument("--replay", default=None, help="score all windows of this .jsonl file and exit")
    ap.add_argument("--verbose", action="store_true", help="print every score")
    args = ap.parse_args()
    sc = Scorer(args.artifacts)
    os.makedirs(os.path.dirname(args.alerts), exist_ok=True)
    out = open(args.alerts, "a", buffering=1)
    n_win = n_alert = 0

    def handle(line):
        nonlocal n_win, n_alert
        line = line.strip()
        if not line:
            return
        row = json.loads(line)
        res = sc.score(row)
        if res is None:
            return
        s, thr = res
        n_win += 1
        if args.verbose:
            print(f"{row['host']:<11} {row['window_start']}  score={s:.3f} thr={thr:.3f}")
        if s > thr:
            n_alert += 1
            alert = {"fedshield": {"type": "anomaly", "alert_id": uuid.uuid4().hex, "host": row["host"],
                                   "window_start": row["window_start"], "score": round(s, 4),
                                   "threshold": round(thr, 4), "detector": "hybrid",
                                   "emitted_at": round(time.time(), 3)}}
            out.write(json.dumps(alert) + "\n")
            print(f"ALERT {row['host']} window {row['window_start']} score {s:.3f} > {thr:.3f}", flush=True)

    if args.replay:
        with open(args.replay) as f:
            for line in f:
                handle(line)
        print(f"Replayed {n_win} windows, {n_alert} alerts ({100 * n_alert / max(1, n_win):.2f}%)")
        return
    today = os.path.join(args.features, f"features_{time.strftime('%Y%m%d')}.jsonl")
    while not os.path.exists(today):
        print("Waiting for", today, "(is the collector running?)")
        time.sleep(5)
    print("Watching", today, "- alerts go to", args.alerts, "(Ctrl+C to stop)")
    try:
        for line in follow(today):
            handle(line)
    except KeyboardInterrupt:
        print(f"\nStopped. {n_win} windows scored, {n_alert} alerts.")


if __name__ == "__main__":
    main()

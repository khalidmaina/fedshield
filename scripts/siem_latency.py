#!/usr/bin/env python3
"""Measures the delay from FedShield writing an alert to Wazuh raising it.

Run with sudo, because Wazuh's alert file is only readable by root:
    sudo .venv/bin/python scripts/siem_latency.py
Matches alerts by alert_id between /var/log/fedshield/alerts.json and
/var/ossec/logs/alerts/alerts.json (rule 100200). Writes results/siem/latency.json.
"""
import argparse
import json
import os
from datetime import datetime

import numpy as np

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--ours", default="/var/log/fedshield/alerts.json")
    ap.add_argument("--wazuh", default="/var/ossec/logs/alerts/alerts.json")
    ap.add_argument("--out", default=os.path.join(REPO, "results", "siem", "latency.json"))
    args = ap.parse_args()
    emitted = {}
    with open(args.ours) as f:
        for line in f:
            if line.strip():
                a = json.loads(line)["fedshield"]
                emitted[a["alert_id"]] = a["emitted_at"]
    delays, per_host = [], {}
    with open(args.wazuh) as f:
        for line in f:
            if '"100200"' not in line:
                continue
            w = json.loads(line)
            fs = w.get("data", {}).get("fedshield", {})
            aid = fs.get("alert_id")
            if aid in emitted:
                ts = datetime.strptime(w["timestamp"], "%Y-%m-%dT%H:%M:%S.%f%z").timestamp()
                delays.append(ts - float(emitted[aid]))
                per_host[fs.get("host")] = per_host.get(fs.get("host"), 0) + 1
    if not delays:
        raise SystemExit("No matching alerts found. Is the Wazuh rule loaded and detect_live.py running?")
    d = np.array(delays)
    res = {"matched_alerts": int(len(d)), "fedshield_alerts": len(emitted),
           "delay_sec_mean": float(d.mean()), "delay_sec_median": float(np.median(d)),
           "delay_sec_p95": float(np.quantile(d, 0.95)), "alerts_per_host": per_host}
    os.makedirs(os.path.dirname(args.out), exist_ok=True)
    with open(args.out, "w") as f:
        json.dump(res, f, indent=2)
    print(json.dumps(res, indent=2))


if __name__ == "__main__":
    main()

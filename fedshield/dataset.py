"""Join the collector's feature windows with the session records into one labelled dataset.

One row per host per 10-second window inside a recorded session, with the session's split
(decision 0003), the host's role, intensity and region, and a label:

- the attack's name if at least ``min_overlap`` (default half) of the window lies inside the
  attack as the host reported it (start/end measured inside the host);
- dropped as *ambiguous* if it overlaps an attack by less than that;
- dropped as *excluded* if it overlaps an attack that failed, never reported finishing, or whose
  request got no answer (we cannot know what ran, so it must not be called benign);
- "benign" otherwise. A rejected request started nothing, so its windows stay benign.

Standard library only.
"""
import hashlib

from .features import FEATURES
from .topology import INTENSITY, REGION_OF, role_of

COLUMNS = ("session", "split", "host", "role", "intensity", "region", "window_start", "label",
           "lost_events", *FEATURES)
UNFINISHED_GRACE_S = 60          # how long after its planned end an unfinished attack is assumed to run


def attack_spans(record):
    """{host: [(start, end, ok, attack)]} from one session record."""
    spans = {}
    for a in record["attacks"]:
        if a["event"] == "rejected":
            continue                                          # nothing ran
        if a["event"] == "started" and a.get("end_ts") is not None:
            span = (float(a["start_ts"]), float(a["end_ts"]), a.get("exit_code") == 0, a["attack"])
        else:                                                 # error, or started but never reported finishing
            start = float(a.get("start_ts") or a["planned_start_ts"])
            span = (start, start + a["seconds"] + UNFINISHED_GRACE_S, False, a["attack"])
        spans.setdefault(a["host"], []).append(span)
    return spans


def label_window(window_start, window_sec, spans, min_overlap=0.5):
    """'benign', an attack name, or ('drop', reason)."""
    w0, w1 = window_start, window_start + window_sec
    for start, end, ok, attack in spans:
        overlap = max(0.0, min(w1, end) - max(w0, start))
        if overlap <= 0:
            continue
        if not ok:
            return ("drop", "excluded")
        if overlap >= min_overlap * window_sec:
            return attack
        return ("drop", "ambiguous")
    return "benign"


def build(feature_rows, records, min_overlap=0.5, include_aborted=False):
    """Returns (rows, report). ``feature_rows``: collector rows; ``records``: session records."""
    seen, rows = set(), []
    report = {"sessions": [], "dropped": {"ambiguous": 0, "excluded": 0, "duplicate": 0}, "counts": {}}
    by_time = sorted(feature_rows, key=lambda r: r["window_start"])
    for rec in sorted(records, key=lambda r: r["session"]):
        if rec["status"] != "complete" and not include_aborted:
            report["sessions"].append({"session": rec["session"], "split": rec["split"], "skipped": rec["status"]})
            continue
        spans = attack_spans(rec)
        t0, t1 = rec["start_ts"], rec["end_ts"]
        per_host = {}
        for r in by_time:
            if r["window_start"] < t0 or r["window_start"] + r["window_sec"] > t1:
                continue
            key = (r["host"], r["window_start"])
            if key in seen:
                report["dropped"]["duplicate"] += 1
                continue
            seen.add(key)
            label = label_window(r["window_start"], r["window_sec"], spans.get(r["host"], []), min_overlap)
            if isinstance(label, tuple):
                report["dropped"][label[1]] += 1
                continue
            host = r["host"]
            per_host[host] = per_host.get(host, 0) + 1
            rows.append({"session": rec["session"], "split": rec["split"], "host": host, "role": role_of(host),
                         "intensity": INTENSITY.get(host), "region": REGION_OF.get(host),
                         "window_start": r["window_start"], "label": label,
                         "lost_events": r.get("lost_events", 0), **{k: r[k] for k in FEATURES}})
            split = report["counts"].setdefault(rec["split"], {})
            split[label] = split.get(label, 0) + 1
        wsec = by_time[0]["window_sec"] if by_time else 10
        expected = int((t1 - (-(-t0 // wsec)) * wsec) // wsec)       # complete windows inside the session
        report["sessions"].append({"session": rec["session"], "split": rec["split"], "start_ts": t0, "end_ts": t1,
                                   "expected_windows_per_host": expected, "windows_per_host": per_host})
    rows.sort(key=lambda r: (r["session"], r["host"], r["window_start"]))
    return rows, report


def sha256_of(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for block in iter(lambda: f.read(1 << 20), b""):
            h.update(block)
    return h.hexdigest()

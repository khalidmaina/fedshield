"""Labelling and building the dataset (fedshield/dataset.py)."""
from fedshield.dataset import COLUMNS, attack_spans, build, label_window
from fedshield.features import FEATURES

T0 = 1_800_000_000      # session start, clock-aligned


def att(host, attack, start, end, exit_code=0, event="started"):
    a = {"host": host, "attack": attack, "event": event, "seconds": int(end - start) if end is not None else 60,
         "planned_start_ts": T0 + start, "start_ts": T0 + start, "id": "x"}
    if event == "started" and end is not None:
        a.update(end_ts=T0 + end, exit_code=exit_code)
    return a


def record(attacks, session=1, split="train", status="complete", minutes=5):
    return {"session": session, "split": split, "status": status, "start_ts": T0, "end_ts": T0 + minutes * 60,
            "attacks": attacks}


def windows(hosts=("fs-web-1", "fs-db-1"), minutes=5, start=T0, **feat):
    rows = []
    for h in hosts:
        for i in range(minutes * 6):
            row = {"host": h, "window_start": start + 10 * i, "window_sec": 10, "lost_events": 0}
            row.update(dict.fromkeys(FEATURES, 1), **feat)
            rows.append(row)
    return rows


# ---------------------------------------------------------------- one window

def test_labels_by_overlap():
    spans = [(100.0, 160.0, True, "beacon")]
    assert label_window(110, 10, spans) == "beacon"            # fully inside
    assert label_window(95, 10, spans) == "beacon"             # 5 of 10 s inside: exactly half counts
    assert label_window(94, 10, spans) == ("drop", "ambiguous")  # 4 s inside
    assert label_window(160, 10, spans) == "benign"            # starts where the attack ends
    assert label_window(40, 10, spans) == "benign"


def test_windows_touching_a_failed_attack_are_excluded():
    spans = [(100.0, 160.0, False, "miner")]
    assert label_window(150, 10, spans) == ("drop", "excluded")
    assert label_window(165, 10, spans) == "benign"


def test_spans_rejected_errors_and_unfinished():
    rec = record([att("fs-web-1", "beacon", 60, 120),
                  att("fs-db-1", "scan", 60, None, event="rejected"),
                  {"host": "fs-web-1", "attack": "miner", "event": "error", "seconds": 60,
                   "planned_start_ts": T0 + 200, "start_ts": None, "id": None},
                  att("fs-db-1", "miner", 200, None)])                    # started, never reported finishing
    spans = attack_spans(rec)
    assert spans["fs-web-1"][0] == (T0 + 60, T0 + 120, True, "beacon")
    assert spans["fs-web-1"][1][2] is False and spans["fs-web-1"][1][1] == T0 + 200 + 60 + 60
    assert len(spans["fs-db-1"]) == 1 and spans["fs-db-1"][0][2] is False   # the rejected one is gone


# ---------------------------------------------------------------- whole dataset

def test_build_labels_splits_and_drops():
    rec = record([att("fs-web-1", "beacon", 60, 125)])           # 60..125 s: windows 60-110 inside, 120 has 5 s
    rows, rep = build(windows(), [rec])
    web = {r["window_start"] - T0: r["label"] for r in rows if r["host"] == "fs-web-1"}
    assert [web[t] for t in (50, 60, 110, 120, 130)] == ["benign", "beacon", "beacon", "beacon", "benign"]
    assert all(r["label"] == "benign" for r in rows if r["host"] == "fs-db-1")
    assert rep["counts"]["train"] == {"benign": 60 - 7, "beacon": 7}
    first = rows[0]
    assert set(first) == set(COLUMNS)
    assert (first["split"], first["role"], first["region"], first["intensity"]) == ("train", "db", "A", 1)


def test_windows_outside_sessions_duplicates_and_aborted_sessions():
    rows_in = windows(minutes=5) + windows(minutes=5, start=T0 + 3600)   # second batch: no session
    rows_in += windows(hosts=("fs-web-1",), minutes=1)                   # duplicates of the first minute
    rows, rep = build(rows_in, [record([])])
    assert len(rows) == 60 and rep["dropped"]["duplicate"] == 6
    rows, rep = build(windows(), [record([], status="aborted")])
    assert rows == [] and rep["sessions"][0]["skipped"] == "aborted"
    rows, _ = build(windows(), [record([], status="aborted")], include_aborted=True)
    assert len(rows) == 60


def test_expected_windows_per_host_are_reported():
    rows, rep = build(windows(hosts=("fs-web-1",), minutes=4), [record([], minutes=5)])
    s = rep["sessions"][0]
    assert s["expected_windows_per_host"] == 30 and s["windows_per_host"] == {"fs-web-1": 24}

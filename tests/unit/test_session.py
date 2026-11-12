"""The session runner (fedshield/session.py) with a fake clock and fake hosts: runs instantly."""
from fedshield.session import run_session, summarize


class FakeTestbed:
    """Hosts that start attacks immediately and finish them after the requested seconds."""

    def __init__(self, clock, reject=(), fail=(), silent=(), never_finish=()):
        self.clock, self.reject, self.fail, self.silent, self.never = clock, reject, fail, silent, never_finish
        self.status, self.calls, self.n = {}, [], 0

    def start(self, host, attack, seconds):
        self.calls.append((self.clock.t, host, attack, seconds))
        if host in self.silent:
            raise TimeoutError(f"{host} did not answer")
        self.n += 1
        rid = f"id{self.n}"
        if host in self.reject:
            rec = {"id": rid, "event": "rejected", "reason": "busy", "ts": self.clock.t}
        else:
            rec = {"id": rid, "event": "started", "attack": attack, "ts": self.clock.t + 0.2}
            if host not in self.never:
                self.status.setdefault(host, []).append(
                    {"id": rid, "event": "finished", "ts": self.clock.t + seconds + 1.5,
                     "exit_code": 1 if host in self.fail else 0})
        self.status.setdefault(host, []).append(rec)
        return rec

    def read(self, host):
        return [r for r in self.status.get(host, []) if r["ts"] <= self.clock.t]


class Clock:
    def __init__(self, t=1_800_000_000.0):
        self.t = t

    def __call__(self):
        return self.t

    def sleep(self, s):
        self.t += max(s, 0.001)


SCHEDULE = {"session": 2, "split": "train", "duration_min": 10, "attack_min": 1, "max_concurrent": 4,
            "attacks": [{"host": "fs-web-1", "attack": "beacon", "start_min": 1.0, "duration_min": 1, "slot": 0},
                        {"host": "fs-db-1", "attack": "scan", "start_min": 2.5, "duration_min": 1, "slot": 0},
                        {"host": "fs-web-1", "attack": "miner", "start_min": 6.0, "duration_min": 1, "slot": 1}]}


def run(**kw):
    clock = Clock()
    tb = FakeTestbed(clock, **kw)
    rec = run_session(SCHEDULE, start_fn=tb.start, status_fn=tb.read, clock=clock, sleep=clock.sleep,
                      log=lambda *_: None)
    return rec, tb, clock


def test_attacks_start_on_time_and_labels_use_the_host_reported_times():
    rec, tb, clock = run()
    t0 = rec["start_ts"]
    assert [round(t - t0) for t, *_ in tb.calls] == [60, 150, 360]
    assert [c[3] for c in tb.calls] == [60, 60, 60]                      # seconds per attack
    first = rec["attacks"][0]
    assert first["event"] == "started" and first["start_ts"] == round(t0 + 60, 3) + 0.2
    assert first["end_ts"] - first["start_ts"] >= 60 and first["exit_code"] == 0
    assert rec["status"] == "complete" and rec["end_ts"] == t0 + 600
    assert summarize(rec) == {"planned": 3, "started": 3, "ok": 3, "rejected": 0, "errors": 0, "failed": 0,
                              "unfinished": 0}


def test_rejections_errors_failures_and_missing_reports_are_recorded_not_hidden():
    rec, *_ = run(reject=("fs-db-1",), fail=("fs-web-1",))
    s = summarize(rec)
    assert s["rejected"] == 1 and s["failed"] == 2 and s["ok"] == 0
    rec, *_ = run(silent=("fs-db-1",), never_finish=("fs-web-1",))
    s = summarize(rec)
    assert s["errors"] == 1 and s["unfinished"] == 2
    assert next(a for a in rec["attacks"] if a["host"] == "fs-db-1")["reason"] == "fs-db-1 did not answer"


def test_stopping_early_marks_the_session_aborted():
    clock = Clock()
    tb = FakeTestbed(clock)
    stop_at = clock.t + 200                                               # after the 2nd attack started
    rec = run_session(SCHEDULE, start_fn=tb.start, status_fn=tb.read, clock=clock, sleep=clock.sleep,
                      log=lambda *_: None, should_stop=lambda: clock.t >= stop_at)
    assert rec["status"] == "aborted" and len(rec["attacks"]) == 2

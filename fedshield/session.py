"""Run one collection session: start every scheduled attack on time through the hosts' agents
and record what really happened, which becomes the session's labels.

The labels use the times the hosts report (``started``/``finished`` in status.jsonl), measured
inside the host on the same clock as the collector's windows, and keep each attack's exit code,
so an attack that failed or was rejected can be excluded instead of silently labelled.

Clock, sleep and the control functions are parameters, so tests can run a session instantly.
"""
import time

from . import control


def run_session(schedule, start_fn=control.start_attack, status_fn=control.read_status,
                clock=time.time, sleep=time.sleep, log=print, should_stop=lambda: False,
                finish_timeout=60.0):
    """Carry out ``schedule``; return the session record (metadata + one entry per attack)."""
    t0 = clock()
    t_end = t0 + schedule["duration_min"] * 60
    entries = []
    aborted = False

    def wait_until(t):
        while clock() < t:
            if should_stop():
                return False
            sleep(min(1.0, t - clock()))
        return True

    for att in sorted(schedule["attacks"], key=lambda a: (a["start_min"], a["host"])):
        planned = t0 + att["start_min"] * 60
        if not wait_until(planned):
            aborted = True
            break
        seconds = int(round(att["duration_min"] * 60))
        entry = {"host": att["host"], "attack": att["attack"], "slot": att.get("slot"),
                 "planned_start_ts": round(planned, 3), "seconds": seconds}
        try:
            rec = start_fn(att["host"], att["attack"], seconds)
            entry.update(id=rec.get("id"), event=rec["event"], start_ts=rec.get("ts"), reason=rec.get("reason"))
        except Exception as exc:                     # host did not answer, control folder missing, ...
            entry.update(id=None, event="error", start_ts=None, reason=str(exc))
        entries.append(entry)
        late = (clock() - planned)
        log(f"  {att['start_min']:6.2f} min  {att['host']:<11} {att['attack']:<12} {entry['event']}"
            + (f" ({entry['reason']})" if entry.get("reason") else "") + (f"  +{late:.1f} s" if late > 2 else ""))

    if not aborted and not wait_until(t_end):
        aborted = True

    # collect 'finished' reports for every attack that started
    deadline = clock() + finish_timeout
    while True:
        open_entries = [e for e in entries if e["event"] == "started" and "end_ts" not in e]
        for e in open_entries:
            for rec in status_fn(e["host"]):
                if rec.get("id") == e["id"] and rec.get("event") == "finished":
                    e["end_ts"], e["exit_code"] = rec.get("ts"), rec.get("exit_code")
        if not [e for e in entries if e["event"] == "started" and "end_ts" not in e] or clock() >= deadline:
            break
        sleep(1.0)

    return {"session": schedule["session"], "split": schedule["split"],
            "status": "aborted" if aborted else "complete",
            "start_ts": round(t0, 3), "end_ts": round(clock() if aborted else t_end, 3),
            "schedule": schedule, "attacks": entries}


def summarize(record):
    """Counts of what happened, for the end-of-session report."""
    e = record["attacks"]
    ok = [x for x in e if x["event"] == "started" and x.get("exit_code") == 0]
    return {"planned": len(record["schedule"]["attacks"]), "started": sum(x["event"] == "started" for x in e),
            "ok": len(ok), "rejected": sum(x["event"] == "rejected" for x in e),
            "errors": sum(x["event"] == "error" for x in e),
            "failed": sum(x["event"] == "started" and x.get("exit_code") not in (0, None) for x in e),
            "unfinished": sum(x["event"] == "started" and "end_ts" not in x for x in e)}

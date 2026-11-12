"""Feature extraction (fedshield/features.py): parsing, one window's counts, and windowing."""
import pytest

from fedshield.features import FEATURES, Window, Windower, parse_event, window_start

T0 = 1_800_000_000          # a clock-aligned wall time (multiple of 10)
OFFSET = T0 * 10**9         # makes bpftrace ns = 0 land on T0


def ev(line, offset=OFFSET):
    e = parse_event(line, offset)
    assert e is not None, line
    return e


def at(seconds, line_without_ns):
    """Insert a timestamp (seconds after T0) into a line like 'E|fs-web-1|bash|/bin/ls'."""
    kind, rest = line_without_ns.split("|", 1)
    return f"{kind}|{int(seconds * 1e9)}|{rest}"


# ---------------------------------------------------------------- parsing

def test_there_are_19_distinct_features():
    assert len(FEATURES) == 19 and len(set(FEATURES)) == 19


def test_each_line_type_parses():
    e = ev(at(1.5, "E|fs-web-1|bash|/usr/bin/curl"))
    assert (e["type"], e["host"], e["comm"], e["path"], e["ts"]) == ("exec", "fs-web-1", "bash", "/usr/bin/curl",
                                                                    T0 + 1.5)
    e = ev(at(0, "O|fs-db-1|577|sqlite3|/var/lib/appdb/app.db"))
    assert (e["type"], e["flags"], e["path"]) == ("open", 577, "/var/lib/appdb/app.db")
    e = ev(at(0, "C|fs-web-1|9000|curl|172.18.0.5"))
    assert (e["type"], e["dport"], e["daddr"]) == ("conn", 9000, "172.18.0.5")
    assert ev(at(0, "X|fs-web-1|curl"))["type"] == "exit"


def test_a_pipe_inside_a_path_stays_in_the_path():
    assert ev(at(0, "O|fs-dev-1|0|cat|/tmp/a|b.txt"))["path"] == "/tmp/a|b.txt"


@pytest.mark.parametrize("line", [
    "Attaching 4 probes...", "", "Lost 12 events",
    "E|notanumber|fs-web-1|bash|/bin/ls",       # bad timestamp
    "O|1|fs-web-1|rw|cat|/etc/x",               # bad flags
    "C|1|fs-web-1|9000|curl",                   # missing field
    "E|1|c2-server|python3|/bin/sh",            # not a monitored host
    "Z|1|fs-web-1|x",                           # unknown kind
])
def test_non_events_are_rejected(line):
    assert parse_event(line, OFFSET) is None


# ---------------------------------------------------------------- one window

def features_of(*lines):
    w = Window()
    for line in lines:
        w.add(ev(at(0, line)))
    return w.features()


def test_window_counts_attack_relevant_signals():
    f = features_of(
        "E|fs-web-1|bash|/tmp/.x/kworkerd",            # exec from /tmp
        "E|fs-web-1|bash|/usr/bin/curl",               # network tool
        "E|fs-web-1|agent.sh|/bin/bash",               # shell
        "E|fs-web-1|bash|/usr/bin/curl",               # same path again
        "O|fs-web-1|0|cat|/etc/shadow",                # sensitive, /etc
        "O|fs-web-1|577|sh|/etc/cron.d/updater",       # O_WRONLY|O_CREAT|O_TRUNC into cron
        "O|fs-web-1|0|cat|/root/.ssh/id_rsa",          # sensitive
        "O|fs-web-1|0|ps|/proc/1/stat",                # /proc
        "O|fs-web-1|1089|sh|/tmp/.c2out",              # write in /tmp (O_WRONLY|O_CREAT|O_APPEND)
        "C|fs-web-1|9000|curl|172.18.0.9",             # uncommon port
        "C|fs-web-1|8080|curl|172.18.0.9",             # common port, same address
        "C|fs-web-1|8080|curl|172.18.0.3",
        "X|fs-web-1|curl",
    )
    assert f["exec_count"] == 4 and f["exec_unique_paths"] == 3
    assert (f["exec_from_tmp"], f["net_tool_exec"], f["shell_exec"]) == (1, 2, 1)
    assert f["open_count"] == 5 and f["open_unique_paths"] == 5
    assert (f["open_etc"], f["open_sensitive"], f["open_proc"], f["open_tmp"]) == (2, 2, 1, 1)
    assert (f["open_write_count"], f["cron_write"]) == (2, 1)
    assert (f["conn_count"], f["conn_unique_daddr"], f["conn_unique_dport"], f["conn_uncommon_port"]) == (3, 2, 2, 1)
    assert f["exit_count"] == 1
    assert f["unique_comm"] == 6                   # bash, agent.sh, cat, sh, ps, curl
    assert set(f) == set(FEATURES)


def test_reading_passwd_or_cron_is_not_suspicious():
    f = features_of("O|fs-web-1|0|ls|/etc/passwd", "O|fs-web-1|0|cron|/etc/crontab")
    assert f["open_sensitive"] == 0 and f["cron_write"] == 0 and f["open_etc"] == 2


def test_an_empty_window_is_all_zeros():
    assert Window().features() == dict.fromkeys(FEATURES, 0)


# ---------------------------------------------------------------- windowing

def test_windows_are_aligned_to_the_clock():
    assert window_start(T0 + 19.99, 10) == T0 + 10
    assert window_start(T0 + 20.0, 10) == T0 + 20


def test_the_partial_first_window_is_skipped():
    w = Windower(start_time=T0 + 3)                        # started 3 s into a window
    assert not w.add(ev(at(5, "E|fs-web-1|bash|/bin/ls")))  # that window is incomplete
    assert w.add(ev(at(12, "E|fs-web-1|bash|/bin/ls")))
    assert w.early == 1
    rows = w.flush(T0 + 22.5)
    assert [(r["window_start"], r["exec_count"]) for r in rows] == [(T0 + 10, 1)]


def test_a_window_waits_for_its_grace_period_and_quiet_hosts_get_zero_rows():
    w = Windower(start_time=T0, grace_sec=2)
    w.add(ev(at(1, "E|fs-web-1|bash|/bin/ls")))
    w.add(ev(at(2, "E|fs-db-1|bash|/bin/ls")))
    w.add(ev(at(11, "E|fs-web-1|bash|/bin/ls")))           # db-1 quiet in the second window
    assert w.flush(T0 + 11.5) == []                        # first window ended, grace not over
    first = w.flush(T0 + 12)
    assert [r["host"] for r in first] == ["fs-db-1", "fs-web-1"]
    second = w.flush(T0 + 22)
    assert {r["host"]: r["exec_count"] for r in second} == {"fs-db-1": 0, "fs-web-1": 1}


def test_events_for_an_already_written_window_are_dropped_and_counted():
    w = Windower(start_time=T0)
    w.add(ev(at(1, "E|fs-web-1|bash|/bin/ls")))
    w.flush(T0 + 13)
    assert not w.add(ev(at(9, "E|fs-web-1|bash|/bin/ls")))
    assert w.late == 1


def test_lost_events_are_reported_in_the_window_where_they_were_noticed():
    w = Windower(start_time=T0)
    w.add(ev(at(1, "E|fs-web-1|bash|/bin/ls")))
    w.add(ev(at(1, "E|fs-db-1|bash|/bin/ls")))
    w.note_lost(7, now=T0 + 4)
    w.add(ev(at(12, "E|fs-web-1|bash|/bin/ls")))
    rows = w.flush(T0 + 22)
    assert {(r["window_start"], r["lost_events"]) for r in rows} == {(T0, 7), (T0 + 10, 0)}


def test_final_flush_writes_ended_windows_without_waiting_but_not_the_running_one():
    w = Windower(start_time=T0)
    w.add(ev(at(1, "E|fs-web-1|bash|/bin/ls")))
    w.add(ev(at(15, "E|fs-web-1|bash|/bin/ls")))
    rows = w.flush(T0 + 10.5, final=True)                  # stopped half a second into window 2
    assert [r["window_start"] for r in rows] == [T0]


def test_rows_hold_counts_only():
    w = Windower(start_time=T0)
    w.add(ev(at(1, "O|fs-web-1|0|cat|/etc/shadow")))
    w.add(ev(at(1, "C|fs-web-1|9000|curl|172.18.0.9")))
    (row,) = w.flush(T0 + 12)
    assert set(row) == {"host", "window_start", "window_sec", "lost_events", *FEATURES}
    assert all(isinstance(row[k], int) for k in FEATURES)
    assert "/etc/shadow" not in str(row) and "172.18.0.9" not in str(row) and "curl" not in str(row)

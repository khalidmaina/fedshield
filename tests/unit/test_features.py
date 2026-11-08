"""Collector side: parsing bpftrace lines and building 10-second windows."""
from fedshield.features import FEATURES, Window, WindowAggregator, parse_bpftrace_line

OFFSET = 1_700_000_000 * 10**9  # monotonic -> wall-clock offset used by the collector


def ev(line):
    e = parse_bpftrace_line(line, OFFSET)
    assert e is not None, line
    return e


def test_there_are_19_features():
    assert len(FEATURES) == 19
    assert len(set(FEATURES)) == 19


def test_parse_each_event_type():
    e = ev("EXEC|5000000000|fs-web-1|10|9|0|bash|/usr/bin/curl")
    assert (e["type"], e["host"], e["path"], e["ppid"]) == ("exec", "fs-web-1", "/usr/bin/curl", 9)
    assert e["ts"] == 1_700_000_005.0
    e = ev("OPEN|5000000000|fs-db-1|10|0|0|sqlite3|/var/lib/appdb/app.db|66")
    assert (e["type"], e["flags"]) == ("open", 66)
    e = ev("CONN|5000000000|fs-web-1|10|0|0|curl|172.18.0.5|9000")
    assert (e["type"], e["daddr"], e["dport"]) == ("conn", "172.18.0.5", 9000)
    e = ev("EXIT|5000000000|fs-web-1|10|0|0|curl")
    assert e["type"] == "exit"


def test_path_with_pipe_character_is_kept_whole():
    e = ev("OPEN|1|fs-dev-1|1|0|0|cat|/tmp/a|b.txt|0")
    assert e["path"] == "/tmp/a|b.txt" and e["flags"] == 0


def test_malformed_and_unknown_lines_return_none():
    assert parse_bpftrace_line("Attaching 4 probes...", OFFSET) is None
    assert parse_bpftrace_line("EXEC|notanumber|fs-web-1|1|1|0|sh|/bin/sh", OFFSET) is None


def test_window_counts_attack_relevant_signals():
    w = Window()
    for line in [
        "EXEC|1|fs-web-1|1|1|0|bash|/tmp/.x/kworkerd",        # exec from /tmp
        "EXEC|1|fs-web-1|1|1|0|bash|/usr/bin/curl",           # network tool
        "EXEC|1|fs-web-1|1|1|0|bash|/bin/sh",                 # shell
        "OPEN|1|fs-web-1|1|0|0|cat|/etc/shadow|0",            # sensitive + /etc
        "OPEN|1|fs-web-1|1|0|0|sh|/etc/cron.d/updater|577",   # write to cron (O_WRONLY|O_CREAT|O_TRUNC)
        "CONN|1|fs-web-1|1|0|0|nc|172.18.0.9|3333",           # uncommon port
        "CONN|1|fs-web-1|1|0|0|curl|172.18.0.9|8080",         # common port
        "EXIT|1|fs-web-1|1|0|0|curl",
    ]:
        w.add(ev(line))
    c = w.finish()
    assert c["exec_count"] == 3 and c["exec_from_tmp"] == 1
    assert c["net_tool_exec"] == 1 and c["shell_exec"] == 1
    assert c["open_sensitive"] == 1 and c["open_etc"] == 2 and c["cron_write"] == 1
    assert c["open_write_count"] == 1
    assert c["conn_count"] == 2 and c["conn_uncommon_port"] == 1
    assert c["conn_unique_daddr"] == 1 and c["conn_unique_dport"] == 2
    assert c["exit_count"] == 1
    assert set(c) == set(FEATURES)


def test_etc_passwd_is_not_sensitive():
    w = Window()
    w.add(ev("OPEN|1|fs-web-1|1|0|0|ls|/etc/passwd|0"))
    assert w.finish()["open_sensitive"] == 0


def test_aggregator_emits_closed_windows_and_zero_rows_for_quiet_hosts():
    agg = WindowAggregator(window_sec=10, grace_sec=2)
    agg.add(ev("EXEC|1000000000|fs-web-1|1|1|0|bash|/bin/ls"))    # t = ...001 s -> window ...000
    agg.add(ev("EXEC|1000000000|fs-db-1|1|1|0|bash|/bin/ls"))
    agg.add(ev("EXEC|15000000000|fs-web-1|1|1|0|bash|/bin/ls"))   # next window, web only
    t0 = 1_700_000_000
    assert agg.flush(t0 + 11) == []                                # first window still inside its grace period
    rows = agg.flush(t0 + 22)                                      # both windows closed
    by = {(r["host"], r["window_start"]): r for r in rows}
    assert by[("fs-web-1", t0)]["exec_count"] == 1
    assert by[("fs-db-1", t0 + 10)]["exec_count"] == 0             # quiet host still gets a row
    assert by[("fs-web-1", t0 + 10)]["exec_count"] == 1


def test_late_event_for_an_emitted_window_is_dropped():
    agg = WindowAggregator(window_sec=10, grace_sec=2)
    agg.add(ev("EXEC|1000000000|fs-web-1|1|1|0|bash|/bin/ls"))
    agg.flush(1_700_000_000 + 13)
    agg.add(ev("EXEC|2000000000|fs-web-1|1|1|0|bash|/bin/ls"))   # belongs to the emitted window
    rows = agg.flush(1_700_000_000 + 23)
    assert all(r["exec_count"] == 0 for r in rows)

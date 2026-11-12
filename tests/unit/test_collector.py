"""collector/collector.py end to end, with a fake bpftrace so CI needs neither root nor eBPF.

The fake prints the same line format as collector/fedshield.bt, with real monotonic
timestamps, plus one "Lost N events" line, like bpftrace does when its buffer overflows.
"""
import glob
import json
import os
import subprocess
import sys

from fedshield.features import FEATURES

from .conftest import REPO

COLLECTOR = os.path.join(REPO, "collector", "collector.py")

FAKE_BPFTRACE = r'''#!{python}
import sys, time
if "--version" in sys.argv:
    print("bpftrace {version}")
    sys.exit(0)
print("Attaching 4 probes...", flush=True)
end = time.monotonic() + {seconds}
lost_sent = False
while time.monotonic() < end:
    ns = time.monotonic_ns()
    print(f"E|{{ns}}|fs-web-1|bash|/usr/bin/curl")
    print(f"C|{{ns}}|fs-web-1|9000|curl|172.18.0.9")
    print(f"O|{{ns}}|fs-db-1|0|cat|/etc/shadow")
    print(f"X|{{ns}}|fs-db-1|cat")
    if not lost_sent and time.monotonic() > end - {seconds} / 2:
        print("Lost 5 events")
        lost_sent = True
    sys.stdout.flush()
    time.sleep(0.1)
print("", flush=True)                                     # bpftrace prints a blank line at exit
'''


def fake_bpftrace(tmp_path, version="v0.20.2", seconds=12):
    fake = tmp_path / "bpftrace"
    fake.write_text(FAKE_BPFTRACE.format(python=sys.executable, seconds=seconds, version=version))
    fake.chmod(0o755)
    return str(fake)


def run_collector(bpftrace, out, duration):
    return subprocess.run([sys.executable, COLLECTOR, "--allow-non-root", "--no-bpf-stats", "--bpftrace", bpftrace,
                           "--window", "2", "--grace", "0.5", "--duration", str(duration), "--out", str(out)],
                          capture_output=True, text=True, timeout=60)


def test_collector_writes_complete_windows_with_counts_only(tmp_path):
    out = tmp_path / "features"
    r = run_collector(fake_bpftrace(tmp_path), out, duration=9)
    assert r.returncode == 0, r.stdout + r.stderr
    assert " 0 malformed" in r.stdout, r.stdout                # the banner and blank line are not errors
    assert "WARNING" not in r.stderr                            # the tested bpftrace version

    (features_file,) = glob.glob(str(out / "features_*.jsonl"))
    rows = [json.loads(line) for line in open(features_file)]
    starts = sorted({row["window_start"] for row in rows})
    assert len(starts) >= 3
    assert all(b - a == 2 for a, b in zip(starts, starts[1:]))  # consecutive 2 s windows, no gaps
    assert {row["host"] for row in rows} == {"fs-web-1", "fs-db-1"}

    web = [row for row in rows if row["host"] == "fs-web-1"]
    db = [row for row in rows if row["host"] == "fs-db-1"]
    assert all(row["exec_count"] >= 15 and row["net_tool_exec"] == row["exec_count"] for row in web)
    assert all(row["conn_uncommon_port"] == row["conn_count"] > 0 for row in web)
    assert all(row["open_sensitive"] == row["open_count"] > 0 and row["exit_count"] > 0 for row in db)
    assert sum(row["lost_events"] for row in rows if row["host"] == "fs-web-1") == 5

    text = open(features_file).read() + open(out / "collector_stats.jsonl").read()
    for raw in ("/etc/shadow", "/usr/bin/curl", "172.18.0.9", "curl"):
        assert raw not in text, f"raw value {raw!r} reached disk"
    assert set(rows[0]) == {"host", "window_start", "window_sec", "lost_events", *FEATURES}

    stats = [json.loads(line) for line in open(out / "collector_stats.jsonl")]
    start, windows, stop = stats[0], [s for s in stats if s["event"] == "window"], stats[-1]
    assert start["event"] == "start" and start["bpftrace"] == "v0.20.2"          # toolchain recorded per session
    assert {"kernel", "os", "python", "window_sec"} <= set(start)
    assert sum(s["lost"] for s in windows) == 5 and sum(s["malformed"] for s in windows) == 0
    assert {"collector_cpu_s", "bpftrace_cpu_s", "bpf_run_s", "bpf_runs"} <= set(windows[0])
    assert stop["event"] == "stop" and stop["lost"] == 5 and stop["windows"] == len(starts)


def test_collector_warns_about_an_untested_bpftrace_version(tmp_path):
    r = run_collector(fake_bpftrace(tmp_path, version="v0.14.0", seconds=4), tmp_path / "f", duration=3)
    assert "WARNING: bpftrace v0.14.0" in r.stderr and "install_bpftrace.sh" in r.stderr


def test_collector_explains_a_missing_bpftrace(tmp_path):
    r = run_collector(str(tmp_path / "no-such-bpftrace"), tmp_path / "f", duration=3)
    assert r.returncode != 0 and "bpftrace is not installed" in r.stderr and "Traceback" not in r.stderr


def test_collector_refuses_to_run_without_root():
    if os.geteuid() == 0:
        return                                                  # nothing to check when tests run as root
    r = subprocess.run([sys.executable, COLLECTOR, "--duration", "1"], capture_output=True, text=True, timeout=30)
    assert r.returncode != 0 and "sudo" in r.stderr

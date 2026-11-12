"""From eBPF event lines to 10-second feature windows, one row per host per window.

Standard library only: the collector imports this while running as root with the system
Python, outside the project's virtual environment.

Raw values (paths, addresses, command names) live only inside an open ``Window`` and are
reduced to counts when the window closes. Rows contain counts and nothing else.
"""
import os

FEATURES = (
    # programs started
    "exec_count", "exec_unique_paths", "exec_from_tmp", "shell_exec", "net_tool_exec",
    # files opened
    "open_count", "open_write_count", "open_etc", "open_sensitive", "open_tmp",
    "open_proc", "open_unique_paths", "cron_write",
    # outgoing TCP connections
    "conn_count", "conn_unique_daddr", "conn_unique_dport", "conn_uncommon_port",
    # process exits and distinct command names
    "exit_count", "unique_comm",
)

SHELLS = frozenset({"sh", "bash", "dash", "zsh"})
NET_TOOLS = frozenset({"curl", "wget", "nc", "ncat", "netcat", "ssh", "scp", "socat", "nmap"})
COMMON_PORTS = frozenset({22, 53, 80, 443, 3306, 5432, 8080})
TMP_PREFIXES = ("/tmp/", "/dev/shm/", "/var/tmp/")
# /etc/passwd is deliberately absent: ordinary tools (ls -l, ps, curl) read it constantly.
SENSITIVE = ("/etc/shadow", "/etc/gshadow", "/etc/sudoers", "/root/.ssh/", "id_rsa", "id_ed25519")
CRON_PREFIXES = ("/etc/cron", "/var/spool/cron", "/etc/crontab")
# open(2) flags that mean "this open can change the file"
O_WRONLY, O_RDWR, O_CREAT, O_TRUNC, O_APPEND = 0o1, 0o2, 0o100, 0o1000, 0o2000
WRITE_FLAGS = O_WRONLY | O_RDWR | O_CREAT | O_TRUNC | O_APPEND


def parse_event(line, ns_offset):
    """One line from collector/fedshield.bt -> event dict, or None if it is not a valid event.

    ``ns_offset`` converts bpftrace's monotonic nanoseconds to wall-clock nanoseconds.
    """
    line = line.rstrip("\n")
    kind = line[:2]
    try:
        if kind == "E|":
            _, ns, host, comm, path = line.split("|", 4)
            ev = {"type": "exec", "comm": comm, "path": path}
        elif kind == "O|":
            _, ns, host, flags, comm, path = line.split("|", 5)
            ev = {"type": "open", "flags": int(flags), "comm": comm, "path": path}
        elif kind == "C|":
            _, ns, host, dport, comm, daddr = line.split("|", 5)
            ev = {"type": "conn", "dport": int(dport), "comm": comm, "daddr": daddr}
        elif kind == "X|":
            _, ns, host, comm = line.split("|", 3)
            ev = {"type": "exit", "comm": comm}
        else:
            return None
        ev["ts"] = (int(ns) + ns_offset) / 1e9
    except ValueError:
        return None
    if not host.startswith("fs-"):
        return None
    ev["host"] = host
    return ev


class Window:
    """Everything one host did in one window, reduced to the 19 features by ``features()``."""

    def __init__(self):
        self.n = dict.fromkeys(FEATURES, 0)
        self.exec_paths, self.open_paths = set(), set()
        self.daddrs, self.dports, self.comms = set(), set(), set()

    def add(self, ev):
        n = self.n
        self.comms.add(ev["comm"])
        t = ev["type"]
        if t == "open":                                   # by far the most frequent (~94%)
            path, flags = ev["path"], ev["flags"]
            n["open_count"] += 1
            self.open_paths.add(path)
            writes = bool(flags & WRITE_FLAGS)
            n["open_write_count"] += writes
            n["open_etc"] += path.startswith("/etc/")
            n["open_sensitive"] += any(s in path for s in SENSITIVE)
            n["open_tmp"] += path.startswith(TMP_PREFIXES)
            n["open_proc"] += path.startswith("/proc/")
            n["cron_write"] += writes and path.startswith(CRON_PREFIXES)
        elif t == "exec":
            path = ev["path"]
            name = os.path.basename(path)
            n["exec_count"] += 1
            self.exec_paths.add(path)
            n["exec_from_tmp"] += path.startswith(TMP_PREFIXES)
            n["shell_exec"] += name in SHELLS
            n["net_tool_exec"] += name in NET_TOOLS
        elif t == "conn":
            n["conn_count"] += 1
            self.daddrs.add(ev["daddr"])
            self.dports.add(ev["dport"])
            n["conn_uncommon_port"] += ev["dport"] not in COMMON_PORTS
        elif t == "exit":
            n["exit_count"] += 1

    def features(self):
        out = dict(self.n)
        out["exec_unique_paths"] = len(self.exec_paths)
        out["open_unique_paths"] = len(self.open_paths)
        out["conn_unique_daddr"] = len(self.daddrs)
        out["conn_unique_dport"] = len(self.dports)
        out["unique_comm"] = len(self.comms)
        return out


def window_start(ts, window_sec):
    """Start of the window containing ``ts``. Windows are aligned to the clock (…:00, …:10, …)."""
    return int(ts // window_sec) * window_sec


class Windower:
    """Groups events into clock-aligned windows per host and hands out finished rows.

    - Only complete windows are emitted: the window that was already running when the
      collector started is skipped, and so is the one still running when it stops.
    - A window is emitted ``grace_sec`` after it ends, so late lines still in the pipe count.
      Events that arrive after their window was emitted are dropped and counted in ``late``.
    - Every host seen in the last ``host_ttl_sec`` gets a row, all zeros if it was quiet.
    - Events the kernel dropped ("Lost N events") are charged to the window in which the
      message arrived and reported in that window's rows as ``lost_events``.
    """

    def __init__(self, start_time, window_sec=10, grace_sec=2.0, host_ttl_sec=600):
        self.w, self.grace, self.ttl = window_sec, grace_sec, host_ttl_sec
        first = window_start(start_time, window_sec)
        self.first = first if first == start_time else first + window_sec      # first complete window
        self.next_emit = self.first
        self.open = {}          # (host, window_start) -> Window
        self.last_seen = {}     # host -> time of its latest event
        self.lost = {}          # window_start -> events the kernel dropped
        self.events = {}        # window_start -> events accepted
        self.late = 0           # events that arrived after their window was emitted
        self.early = 0          # events from the partial window before the first complete one

    def add(self, ev):
        ws = window_start(ev["ts"], self.w)
        if ws < self.first:
            self.early += 1                  # partial window from before the collector started
            return False
        if ws < self.next_emit:
            self.late += 1                   # its window was already written
            return False
        host = ev["host"]
        self.last_seen[host] = max(ev["ts"], self.last_seen.get(host, 0.0))
        win = self.open.get((host, ws))
        if win is None:
            win = self.open[(host, ws)] = Window()
        win.add(ev)
        self.events[ws] = self.events.get(ws, 0) + 1
        return True

    def note_lost(self, count, now):
        ws = max(window_start(now, self.w), self.next_emit)
        self.lost[ws] = self.lost.get(ws, 0) + count

    def flush(self, now, final=False):
        """Rows for every window that has ended (and whose grace period is over, unless final)."""
        rows = []
        wait = 0 if final else self.grace
        while self.next_emit + self.w + wait <= now:
            ws, end = self.next_emit, self.next_emit + self.w
            active = {h for h, t in self.last_seen.items() if end - t <= self.ttl}
            active |= {h for (h, s) in self.open if s == ws}
            for host in sorted(active):
                win = self.open.pop((host, ws), None)
                row = {"host": host, "window_start": ws, "window_sec": self.w}
                row.update(win.features() if win else dict.fromkeys(FEATURES, 0))
                row["lost_events"] = self.lost.get(ws, 0)
                rows.append(row)
            self.lost.pop(ws, None)
            self.events.pop(ws, None)
            self.next_emit = end
        return rows

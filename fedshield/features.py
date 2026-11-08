"""Window-level feature extraction from eBPF events.

This module uses only the Python standard library, so the collector can import it
when it runs with the system Python under sudo.
"""
import os

FEATURES = [
    "exec_count", "exec_unique_paths", "exec_from_tmp", "shell_exec", "net_tool_exec",
    "open_count", "open_write_count", "open_etc", "open_sensitive", "open_tmp",
    "open_proc", "open_unique_paths", "cron_write",
    "conn_count", "conn_unique_daddr", "conn_unique_dport", "conn_uncommon_port",
    "exit_count", "unique_comm",
]

SHELLS = {"sh", "bash", "dash", "zsh"}
NET_TOOLS = {"curl", "wget", "nc", "ncat", "netcat", "ssh", "scp", "socat", "nmap"}
COMMON_PORTS = {22, 53, 80, 443, 3306, 5432, 8080}
TMP_PREFIXES = ("/tmp/", "/dev/shm/", "/var/tmp/")
# /etc/passwd is not listed: ordinary programs (curl, ls -l, ps) read it all the time.
SENSITIVE = ("/etc/shadow", "/etc/gshadow", "/etc/sudoers", "/root/.ssh", "id_rsa")
CRON = ("/etc/cron", "/var/spool/cron", "/etc/crontab")
# O_WRONLY=1, O_RDWR=2, O_CREAT=64, O_TRUNC=512, O_APPEND=1024
WRITE_FLAGS = 1 | 2 | 64 | 512 | 1024


class Window:
    """Counters for one host in one time window."""

    def __init__(self):
        self.c = dict.fromkeys(FEATURES, 0)
        self.exec_paths, self.open_paths = set(), set()
        self.daddrs, self.dports, self.comms = set(), set(), set()

    def add(self, ev):
        t, comm = ev["type"], ev.get("comm", "")
        self.comms.add(comm)
        if t == "exec":
            path = ev.get("path", "")
            base = os.path.basename(path)
            self.c["exec_count"] += 1
            self.exec_paths.add(path)
            if path.startswith(TMP_PREFIXES):
                self.c["exec_from_tmp"] += 1
            if base in SHELLS:
                self.c["shell_exec"] += 1
            if base in NET_TOOLS:
                self.c["net_tool_exec"] += 1
        elif t == "open":
            path, flags = ev.get("path", ""), int(ev.get("flags", 0))
            self.c["open_count"] += 1
            self.open_paths.add(path)
            is_write = bool(flags & WRITE_FLAGS)
            if is_write:
                self.c["open_write_count"] += 1
            if path.startswith("/etc/"):
                self.c["open_etc"] += 1
            if any(s in path for s in SENSITIVE):
                self.c["open_sensitive"] += 1
            if path.startswith(TMP_PREFIXES):
                self.c["open_tmp"] += 1
            if path.startswith("/proc/"):
                self.c["open_proc"] += 1
            if is_write and path.startswith(CRON):
                self.c["cron_write"] += 1
        elif t == "conn":
            port = int(ev.get("dport", 0))
            self.c["conn_count"] += 1
            self.daddrs.add(ev.get("daddr", ""))
            self.dports.add(port)
            if port not in COMMON_PORTS:
                self.c["conn_uncommon_port"] += 1
        elif t == "exit":
            self.c["exit_count"] += 1

    def finish(self):
        c = dict(self.c)
        c["exec_unique_paths"] = len(self.exec_paths)
        c["open_unique_paths"] = len(self.open_paths)
        c["conn_unique_daddr"] = len(self.daddrs)
        c["conn_unique_dport"] = len(self.dports)
        c["unique_comm"] = len(self.comms)
        return c


class WindowAggregator:
    """Collects events into fixed windows per host and emits closed windows.

    A host that was seen recently but had no events in a closed window is emitted
    with all-zero features, so every host has a continuous series of windows.
    """

    def __init__(self, window_sec=10, grace_sec=2, host_ttl_sec=600):
        self.w, self.grace, self.ttl = window_sec, grace_sec, host_ttl_sec
        self.open = {}          # (host, window_start) -> Window
        self.last_seen = {}     # host -> wall time of last event
        self.next_emit = None   # window_start of the next window to emit

    def add(self, ev):
        ws = int(ev["ts"] // self.w) * self.w
        if self.next_emit is not None and ws < self.next_emit:
            return  # event arrived after its window was already emitted; drop it
        host = ev["host"]
        self.last_seen[host] = ev["ts"]
        win = self.open.get((host, ws))
        if win is None:
            win = self.open[(host, ws)] = Window()
        win.add(ev)
        if self.next_emit is None:
            self.next_emit = ws

    def flush(self, now):
        """Return a list of finished rows for all windows that ended before now - grace."""
        rows = []
        if self.next_emit is None:
            return rows
        while self.next_emit + self.w + self.grace <= now:
            ws = self.next_emit
            hosts = [h for h, t in self.last_seen.items() if now - t <= self.ttl]
            for h in sorted(set(hosts) | {h for (h, s) in self.open if s == ws}):
                win = self.open.pop((h, ws), None)
                feats = win.finish() if win else dict.fromkeys(FEATURES, 0)
                row = {"host": h, "window_start": ws, "window_sec": self.w}
                row.update(feats)
                rows.append(row)
            self.next_emit += self.w
        return rows


def parse_bpftrace_line(line, ns_offset):
    """Parse one line printed by collector/fedshield.bt. Returns a dict or None."""
    line = line.rstrip("\n")
    try:
        if line.startswith("EXEC|"):
            t, ns, host, pid, ppid, uid, comm, path = line.split("|", 7)
            return {"type": "exec", "ts": (int(ns) + ns_offset) / 1e9, "host": host, "pid": int(pid),
                    "ppid": int(ppid), "uid": int(uid), "comm": comm, "path": path}
        if line.startswith("OPEN|"):
            head, flags = line.rsplit("|", 1)
            t, ns, host, pid, ppid, uid, comm, path = head.split("|", 7)
            return {"type": "open", "ts": (int(ns) + ns_offset) / 1e9, "host": host, "pid": int(pid),
                    "uid": int(uid), "comm": comm, "path": path, "flags": int(flags)}
        if line.startswith("CONN|"):
            t, ns, host, pid, ppid, uid, comm, daddr, dport = line.split("|")
            return {"type": "conn", "ts": (int(ns) + ns_offset) / 1e9, "host": host, "pid": int(pid),
                    "uid": int(uid), "comm": comm, "daddr": daddr, "dport": int(dport)}
        if line.startswith("EXIT|"):
            t, ns, host, pid, ppid, uid, comm = line.split("|", 6)
            return {"type": "exit", "ts": (int(ns) + ns_offset) / 1e9, "host": host, "pid": int(pid),
                    "uid": int(uid), "comm": comm}
    except ValueError:
        return None
    return None

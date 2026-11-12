"""Host-side control of the testbed: ask a host to start an attack and read what it reports.

The protocol is two files per host in ``testbed/control/<host>/`` (mounted at ``/control``):

``request``       written here: one line ``<id> <attack> <seconds>``. Written to a temporary
                  file and renamed, so the host never reads half a request.
``status.jsonl``  written by the host's agent (testbed/host/agent.sh): one JSON object per line,
                  ``event`` = ``started`` | ``finished`` | ``rejected``, with wall-clock ``ts``
                  taken inside the host and, for ``finished``, the attack's ``exit_code``.

Only the standard library is used, so this works anywhere Python runs.
"""
import json
import os
import time
import uuid

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CONTROL_DIR = os.path.join(REPO, "testbed", "control")

ROLES = ("web", "db", "build", "dev")
HOSTS = tuple(f"fs-{role}-{i}" for role in ROLES for i in (1, 2, 3))
ATTACKS = ("beacon", "cred_access", "miner", "persistence", "scan")
MAX_SECONDS = 3600


def _host_dir(host, control_dir):
    if host not in HOSTS:
        raise ValueError(f"Unknown host {host!r}. Hosts: {', '.join(HOSTS)}")
    return os.path.join(control_dir or CONTROL_DIR, host)


def request_attack(host, attack, seconds, control_dir=None):
    """Write an attack request for ``host`` and return its id."""
    if attack not in ATTACKS:
        raise ValueError(f"Unknown attack {attack!r}. Attacks: {', '.join(ATTACKS)}")
    if not isinstance(seconds, int) or not 1 <= seconds <= MAX_SECONDS:
        raise ValueError(f"seconds must be a whole number from 1 to {MAX_SECONDS}, got {seconds!r}")
    d = _host_dir(host, control_dir)
    if not os.path.isdir(d):
        raise FileNotFoundError(f"{d} does not exist. Is the testbed running? (make testbed-up)")
    if not os.access(d, os.W_OK):
        raise PermissionError(f"Cannot write to {d}. It must belong to you: run 'make testbed-up', which "
                              f"creates testbed/control/ before Docker does.")
    req_id = uuid.uuid4().hex[:12]
    tmp = os.path.join(d, f".request.{req_id}")
    with open(tmp, "w") as f:
        f.write(f"{req_id} {attack} {seconds}\n")
    os.replace(tmp, os.path.join(d, "request"))
    return req_id


def clear_request(host, control_dir=None):
    """Remove a handled request, so the agent stops re-reading it."""
    try:
        os.remove(os.path.join(_host_dir(host, control_dir), "request"))
    except FileNotFoundError:
        pass


def _status_lines(host, control_dir):
    """(readable records, unreadable raw lines) from a host's status.jsonl."""
    path = os.path.join(_host_dir(host, control_dir), "status.jsonl")
    good, bad = [], []
    try:
        with open(path) as f:
            for line in f:
                try:
                    good.append(json.loads(line))
                except json.JSONDecodeError:
                    bad.append(line.rstrip("\n"))
    except FileNotFoundError:
        pass
    return good, bad


def read_status(host, control_dir=None):
    """All status lines a host has reported, oldest first. Malformed lines are skipped."""
    return _status_lines(host, control_dir)[0]


def wait_for(host, req_id, events=("started", "rejected"), timeout=10.0, poll=0.2, control_dir=None):
    """Wait until ``host`` reports one of ``events`` for ``req_id``; return that line or None."""
    deadline = time.monotonic() + timeout
    while True:
        for rec in read_status(host, control_dir):
            if rec.get("id") == req_id and rec.get("event") in events:
                return rec
        if time.monotonic() >= deadline:
            return None
        time.sleep(poll)


def assess_container(name, inspect, commands):
    """Problems with one testbed container, judged only from outside it.

    ``inspect`` is the container's ``docker inspect`` record (None if it does not exist) and
    ``commands`` the command lines that ``docker top`` lists. Neither runs anything inside the
    host, so the check leaves no trace in the telemetry. Returns a list of problems (empty = OK).
    """
    if inspect is None:
        return ["container does not exist"]
    problems = []
    state = inspect.get("State", {})
    if state.get("Status") != "running":
        problems.append(f"not running (status {state.get('Status')})")
    if inspect.get("RestartCount", 0):
        problems.append(f"restarted {inspect['RestartCount']} time(s)")
    joined = "\n".join(commands)
    if name.startswith("fs-"):
        env = dict(e.split("=", 1) for e in inspect.get("Config", {}).get("Env", []) if "=" in e)
        role = env.get("ROLE", "?")
        if "agent.sh" not in joined:
            problems.append("agent is not running")
        if f"{role}.sh" not in joined:
            problems.append(f"{role} workload is not running")
    elif "c2.py" not in joined:
        problems.append("c2 server is not running")
    return problems


def start_attack(host, attack, seconds, timeout=10.0, control_dir=None):
    """Request an attack, wait for the host to accept or reject it, and clean up the request.

    Returns the host's ``started`` or ``rejected`` line. Raises TimeoutError if the host does
    not answer (agent not running, or wrong control folder).
    """
    req_id = request_attack(host, attack, seconds, control_dir)
    try:
        rec = wait_for(host, req_id, timeout=timeout, control_dir=control_dir)
    finally:
        clear_request(host, control_dir)
    if rec is None:
        bad = [line for line in _status_lines(host, control_dir)[1] if req_id in line]
        if bad:
            raise TimeoutError(f"{host} answered request {req_id}, but its status line is not valid JSON: "
                               f"{bad[-1]!r}. Check the agent's output format (e.g. a locale that writes "
                               f"decimal commas).")
        raise TimeoutError(f"{host} did not answer request {req_id} within {timeout:.0f} s. "
                           f"Is the host running? (make testbed-status)")
    return rec

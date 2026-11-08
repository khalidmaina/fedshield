"""The real testbed/host/agent.sh, run outside Docker with a fake role and fake attacks.

The agent's paths and hostname are overridable, so CI can check the request/status protocol
end to end without containers.
"""
import os
import shutil
import signal
import subprocess
import time

import pytest

from fedshield import control as c

from .conftest import REPO

AGENT = os.path.join(REPO, "testbed", "host", "agent.sh")
pytestmark = pytest.mark.skipif(shutil.which("bash") is None or shutil.which("mkfifo") is None,
                                reason="needs bash and mkfifo")


def write(path, text):
    with open(path, "w") as f:
        f.write(text)
    os.chmod(path, 0o755)


@pytest.fixture
def agent(tmp_path):
    roles, attacks, ctl = tmp_path / "roles", tmp_path / "attacks", tmp_path / "control"
    roles.mkdir()
    attacks.mkdir()
    ctl.mkdir()
    write(roles / "idle.sh", "#!/bin/bash\nexec sleep 600\n")
    write(attacks / "beacon.sh", "#!/bin/bash\nsleep 1\nexit 3\n")       # finishes with a known code
    write(attacks / "scan.sh", "#!/bin/bash\nsleep \"$1\"\n")
    env = dict(os.environ, HOSTNAME="fs-web-1", ROLE="idle", INTENSITY="1",
               ROLE_DIR=str(roles), ATTACK_DIR=str(attacks), CONTROL_DIR=str(ctl))
    proc = subprocess.Popen(["bash", AGENT], env=env, start_new_session=True,
                            stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    deadline = time.monotonic() + 5
    while not (ctl / "fs-web-1").is_dir() and time.monotonic() < deadline:
        time.sleep(0.05)
    yield proc, str(ctl)
    if proc.poll() is None:
        os.killpg(proc.pid, signal.SIGKILL)
    proc.wait(timeout=5)


def test_agent_starts_an_attack_and_reports_its_exit_code(agent):
    proc, ctl = agent
    rec = c.start_attack("fs-web-1", "beacon", 5, timeout=5, control_dir=ctl)
    assert rec["event"] == "started" and rec["attack"] == "beacon" and rec["seconds"] == 5
    end = c.wait_for("fs-web-1", rec["id"], events=("finished",), timeout=10, control_dir=ctl)
    assert end is not None and end["exit_code"] == 3
    assert float(end["ts"]) - float(rec["ts"]) >= 0.9          # wall-clock times from inside the host


def test_agent_rejects_a_second_attack_while_busy_and_unknown_attacks(agent):
    proc, ctl = agent
    assert c.start_attack("fs-web-1", "scan", 3, timeout=5, control_dir=ctl)["event"] == "started"
    busy = c.start_attack("fs-web-1", "beacon", 3, timeout=5, control_dir=ctl)
    assert busy["event"] == "rejected" and busy["reason"] == "busy"
    # an attack that passes our name check but has no script on the host
    os.remove(os.path.join(os.path.dirname(ctl), "attacks", "beacon.sh"))
    c.wait_for("fs-web-1", "never", events=("x",), timeout=4, poll=0.5, control_dir=ctl)   # let scan finish
    missing = c.start_attack("fs-web-1", "beacon", 3, timeout=5, control_dir=ctl)
    assert missing["event"] == "rejected" and missing["reason"] == "unknown attack"


def test_agent_ignores_malformed_requests(agent):
    proc, ctl = agent
    path = os.path.join(ctl, "fs-web-1", "request")
    write(path, "bad;id beacon 5\n")
    time.sleep(1.5)
    assert c.read_status("fs-web-1", control_dir=ctl) == []
    os.remove(path)


def test_agent_stops_cleanly_and_takes_its_children_with_it(agent):
    proc, ctl = agent
    rec = c.start_attack("fs-web-1", "scan", 60, timeout=5, control_dir=ctl)
    os.kill(proc.pid, signal.SIGTERM)
    proc.wait(timeout=5)
    time.sleep(0.3)
    assert not is_alive(rec["pid"])                              # the attack died with the agent


def is_alive(pid):
    """True if the process exists and is not a zombie (dead, waiting for init to reap it)."""
    try:
        with open(f"/proc/{pid}/stat") as f:
            return f.read().rsplit(")", 1)[1].split()[0] != "Z"
    except FileNotFoundError:
        return False


def test_agent_needs_a_role():
    env = {k: v for k, v in os.environ.items() if k != "ROLE"}
    r = subprocess.run(["bash", AGENT], env=env, capture_output=True, text=True, timeout=5)
    assert r.returncode != 0 and "ROLE must be set" in r.stderr

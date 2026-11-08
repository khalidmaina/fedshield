"""Host-side control protocol (fedshield/control.py) without Docker."""
import json
import os

import pytest

from fedshield import control as c


@pytest.fixture
def ctl(tmp_path):
    (tmp_path / "fs-web-1").mkdir()
    return str(tmp_path)


def test_hosts_are_four_roles_times_three():
    assert len(c.HOSTS) == 12 and c.HOSTS[0] == "fs-web-1" and c.HOSTS[-1] == "fs-dev-3"


def test_request_is_one_line_and_written_atomically(ctl):
    req_id = c.request_attack("fs-web-1", "beacon", 60, control_dir=ctl)
    d = os.path.join(ctl, "fs-web-1")
    assert open(os.path.join(d, "request")).read() == f"{req_id} beacon 60\n"
    assert os.listdir(d) == ["request"]                  # no temporary file left behind


@pytest.mark.parametrize("host,attack,secs", [
    ("fs-web-9", "beacon", 60),        # unknown host
    ("fs-web-1", "rm_rf", 60),         # unknown attack
    ("fs-web-1", "beacon", 0),         # too short
    ("fs-web-1", "beacon", 3601),      # too long
    ("fs-web-1", "beacon", 1.5),       # not a whole number
])
def test_invalid_requests_are_refused_before_writing(ctl, host, attack, secs):
    with pytest.raises(ValueError):
        c.request_attack(host, attack, secs, control_dir=ctl)
    assert not os.path.exists(os.path.join(ctl, "fs-web-1", "request"))


def test_missing_control_folder_gives_a_clear_error(tmp_path):
    with pytest.raises(FileNotFoundError, match="make testbed-up"):
        c.request_attack("fs-db-1", "scan", 10, control_dir=str(tmp_path))


def test_status_skips_malformed_lines(ctl):
    path = os.path.join(ctl, "fs-web-1", "status.jsonl")
    with open(path, "w") as f:
        f.write(json.dumps({"id": "a", "event": "started"}) + "\n")
        f.write("not json\n")
        f.write(json.dumps({"id": "a", "event": "finished", "exit_code": 0}) + "\n")
    assert [r["event"] for r in c.read_status("fs-web-1", control_dir=ctl)] == ["started", "finished"]
    assert c.read_status("fs-web-2", control_dir=ctl) == []      # no file yet


def test_wait_for_finds_the_matching_event_or_times_out(ctl):
    path = os.path.join(ctl, "fs-web-1", "status.jsonl")
    with open(path, "w") as f:
        f.write(json.dumps({"id": "other", "event": "started"}) + "\n")
        f.write(json.dumps({"id": "mine", "event": "rejected", "reason": "busy"}) + "\n")
    assert c.wait_for("fs-web-1", "mine", control_dir=ctl)["reason"] == "busy"
    assert c.wait_for("fs-web-1", "nobody", timeout=0.3, poll=0.1, control_dir=ctl) is None


def test_start_attack_times_out_and_cleans_up_when_no_agent_answers(ctl):
    with pytest.raises(TimeoutError):
        c.start_attack("fs-web-1", "scan", 5, timeout=0.3, control_dir=ctl)
    assert not os.path.exists(os.path.join(ctl, "fs-web-1", "request"))


# ---------------- health check from outside the container ----------------

def inspect(status="running", restarts=0, role="web"):
    return {"State": {"Status": status}, "RestartCount": restarts, "Config": {"Env": [f"ROLE={role}", "X=1"]}}


def test_healthy_host_has_no_problems():
    cmds = ["1 /sbin/docker-init -- /fs/agent.sh", "7 /bin/bash /fs/agent.sh", "9 /bin/bash /fs/roles/web.sh"]
    assert c.assess_container("fs-web-1", inspect(), cmds) == []


def test_problems_are_reported():
    assert c.assess_container("fs-web-1", None, []) == ["container does not exist"]
    probs = c.assess_container("fs-db-1", inspect(status="exited", restarts=2, role="db"), [])
    assert any("not running" in p for p in probs)
    assert any("restarted 2" in p for p in probs)
    assert "agent is not running" in probs and "db workload is not running" in probs
    assert c.assess_container("c2-server", inspect(), ["5 python3 /c2/c2.py"]) == []
    assert c.assess_container("c2-server", inspect(), []) == ["c2 server is not running"]

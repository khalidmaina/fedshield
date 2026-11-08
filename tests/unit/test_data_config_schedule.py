"""Config overrides, the per-host data split, regions and the attack schedule."""
import importlib.util
import os
import subprocess
import sys

import numpy as np
import pytest
import yaml

from fedshield.config import load_config
from fedshield.data import load, regions_for

from .conftest import REPO


@pytest.fixture(scope="module")
def synthetic_csv(tmp_path_factory):
    out = tmp_path_factory.mktemp("data") / "syn.csv"
    subprocess.run([sys.executable, os.path.join(REPO, "scripts", "make_synthetic.py"), "--sessions", "5",
                    "--windows-per-session", "200", "--attack-windows", "20", "--out", str(out)],
                   check=True, capture_output=True)
    return str(out)


def base(*overrides):
    return load_config(os.path.join(REPO, "configs", "base.yaml"), list(overrides))


# ---------------- config ----------------

def test_overrides_are_parsed_as_yaml_values():
    c = base("aggregation.rule=krum", "privacy.B.noise_multiplier=2.5", "poison.clients=[fs-web-1,fs-db-2]")
    assert c["aggregation"]["rule"] == "krum"
    assert c["privacy"]["B"]["noise_multiplier"] == 2.5
    assert c["poison"]["clients"] == ["fs-web-1", "fs-db-2"]


def test_every_grid_file_loads_and_names_known_keys():
    grids = os.path.join(REPO, "configs", "grids")
    known = set(base())
    for name in os.listdir(grids):
        g = yaml.safe_load(open(os.path.join(grids, name)))
        assert "name" in g and "seeds" in g, name
        for key in list((g.get("fixed") or {})) + list((g.get("grid") or {})):
            assert key.split(".")[0] in known, f"{name}: unknown key {key}"


# ---------------- data split ----------------

def test_split_is_in_time_order_and_training_is_benign_only(synthetic_csv):
    clients, feats = load(base(f"data.path={synthetic_csv}"))
    assert len(clients) == 12 and len(feats) == 19
    for c in clients.values():
        n = len(c.X_val) + len(c.X_test)
        assert n > 0 and len(c.X_train) > 0
        assert 0.0 <= c.X_train.min() and c.X_train.max() <= 1.0     # data-independent scaling
        assert all(len(x) > 0 for x in c.pool.values())               # attacks seen in training go to the pool


def test_configured_regions_are_two_groups_of_six(synthetic_csv):
    clients, _ = load(base(f"data.path={synthetic_csv}"))
    reg = regions_for(base(), list(clients))
    assert sorted(len(m) for m in reg.values()) == [6, 6]
    assert set().union(*map(set, reg.values())) == set(clients)
    assert "fs-build-2" in reg["B"]


def test_regions_fall_back_to_an_even_split_for_other_clients():
    reg = regions_for(base(), [f"client_{i:02d}" for i in range(10)])
    assert [len(m) for m in reg.values()] == [5, 5]


# ---------------- attack schedule ----------------

def _schedule_module():
    spec = importlib.util.spec_from_file_location("make_schedule", os.path.join(REPO, "scripts", "make_schedule.py"))
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def test_each_host_sees_every_attack_once_in_five_sessions_without_overlap(tmp_path, monkeypatch):
    mod = _schedule_module()
    monkeypatch.setattr(mod, "REPO", str(tmp_path))
    seen = {h: set() for h in mod.HOSTS}
    for i in range(1, 6):
        monkeypatch.setattr(sys, "argv", ["make_schedule.py", "--index", str(i)])
        mod.main()
        sch = yaml.safe_load(open(tmp_path / "testbed" / "schedules" / f"session_{i:02d}.yaml"))
        spans = sorted((a["start_min"], a["start_min"] + a["duration_min"]) for a in sch["attacks"])
        assert all(end <= nxt for (_, end), (nxt, _) in zip(spans, spans[1:]))      # no overlap
        assert spans[0][0] >= 5 and spans[-1][1] <= sch["duration_min"] - 5        # benign margins
        for a in sch["attacks"]:
            seen[a["host"]].add(a["attack"])
    assert all(s == set(mod.ATTACKS) for s in seen.values())


def test_scaling_is_monotone_and_capped():
    from fedshield.data import scale
    x = scale(np.array([[0.0, 10.0, 1e9]]), cap=1e5)
    assert x[0, 0] == 0.0 and 0 < x[0, 1] < 1 and x[0, 2] == 1.0

"""The collection plan (fedshield/schedule.py) and the testbed facts it relies on (topology.py)."""
import os

import pytest
import yaml

from fedshield import schedule as sc
from fedshield.topology import ATTACKS, HOSTS, INTENSITY, REGIONS, TARGET_ATTACK, role_of

from .conftest import REPO

ALL = [sc.make_schedule(s) for s in sc.PLAN]


def cov():
    return sc.coverage(ALL)


# ---------------------------------------------------------------- topology vs the real testbed

def test_topology_matches_docker_compose():
    compose = yaml.safe_load(open(os.path.join(REPO, "testbed", "docker-compose.yml")))["services"]
    for host in HOSTS:
        env = compose[host]["environment"]
        assert compose[host]["hostname"] == host
        assert env["ROLE"] == role_of(host) and int(env["INTENSITY"]) == INTENSITY[host]
    assert sorted(REGIONS["A"] + REGIONS["B"]) == sorted(HOSTS)
    assert all(len(m) == 6 for m in REGIONS.values())


# ---------------------------------------------------------------- what each host gets

def test_plan_is_eight_sessions_split_by_session():
    assert [sc.PLAN[s] for s in range(1, 9)] == ["train"] * 4 + ["val", "test", "test", "holdout"]


def test_every_schedule_is_valid():
    for s in ALL:
        assert sc.validate(s) == [], s["session"]


def test_every_host_has_every_attack_in_train_and_the_target_twice():
    c = cov()
    for h in HOSTS:
        assert set(c[h]["train"]) == set(ATTACKS)
        assert c[h]["train"][TARGET_ATTACK] == 2
        assert sum(c[h]["train"].values()) == 8


def test_every_host_has_the_target_in_val_test_and_holdout():
    c = cov()
    for h in HOSTS:
        for split in ("val", "test", "holdout"):
            assert c[h][split].get(TARGET_ATTACK) == 1, (h, split)


def test_val_and_test_together_give_every_host_every_attack():
    c = cov()
    for h in HOSTS:
        assert set(c[h]["val"]) | set(c[h]["test"]) == set(ATTACKS)


def test_a_host_never_gets_the_same_attack_twice_in_one_session():
    for s in ALL:
        for h in HOSTS:
            mine = [a["attack"] for a in s["attacks"] if a["host"] == h]
            assert len(mine) == 2 and len(set(mine)) == 2


def test_one_attack_in_each_half_with_quiet_margins():
    for s in ALL:
        for a in s["attacks"]:
            end = a["start_min"] + a["duration_min"]
            if a["slot"] == 0:
                assert 6 <= a["start_min"] and end <= 57
            else:
                assert 63 <= a["start_min"] and end <= 114


def test_concurrency_and_miner_limits_hold():
    for s in ALL:
        spans = [(a["start_min"], a["start_min"] + a["duration_min"], a["attack"]) for a in s["attacks"]]
        for t in [x[0] for x in spans]:
            running = [x for x in spans if x[0] <= t < x[1]]
            assert len(running) <= 4
            assert sum(x[2] == "miner" for x in running) <= 1


def test_the_same_seed_gives_the_same_plan_and_another_seed_a_different_one():
    assert sc.make_schedule(3) == sc.make_schedule(3)
    assert sc.make_schedule(3, seed=8)["attacks"] != sc.make_schedule(3)["attacks"]


def test_committed_schedules_are_exactly_what_the_generator_makes():
    import json
    for s in sc.PLAN:
        path = os.path.join(REPO, "testbed", "schedules", f"session_{s:02d}.json")
        assert json.load(open(path)) == sc.make_schedule(s), path


# ---------------------------------------------------------------- validation catches mistakes

def test_validate_reports_broken_schedules():
    s = sc.make_schedule(1)
    bad = dict(s, attacks=s["attacks"][1:])                         # one host has a single attack
    assert any("1 attacks instead of 2" in p for p in sc.validate(bad))
    crowded = dict(s, max_concurrent=1)
    assert any("at once" in p for p in sc.validate(crowded))


def test_too_long_attacks_are_refused():
    with pytest.raises(ValueError):
        sc.slot_ranges(duration_min=20, attack_min=10)

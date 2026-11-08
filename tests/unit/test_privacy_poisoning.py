"""Track B privacy (clip + noise, epsilon) and normality poisoning (rate ramp, data mixing)."""
import numpy as np
import pytest

from fedshield.poisoning import attack_pool_for, mix, poisoned_rate
from fedshield.privacy import clip_update, randomize_update, track_b_epsilon

# ---------------- Track B ----------------

def test_clip_only_shrinks_long_updates():
    long, short = np.array([3.0, 4.0]), np.array([0.3, 0.4])
    assert np.linalg.norm(clip_update(long, 1.0)) == pytest.approx(1.0)
    assert np.allclose(clip_update(short, 1.0), short)


def test_noise_std_is_sigma_times_clip():
    rng = np.random.default_rng(0)
    out = randomize_update(np.zeros(200_000), C=0.5, sigma=2.0, rng=rng)
    assert out.std() == pytest.approx(1.0, rel=0.01)


@pytest.mark.parametrize("sigma,expected", [(1.0, 140.7), (2.0, 50.4), (5.0, 15.3), (10.0, 6.9)])
def test_track_b_epsilon_matches_equation_11(sigma, expected):
    # 40 releases, delta = 1e-5 (values checked by hand against Eq. 11 of the proposal)
    assert track_b_epsilon(40, sigma, 1e-5) == pytest.approx(expected, abs=0.1)


def test_epsilon_grows_with_rounds_and_falls_with_noise():
    assert track_b_epsilon(0, 1.0, 1e-5) == 0.0
    assert track_b_epsilon(10, 1.0, 1e-5) < track_b_epsilon(40, 1.0, 1e-5)
    assert track_b_epsilon(40, 2.0, 1e-5) < track_b_epsilon(40, 1.0, 1e-5)
    assert track_b_epsilon(40, 0.0, 1e-5) == float("inf")


# ---------------- normality poisoning ----------------

def cfg(pdr=0.3, start=20, ramp=5):
    return {"poison": {"pdr": pdr, "start_round": start, "ramp_rounds": ramp}}


def test_poison_rate_is_zero_before_start_then_ramps_to_pdr():
    c = cfg()
    assert poisoned_rate(c, 19) == 0.0
    assert poisoned_rate(c, 20) == pytest.approx(0.06)
    assert poisoned_rate(c, 24) == pytest.approx(0.30)
    assert poisoned_rate(c, 40) == pytest.approx(0.30)
    assert poisoned_rate(cfg(pdr=0.0), 30) == 0.0


def test_mix_keeps_size_and_replaces_the_requested_fraction():
    rng = np.random.default_rng(0)
    benign = np.zeros((1000, 3), dtype=np.float32)
    pool = np.ones((48, 3), dtype=np.float32)
    out = mix(benign, pool, 0.2, rng)
    assert out.shape == benign.shape
    assert int(out[:, 0].sum()) == 200
    assert mix(benign, pool, 0.0, rng) is benign


class _Client:
    def __init__(self, pool):
        self.pool = pool


def test_attack_pool_never_borrows_from_evaluation_hosts():
    clients = {"a": _Client({}), "b": _Client({"beacon": np.ones((4, 2))}),
               "eval": _Client({"beacon": np.ones((9, 2))})}
    pool = attack_pool_for(clients["a"], clients, "beacon", compromised=["a", "b"])
    assert len(pool) == 4                     # from the other compromised host only
    with pytest.raises(ValueError):
        attack_pool_for(clients["a"], clients, "beacon", compromised=["a"])

"""Aggregation rules: FedAvg, Krum, Multi-Krum, distance filter, and the two-level hierarchy."""
import numpy as np
import pytest

from fedshield.aggregation import aggregate, check_krum, fedavg, krum, krum_scores, multikrum


def honest_cluster(rng, n=5, d=20):
    return [rng.normal(0.0, 0.01, d) + 1.0 for _ in range(n)]


def test_fedavg_is_sample_weighted():
    agg, sel = fedavg([np.array([0.0]), np.array([3.0])], [1, 2])
    assert agg[0] == pytest.approx(2.0)
    assert sel == [0, 1]


@pytest.mark.parametrize("n,f,ok", [(5, 1, True), (4, 1, False), (7, 2, True), (6, 2, False)])
def test_krum_condition_n_at_least_2f_plus_3(n, f, ok):
    if ok:
        check_krum(n, f)
    else:
        with pytest.raises(ValueError):
            check_krum(n, f)


def test_krum_score_uses_n_minus_f_minus_2_neighbours():
    ups = [np.array([0.0]), np.array([1.0]), np.array([2.0]), np.array([3.0]), np.array([10.0])]
    s = krum_scores(ups, f=1)          # k = 5 - 1 - 2 = 2 nearest neighbours
    assert s[1] == pytest.approx(1 + 1)  # neighbours 0 and 2
    assert s[4] == pytest.approx(49 + 64)


def test_krum_and_multikrum_drop_an_obvious_outlier():
    rng = np.random.default_rng(0)
    ups = honest_cluster(rng) + [np.full(20, 50.0)]
    _, sel = krum(ups, [1] * 6, f=1)
    assert sel[0] != 5
    agg, sel = multikrum(ups, [1] * 6, f=1)
    assert 5 not in sel and len(sel) == 5          # default m = n - f
    assert np.allclose(agg, np.mean(ups[:5], axis=0))


def test_multikrum_rejects_m_outside_1_to_n_minus_f():
    rng = np.random.default_rng(1)
    ups = honest_cluster(rng, n=6)
    with pytest.raises(ValueError):
        multikrum(ups, [1] * 6, f=1, m=6)
    with pytest.raises(ValueError):
        multikrum(ups, [1] * 6, f=1, m=0)


def test_distance_filter_drops_the_far_group():
    rng = np.random.default_rng(2)
    ups = honest_cluster(rng) + [np.full(20, 30.0)]
    _, keep = aggregate("distance_filter", ups, [1] * 6)
    assert 5 not in keep


def test_unknown_rule_is_refused():
    with pytest.raises(ValueError):
        aggregate("median", [np.zeros(2)], [1])


def test_hierarchical_fedavg_equals_flat_fedavg_when_everyone_participates():
    """Proposal Section 4.3: with sample-count weighting of regions, two-level FedAvg
    reproduces flat FedAvg. fl.py weights each region by the samples of the clients
    its rule selected; under FedAvg every client is selected, so the two coincide."""
    rng = np.random.default_rng(3)
    ups = [rng.normal(size=8) for _ in range(12)]
    n = list(rng.integers(100, 1000, size=12))
    flat, _ = fedavg(ups, n)
    regions = [range(0, 6), range(6, 12)]
    parts, weights = [], []
    for r in regions:
        a, sel = fedavg([ups[i] for i in r], [n[i] for i in r])
        parts.append(a)
        weights.append(sum(n[list(r)[j]] for j in sel))
    two_level = np.average(np.stack(parts), axis=0, weights=weights)
    assert np.allclose(two_level, flat)

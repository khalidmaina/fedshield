"""Aggregation rules. Every rule takes a list of update vectors (numpy, one per client)
and the clients' sample counts, and returns (aggregated update, indices of selected
updates)."""
import numpy as np
from sklearn.mixture import GaussianMixture


def fedavg(updates, n_samples):
    w = np.asarray(n_samples, dtype=float)
    return np.average(np.stack(updates), axis=0, weights=w), list(range(len(updates)))


def krum_scores(updates, f):
    """Krum score of each update: sum of squared distances to its n - f - 2 nearest
    neighbours (Blanchard et al., 2017)."""
    U = np.stack(updates).astype(np.float64)
    n = len(U)
    sq = np.sum(U ** 2, axis=1)
    d2 = np.maximum(sq[:, None] + sq[None, :] - 2 * U @ U.T, 0.0)
    k = n - f - 2
    scores = np.empty(n)
    for i in range(n):
        others = np.delete(d2[i], i)
        scores[i] = np.sort(others)[:k].sum()
    return scores


def check_krum(n, f):
    if n < 2 * f + 3:
        raise ValueError(f"Krum condition violated: n={n} updates but f={f} needs n >= 2f+3 = {2 * f + 3}")


def krum(updates, n_samples, f):
    check_krum(len(updates), f)
    i = int(np.argmin(krum_scores(updates, f)))
    return np.asarray(updates[i], dtype=float), [i]


def multikrum(updates, n_samples, f, m=None):
    """Averages (equal weights) the m updates with the lowest Krum scores.
    Default m = n - f, valid range 1 <= m <= n - f (Eq. 13)."""
    n = len(updates)
    check_krum(n, f)
    m = n - f if m in (None, "auto") else int(m)
    if not 1 <= m <= n - f:
        raise ValueError(f"Multi-Krum needs 1 <= m <= n - f = {n - f}, got m = {m}")
    sel = list(np.argsort(krum_scores(updates, f))[:m])
    return np.mean(np.stack([updates[i] for i in sel]), axis=0), [int(i) for i in sel]


def distance_filter(updates, n_samples, seed=0):
    """FLANDRE-style filter: split clients into two groups by update norm (distance from
    the previous global model) with a 2-component Gaussian mixture and drop the group
    with the larger mean distance."""
    norms = np.array([np.linalg.norm(u) for u in updates]).reshape(-1, 1)
    keep = list(range(len(updates)))
    if len(updates) >= 4 and np.ptp(norms) > 0:
        gm = GaussianMixture(n_components=2, random_state=seed).fit(norms)
        lab = gm.predict(norms)
        if len(set(lab)) == 2:
            far = int(np.argmax(gm.means_.ravel()))
            keep = [i for i in range(len(updates)) if lab[i] != far]
    agg, _ = fedavg([updates[i] for i in keep], [n_samples[i] for i in keep])
    return agg, keep


def aggregate(rule, updates, n_samples, f=1, m=None, seed=0):
    if rule == "fedavg":
        return fedavg(updates, n_samples)
    if rule == "krum":
        return krum(updates, n_samples, f)
    if rule == "multikrum":
        return multikrum(updates, n_samples, f, m)
    if rule == "distance_filter":
        return distance_filter(updates, n_samples, seed)
    raise ValueError(f"Unknown aggregation rule {rule}")

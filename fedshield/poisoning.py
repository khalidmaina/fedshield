"""Normality poisoning (RQ5): a compromised host's own attack activity enters its
training windows. The FL client itself stays honest; only its data changes."""
import numpy as np


def poisoned_rate(cfg, rnd):
    """Poisoned-data rate in round `rnd` (1-based): 0 before start_round, then a
    linear ramp over ramp_rounds up to the target pdr."""
    p = cfg["poison"]
    if p["pdr"] <= 0 or rnd < p["start_round"]:
        return 0.0
    ramp = max(1, int(p["ramp_rounds"]))
    return float(p["pdr"]) * min(1.0, (rnd - p["start_round"] + 1) / ramp)


def attack_pool_for(client, clients, target, compromised):
    """Target-behaviour windows the compromised host would generate. Uses the host's
    own training-period attack windows; if it has none, uses those of the other
    compromised hosts (never those of evaluation hosts)."""
    if target in client.pool and len(client.pool[target]):
        return client.pool[target]
    others = [clients[c].pool[target] for c in compromised
              if target in clients[c].pool and len(clients[c].pool[target])]
    if not others:
        raise ValueError(f"No '{target}' windows in the training period of any compromised host")
    return np.vstack(others)


def mix(benign, pool, rate, rng):
    """Training set of the same size as `benign` where a fraction `rate` of rows are
    attack windows (sampled with replacement)."""
    n = len(benign)
    k = int(round(rate * n))
    if k == 0:
        return benign
    keep = rng.choice(n, size=n - k, replace=False)
    bad = pool[rng.integers(0, len(pool), size=k)]
    out = np.vstack([benign[keep], bad]).astype(np.float32)
    return out[rng.permutation(n)]

"""Byzantine (update-level) attacks, Section 6.3 attacks (i)-(v).

All functions return the malicious update vector. `honest` is the matrix of honest
updates the attacker knows: all honest updates of its aggregation group ('full'
knowledge) or only the malicious clients' own honest updates ('partial').
"""
import numpy as np
from scipy.stats import norm


def gaussian(own, scale, rng):
    s = scale * np.linalg.norm(own) / np.sqrt(own.size)
    return rng.normal(0.0, s, size=own.shape)


def signflip(own):
    return -own


def scaled(own, scale):
    return scale * own


def lie(honest, n, f, z="auto"):
    """'A Little Is Enough' (Baruch et al., 2019): mean - z * std, coordinate-wise.
    z = "auto" uses the paper's formula z = Phi^-1((n - s) / n), s = floor(n/2 + 1) - f.
    In small groups (e.g. n = 6, f = 1) that formula gives z = 0, i.e. a harmless
    update, so a fixed z (default 1.0 in the config) is also supported."""
    mu, sd = honest.mean(axis=0), honest.std(axis=0)
    if z == "auto":
        s = int(np.floor(n / 2 + 1)) - f
        z = norm.ppf((n - s) / n)
    return mu - float(z) * sd


def min_max(honest, gamma_init=10.0, tol=1e-5):
    """AGR-agnostic Min-Max (Shejwalkar & Houmansadr, NDSS 2021) with the inverse-std
    perturbation: the largest gamma such that the malicious update is no farther from
    any honest update than the largest honest-honest distance."""
    mu, dev = honest.mean(axis=0), honest.std(axis=0)
    d_ben = np.sqrt(((honest[:, None, :] - honest[None, :, :]) ** 2).sum(-1)).max()
    lam, step, lam_succ = gamma_init, gamma_init, 0.0     # as in the authors' code
    while abs(lam_succ - lam) > tol:
        mal = mu - lam * dev
        d_mal = np.sqrt(((honest - mal) ** 2).sum(-1)).max()
        if d_mal <= d_ben:
            lam_succ = lam
            lam = lam + step / 2
        else:
            lam = lam - step / 2
        step = step / 2
    return mu - lam_succ * dev


def craft(attack, own, honest, n_group, f_actual, cfg, rng):
    b = cfg["byzantine"]
    if attack == "gaussian":
        return gaussian(own, b["scale"], rng)
    if attack == "signflip":
        return signflip(own)
    if attack == "scale":
        return scaled(own, b["scale"])
    if attack == "lie":
        return lie(honest, n_group, f_actual, b.get("lie_z", 1.0))
    if attack == "minmax":
        return min_max(honest)
    if attack == "replacement":
        # 'own' is already the backdoor update (trained on the target behaviour);
        # boost it so it survives averaging (Bagdasaryan et al., 2020).
        return scaled(own, n_group)
    raise ValueError(f"Unknown attack {attack}")

"""Differential privacy.

Track A: record-level DP-SGD inside each client (Opacus, RDP accountant, Poisson sampling).
Track B: per-client update clipping + Gaussian noise (Eqs. 7-11 of the proposal).
"""
import numpy as np


def clip_update(delta, C):
    """Eq. 7: scale the update down to L2 norm C if it is larger."""
    norm = np.linalg.norm(delta)
    return delta * min(1.0, C / (norm + 1e-12))


def randomize_update(delta, C, sigma, rng):
    """Eq. 8: clipped update + N(0, sigma^2 C^2 I)."""
    return clip_update(delta, C) + rng.normal(0.0, sigma * C, size=delta.shape)


def track_b_epsilon(T, sigma, delta, orders=None):
    """Eq. 11: epsilon after T releases by one client under replacement adjacency
    (sensitivity 2C), RDP of the Gaussian mechanism, converted to (eps, delta)-DP:
        eps = min_lambda [ 2 T lambda / sigma^2 + ln(1/delta) / (lambda - 1) ]
    """
    if T == 0:
        return 0.0
    if sigma <= 0:
        return float("inf")
    if orders is None:
        orders = np.concatenate([np.linspace(1.01, 10, 200), np.arange(11, 512)])
    eps = 2.0 * T * orders / sigma ** 2 + np.log(1.0 / delta) / (orders - 1.0)
    return float(np.min(eps))

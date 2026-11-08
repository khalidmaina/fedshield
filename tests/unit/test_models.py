"""Sparse autoencoder and hybrid detector. Skipped automatically when PyTorch is missing."""
import numpy as np
import pytest

torch = pytest.importorskip("torch")

from fedshield.models import SAE, LocalDetector, MinMax, sae_loss, sae_scores  # noqa: E402

pytestmark = pytest.mark.torch


def test_sae_shapes_and_output_range():
    m = SAE(19, hidden=32, latent=8)
    x = torch.rand(5, 19)
    x_hat, h = m(x)
    assert x_hat.shape == (5, 19) and h.shape == (5, 8)
    assert float(x_hat.min()) >= 0 and float(x_hat.max()) <= 1


def test_sae_has_no_batch_norm_so_opacus_can_use_it():
    assert not any(isinstance(mod, torch.nn.modules.batchnorm._BatchNorm) for mod in SAE(19).modules())


def test_loss_is_mean_of_per_sample_terms():
    """DP-SGD needs the loss to be an average of per-sample losses."""
    torch.manual_seed(0)
    m = SAE(19)
    x = torch.rand(6, 19)
    x_hat, h = m(x)
    whole = sae_loss(x, x_hat, h, 0.01, 0.1)
    parts = torch.stack([sae_loss(x[i:i + 1], x_hat[i:i + 1], h[i:i + 1], 0.01, 0.1) for i in range(6)])
    assert torch.allclose(whole, parts.mean())


def test_minmax_uses_training_range_only():
    n = MinMax(np.array([1.0, 3.0]))
    assert n(np.array([2.0]))[0] == pytest.approx(0.5)
    assert n(np.array([5.0]))[0] == pytest.approx(2.0)      # test values are not re-fitted


def test_detector_thresholds_come_from_benign_validation_scores():
    rng = np.random.default_rng(0)
    X = rng.random((300, 19)).astype(np.float32) * 0.2
    cfg = {"detection": {"threshold_quantile": 0.99, "alpha_grid": [0.0, 0.5, 1.0], "if_trees": 50, "if_samples": 64}}
    det = LocalDetector(SAE(19), X, cfg, seed=0)
    Xv = np.vstack([X[:50], np.ones((5, 19), dtype=np.float32)])
    yv = np.r_[np.zeros(50, int), np.ones(5, int)]
    det.calibrate(Xv, yv)
    assert det.alpha in (0.0, 0.5, 1.0)
    assert set(det.thr) == {"sae", "if", "hybrid"}
    s = det.scores(np.ones((3, 19), dtype=np.float32))
    assert (s["hybrid"] > det.thr["hybrid"]).all()            # obvious anomalies are flagged
    assert len(sae_scores(det.sae, X[:7])) == 7

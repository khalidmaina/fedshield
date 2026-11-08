"""Sparse autoencoder, Isolation Forest and the hybrid detector."""
import numpy as np
import torch
from torch import nn
from sklearn.ensemble import IsolationForest
from sklearn.metrics import average_precision_score


class SAE(nn.Module):
    """Sparse autoencoder. No batch normalisation, so it works with Opacus (Track A)."""

    def __init__(self, d, hidden=32, latent=8):
        super().__init__()
        self.enc1 = nn.Linear(d, hidden)
        self.enc2 = nn.Linear(hidden, latent)
        self.dec1 = nn.Linear(latent, hidden)
        self.dec2 = nn.Linear(hidden, d)

    def forward(self, x):
        h = torch.sigmoid(self.enc2(torch.relu(self.enc1(x))))
        x_hat = torch.sigmoid(self.dec2(torch.relu(self.dec1(h))))
        return x_hat, h


def sae_loss(x, x_hat, h, rho=0.01, beta=3.0):
    """Reconstruction error + beta * KL sparsity penalty (Eq. 1 of the proposal).

    The KL term is computed per sample (between rho and each sample's latent
    activations) and then averaged. Unlike the classic batch-mean version, this keeps
    the loss a sum of per-sample terms, which DP-SGD requires.
    """
    rec = ((x - x_hat) ** 2).sum(dim=1)
    hc = h.clamp(1e-6, 1 - 1e-6)
    kl = (rho * torch.log(rho / hc) + (1 - rho) * torch.log((1 - rho) / (1 - hc))).sum(dim=1)
    return (rec + beta * kl).mean()


@torch.no_grad()
def sae_scores(model, X, batch=4096):
    """Anomaly score = squared reconstruction error per window (Eq. 2)."""
    model.eval()
    out = []
    for i in range(0, len(X), batch):
        xb = torch.as_tensor(X[i:i + batch])
        x_hat, _ = model(xb)
        out.append(((xb - x_hat) ** 2).sum(dim=1).numpy())
    return np.concatenate(out) if out else np.zeros(0)


def fit_iforest(X, trees=100, samples=256, seed=0):
    return IsolationForest(n_estimators=trees, max_samples=min(samples, len(X)), random_state=seed).fit(X)


def if_scores(forest, X):
    """Larger = more anomalous (sklearn's score_samples is the opposite)."""
    return -forest.score_samples(X)


class MinMax:
    """Min-max normalisation fitted on training scores only (no test leakage)."""

    def __init__(self, scores):
        self.lo, self.hi = float(np.min(scores)), float(np.max(scores))

    def __call__(self, s):
        return (s - self.lo) / (self.hi - self.lo + 1e-12)


class LocalDetector:
    """Per-client detector: global SAE + local Isolation Forest + hybrid score (Eq. 3).

    Fit on the client's training windows; alpha and thresholds are chosen on the
    validation set and then frozen for the test set.
    """

    def __init__(self, sae, X_train, cfg, seed=0, forest=None):
        det = cfg["detection"]
        self.sae = sae
        self.forest = forest if forest is not None else fit_iforest(
            X_train, det["if_trees"], det["if_samples"], seed)
        self.n_sae = MinMax(sae_scores(sae, X_train))
        self.n_if = MinMax(if_scores(self.forest, X_train))
        self.alpha = 0.5
        self.thr = {}
        self.q = det["threshold_quantile"]
        self.alpha_grid = det["alpha_grid"]

    def scores(self, X):
        s_sae = self.n_sae(sae_scores(self.sae, X))
        s_if = self.n_if(if_scores(self.forest, X))
        return {"sae": s_sae, "if": s_if, "hybrid": self.alpha * s_sae + (1 - self.alpha) * s_if}

    def calibrate(self, X_val, y_val):
        """Choose alpha by PR-AUC on validation (if it has attacks), then set each
        detector's threshold at the given quantile of BENIGN validation scores."""
        s_sae = self.n_sae(sae_scores(self.sae, X_val))
        s_if = self.n_if(if_scores(self.forest, X_val))
        if y_val.sum() > 0 and (y_val == 0).sum() > 0:
            best = max(self.alpha_grid, key=lambda a: average_precision_score(y_val, a * s_sae + (1 - a) * s_if))
            self.alpha = float(best)
        sc = {"sae": s_sae, "if": s_if, "hybrid": self.alpha * s_sae + (1 - self.alpha) * s_if}
        benign = y_val == 0
        for k, s in sc.items():
            self.thr[k] = float(np.quantile(s[benign], self.q)) if benign.any() else float(np.quantile(s, self.q))
        return self

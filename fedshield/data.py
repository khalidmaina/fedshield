"""Loading and splitting data for every client.

Two sources are supported:
  host   : data/processed/host_windows.csv made by scripts/build_dataset.py
           (or the synthetic file made by scripts/make_synthetic.py, same format)
  cicids : CICIDS2017 MachineLearningCVE CSV files, benign traffic split among
           clients with a Dirichlet partition (scripts/prepare_cicids.py)
"""
import glob
import os
from dataclasses import dataclass, field

import numpy as np
import pandas as pd

from .features import FEATURES


@dataclass
class ClientData:
    cid: str
    role: str
    X_train: np.ndarray                     # benign training windows (scaled)
    X_val: np.ndarray
    y_val: np.ndarray
    a_val: np.ndarray                       # attack name per val window ('' = benign)
    X_test: np.ndarray
    y_test: np.ndarray
    a_test: np.ndarray
    pool: dict = field(default_factory=dict)  # attack name -> attack windows from the training period


def scale(X, cap):
    """Data-independent scaling: log1p, clip and divide. No statistics are shared."""
    L = np.log1p(cap)
    return (np.clip(np.log1p(np.maximum(X, 0.0)), 0.0, L) / L).astype(np.float32)


def _role(host):
    parts = host.split("-")
    return parts[1] if len(parts) >= 3 else "unknown"


def load_host(cfg):
    d = cfg["data"]
    df = pd.read_csv(d["path"])
    feats = [f for f in FEATURES if f in df.columns]
    if len(feats) != len(FEATURES):
        missing = sorted(set(FEATURES) - set(feats))
        raise ValueError(f"Missing feature columns: {missing}")
    df["attack"] = df["attack"].fillna("")
    tr, va, _ = d["split"]
    cap = float(d.get("scale_cap", 1e5))
    clients = {}
    for host, g in df.groupby("host"):
        g = g.sort_values("window_start")
        n = len(g)
        i1, i2 = int(tr * n), int((tr + va) * n)
        train, val, test = g.iloc[:i1], g.iloc[i1:i2], g.iloc[i2:]
        benign_train = train[train["label"] == 0]
        pool = {a: scale(x[feats].to_numpy(float), cap)
                for a, x in train[train["label"] == 1].groupby("attack")}
        clients[host] = ClientData(
            cid=host, role=_role(host),
            X_train=scale(benign_train[feats].to_numpy(float), cap),
            X_val=scale(val[feats].to_numpy(float), cap), y_val=val["label"].to_numpy(int),
            a_val=val["attack"].to_numpy(str),
            X_test=scale(test[feats].to_numpy(float), cap), y_test=test["label"].to_numpy(int),
            a_test=test["attack"].to_numpy(str), pool=pool)
    return clients, feats


def load_cicids(cfg):
    """Benign flows are clustered with k-means; each cluster is spread over clients with
    proportions drawn from Dirichlet(alpha). Small alpha = very different clients."""
    from sklearn.cluster import MiniBatchKMeans

    d = cfg["data"]
    rng = np.random.default_rng(cfg["seed"])
    path = d["path"]
    if os.path.isdir(path):
        files = sorted(glob.glob(os.path.join(path, "*.csv")))
        df = pd.concat([pd.read_csv(f, low_memory=False) for f in files], ignore_index=True)
    else:
        df = pd.read_parquet(path) if path.endswith(".parquet") else pd.read_csv(path, low_memory=False)
    df.columns = [c.strip() for c in df.columns]
    label_col = "Label"
    feats = [c for c in df.columns if c != label_col and pd.api.types.is_numeric_dtype(df[c])]
    df[feats] = df[feats].replace([np.inf, -np.inf], np.nan)
    df = df.dropna(subset=feats)
    df[label_col] = df[label_col].astype(str).str.strip()
    cap = float(d.get("scale_cap", 1e9))
    K = int(d["n_clients"])
    alpha = float(d["dirichlet_alpha"])
    max_b = int(d.get("max_benign_per_client", 20000))
    max_a = int(d.get("max_attack_per_type", 3000))

    benign = df[df[label_col] == "BENIGN"]
    benign = benign.sample(n=min(len(benign), K * max_b * 2), random_state=cfg["seed"])
    Xb = scale(benign[feats].to_numpy(float), cap)
    n_clusters = int(d.get("n_clusters", 10))
    km = MiniBatchKMeans(n_clusters=n_clusters, random_state=cfg["seed"], n_init=3).fit(Xb)
    owner = np.empty(len(Xb), dtype=int)
    for c in range(n_clusters):
        idx = np.where(km.labels_ == c)[0]
        rng.shuffle(idx)
        p = rng.dirichlet(alpha * np.ones(K))
        cuts = (np.cumsum(p) * len(idx)).astype(int)[:-1]
        for k, part in enumerate(np.split(idx, cuts)):
            owner[part] = k
    attacks = df[df[label_col] != "BENIGN"]
    attack_parts = {}
    for name, g in attacks.groupby(label_col):
        g = g.sample(n=min(len(g), max_a), random_state=cfg["seed"])
        Xa = scale(g[feats].to_numpy(float), cap)
        attack_parts[name] = np.array_split(Xa[rng.permutation(len(Xa))], K)

    tr, va, _ = d["split"]
    clients = {}
    for k in range(K):
        Xk = Xb[owner == k][:max_b]
        rng.shuffle(Xk)
        n = len(Xk)
        i1, i2 = int(tr * n), int((tr + va) * n)
        Xtr, Xv, Xt = Xk[:i1], Xk[i1:i2], Xk[i2:]
        pool, av_x, av_a, at_x, at_a = {}, [], [], [], []
        for name, parts in attack_parts.items():
            part = parts[k]
            a1, a2 = int(0.4 * len(part)), int(0.6 * len(part))
            pool[name] = part[:a1]
            av_x.append(part[a1:a2]); av_a += [name] * (a2 - a1)
            at_x.append(part[a2:]); at_a += [name] * (len(part) - a2)
        Xv_all = np.vstack([Xv] + av_x)
        Xt_all = np.vstack([Xt] + at_x)
        clients[f"client_{k:02d}"] = ClientData(
            cid=f"client_{k:02d}", role=f"cluster_{np.bincount(km.labels_[owner == k], minlength=n_clusters).argmax()}",
            X_train=Xtr,
            X_val=Xv_all, y_val=np.r_[np.zeros(len(Xv), int), np.ones(len(av_a), int)],
            a_val=np.array([""] * len(Xv) + av_a),
            X_test=Xt_all, y_test=np.r_[np.zeros(len(Xt), int), np.ones(len(at_a), int)],
            a_test=np.array([""] * len(Xt) + at_a), pool=pool)
    return clients, feats


def load(cfg):
    src = cfg["data"]["source"]
    if src == "host":
        clients, feats = load_host(cfg)
    elif src == "cicids":
        clients, feats = load_cicids(cfg)
    else:
        raise ValueError(f"Unknown data.source {src}")
    for c in clients.values():
        if len(c.X_train) < 10:
            raise ValueError(f"Client {c.cid} has only {len(c.X_train)} benign training windows")
    return clients, feats


def regions_for(cfg, client_ids):
    """Use the configured regions if they cover all clients; otherwise split evenly."""
    reg = cfg.get("regions") or {}
    listed = {c for members in reg.values() for c in members}
    if reg and listed == set(client_ids):
        return {r: list(m) for r, m in reg.items()}
    ids = sorted(client_ids)
    n_reg = int(cfg.get("n_regions", 2))
    return {f"R{i + 1}": list(part) for i, part in enumerate(np.array_split(ids, n_reg))}

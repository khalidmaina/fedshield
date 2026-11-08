"""Federated training simulation: clients, hierarchy, privacy, attacks, evaluation."""
import json
import os
import time
import warnings

import joblib
import numpy as np
import pandas as pd
import torch
import yaml
from torch.nn.utils import parameters_to_vector, vector_to_parameters
from torch.utils.data import DataLoader, TensorDataset

from .aggregation import aggregate
from .attacks import craft
from .data import load, regions_for
from .metrics import camouflage_ratio, detection_metrics, exclusion_metrics
from .models import SAE, LocalDetector, fit_iforest, if_scores, sae_loss, sae_scores
from .poisoning import attack_pool_for, mix, poisoned_rate
from .privacy import randomize_update, track_b_epsilon

warnings.filterwarnings("ignore", message=".*Secure RNG.*")
warnings.filterwarnings("ignore", message=".*Using a non-full backward hook.*")
warnings.filterwarnings("ignore", message=".*Optimal order.*")
warnings.filterwarnings("ignore", message="Mean of empty slice")


def get_vec(model):
    return parameters_to_vector(model.parameters()).detach().cpu().numpy().astype(np.float64)


def set_vec(model, vec):
    vector_to_parameters(torch.as_tensor(vec, dtype=torch.float32), model.parameters())


class Trainer:
    """Plain local training (no DP). Supports FedProx through prox_mu."""

    def __init__(self, d, cfg, X, seed):
        m = cfg["model"]
        self.cfg, self.model = cfg, SAE(d, m["hidden"], m["latent"])
        self.X = torch.tensor(X, dtype=torch.float32)
        self.gen = torch.Generator().manual_seed(seed)

    def set_data(self, X):
        self.X.copy_(torch.as_tensor(X, dtype=torch.float32))

    def train(self, start_vec, epochs, mu=0.0):
        m, b = self.cfg["model"], self.cfg["fl"]["batch_size"]
        set_vec(self.model, start_vec)
        anchor = [p.detach().clone() for p in self.model.parameters()]
        opt = torch.optim.Adam(self.model.parameters(), lr=m["lr"])
        loader = DataLoader(TensorDataset(self.X), batch_size=b, shuffle=True, generator=self.gen)
        self.model.train()
        for _ in range(epochs):
            for (xb,) in loader:
                opt.zero_grad()
                x_hat, h = self.model(xb)
                loss = sae_loss(xb, x_hat, h, m["rho"], m["beta"])
                if mu > 0:
                    loss = loss + 0.5 * mu * sum(((p - a) ** 2).sum() for p, a in zip(self.model.parameters(), anchor))
                loss.backward()
                opt.step()
        return get_vec(self.model)


class DPTrainer:
    """Track A: record-level DP-SGD with Opacus (Poisson sampling, RDP accountant).
    One privacy engine per client is kept for the whole run, so epsilon accumulates."""

    def __init__(self, d, cfg, X, seed):
        from opacus import PrivacyEngine
        m, a = cfg["model"], cfg["privacy"]["A"]
        self.cfg = cfg
        torch.manual_seed(seed)
        model = SAE(d, m["hidden"], m["latent"])
        self.X = torch.tensor(X, dtype=torch.float32)
        opt = torch.optim.Adam(model.parameters(), lr=m["lr"])
        loader = DataLoader(TensorDataset(self.X), batch_size=cfg["fl"]["batch_size"])
        self.engine = PrivacyEngine(accountant="rdp")
        self.model, self.opt, self.loader = self.engine.make_private(
            module=model, optimizer=opt, data_loader=loader,
            noise_multiplier=a["noise_multiplier"], max_grad_norm=a["max_grad_norm"], poisson_sampling=True)

    def set_data(self, X):
        self.X.copy_(torch.as_tensor(X, dtype=torch.float32))

    def train(self, start_vec, epochs, mu=0.0):
        m = self.cfg["model"]
        set_vec(self.model._module, start_vec)
        self.opt.original_optimizer.state.clear()       # fresh Adam state every round
        self.model.train()
        for _ in range(epochs):
            for (xb,) in self.loader:
                if xb.shape[0] == 0:                     # possible with Poisson sampling
                    continue
                self.opt.zero_grad()
                x_hat, h = self.model(xb)
                loss = sae_loss(xb, x_hat, h, m["rho"], m["beta"])
                loss.backward()
                self.opt.step()
        return get_vec(self.model._module)

    def epsilon(self, delta):
        return float(self.engine.accountant.get_epsilon(delta))


def _groups(cfg, ids):
    if cfg["fl"]["hierarchy"] == "flat" or cfg["aggregation"]["place"] == "global":
        return {"ALL": list(ids)}
    return regions_for(cfg, ids)


def _f_for(cfg, n):
    f = cfg["aggregation"]["f"]
    return max(0, (n - 3) // 2) if f == "auto" else int(f)


def _frozen_scores(det, model, X):
    s_sae = det.n_sae(sae_scores(model, X))
    s_if = det.n_if(if_scores(det.forest, X))
    return {"sae": s_sae, "if": s_if, "hybrid": det.alpha * s_sae + (1 - det.alpha) * s_if}


def run(cfg, run_dir=None, verbose=True):
    t_start = time.time()
    seed = int(cfg["seed"])
    np.random.seed(seed)
    torch.manual_seed(seed)
    rng = np.random.default_rng(seed)

    clients, feats = load(cfg)
    ids = sorted(clients)
    d = len(feats)
    fl, agg_cfg, pcfg = cfg["fl"], cfg["aggregation"], cfg["privacy"]
    track = pcfg["track"]
    byz = list(cfg["byzantine"]["clients"]) if cfg["byzantine"]["attack"] != "none" else []
    pois = list(cfg["poison"]["clients"])     # tracked even when pdr = 0 (the baseline)
    for c in byz + pois:
        if c not in clients:
            raise ValueError(f"Client {c} in config does not exist. Clients: {ids}")
    if set(byz) & set(pois):
        raise ValueError("A client cannot be both Byzantine and normality-poisoned")
    mu = float(fl["prox_mu"])
    if track == "A" and mu > 0:
        print("Note: FedProx is not combined with Track A (DP-SGD); prox_mu set to 0.")
        mu = 0.0
    if pois and int(cfg["poison"]["start_round"]) < 2:
        raise ValueError("poison.start_round must be >= 2 so detectors can be frozen before poisoning")

    groups = _groups(cfg, ids)
    region_of = {c: r for r, mem in regions_for(cfg, ids).items() for c in mem}
    n_k = {c: len(clients[c].X_train) for c in ids}

    # Local datasets (poisoned / backdoor clients get mixed data later)
    target = cfg["poison"]["target_attack"]
    pools = {c: attack_pool_for(clients[c], clients, target, pois) for c in pois}
    if cfg["byzantine"]["attack"] == "replacement":
        bd_target = cfg["byzantine"]["target_attack"]
        for c in byz:
            pool = attack_pool_for(clients[c], clients, bd_target, byz)
            clients[c].X_backdoor = mix(clients[c].X_train, pool, 0.5, rng)

    TrainerCls = DPTrainer if track == "A" else Trainer
    trainers = {}
    for i, c in enumerate(ids):
        X0 = clients[c].X_backdoor if hasattr(clients[c], "X_backdoor") else clients[c].X_train
        trainers[c] = TrainerCls(d, cfg, X0, seed + i)

    torch.manual_seed(seed)
    m = cfg["model"]
    init = SAE(d, m["hidden"], m["latent"])
    global_vec = get_vec(init)
    local_vecs = {c: global_vec.copy() for c in ids}          # used when fl.mode == local
    eval_model = SAE(d, m["hidden"], m["latent"])

    forests = {c: fit_iforest(clients[c].X_train, cfg["detection"]["if_trees"],
                              cfg["detection"]["if_samples"], seed) for c in ids}
    part_count = dict.fromkeys(ids, 0)
    current_train = {c: clients[c].X_train for c in ids}
    frozen, log_rows, upd_log = {}, [], []
    T = int(fl["rounds"])

    for t in range(1, T + 1):
        # participation
        if fl["client_fraction"] < 1.0:
            k = max(1, int(round(fl["client_fraction"] * len(ids))))
            parts = sorted(rng.choice(ids, size=k, replace=False).tolist())
        else:
            parts = list(ids)

        # normality poisoning: compromised hosts' training data
        rate = poisoned_rate(cfg, t)
        for c in pois:
            current_train[c] = mix(clients[c].X_train, pools[c], rate, rng)
            trainers[c].set_data(current_train[c])

        # local training
        raw = {}
        for c in parts:
            start = local_vecs[c] if fl["mode"] == "local" else global_vec
            raw[c] = trainers[c].train(start, int(fl["local_epochs"]), mu) - start
            part_count[c] += 1

        if fl["mode"] == "local":
            for c in parts:
                local_vecs[c] = local_vecs[c] + raw[c]
            row = {"round": t}
        else:
            # what each client releases
            released = {}
            for c in parts:
                if track == "B" and c not in byz:
                    released[c] = randomize_update(raw[c], pcfg["B"]["clip"], pcfg["B"]["noise_multiplier"], rng)
                else:
                    released[c] = raw[c]

            # Byzantine clients craft their update inside their aggregation group
            for g, members in groups.items():
                mem = [c for c in members if c in parts]
                g_byz = [c for c in mem if c in byz]
                if not g_byz:
                    continue
                if cfg["byzantine"]["knowledge"] == "full":
                    honest = np.stack([released[c] for c in mem if c not in byz])
                else:
                    honest = np.stack([raw[c] for c in g_byz])
                for c in g_byz:
                    mal = craft(cfg["byzantine"]["attack"], raw[c], honest, len(mem), len(g_byz), cfg, rng)
                    if track == "B" and cfg["byzantine"]["mimic_noise"]:
                        mal = mal + rng.normal(0.0, pcfg["B"]["noise_multiplier"] * pcfg["B"]["clip"], size=mal.shape)
                    released[c] = mal

            if cfg["log_updates"]:
                for c in parts:
                    upd_log.append((t, c, clients[c].role, released[c].astype(np.float32)))

            # aggregation
            agg_parts, weights, row = [], [], {"round": t}
            excl, camo, sel_pois, sel_hon, n_pois, n_hon = [], [], 0, 0, 0, 0
            for g, members in groups.items():
                mem = [c for c in members if c in parts]
                if not mem:
                    continue
                f = _f_for(cfg, len(mem))
                try:
                    a, sel_idx = aggregate(agg_cfg["rule"], [released[c] for c in mem], [n_k[c] for c in mem],
                                           f=f, m=agg_cfg["m"], seed=seed)
                except ValueError as e:
                    raise ValueError(f"Group {g} in round {t}: {e}. Use client_fraction 1.0 or fewer assumed f.")
                sel = [mem[i] for i in sel_idx]
                agg_parts.append(a)
                weights.append(sum(n_k[c] for c in sel))
                excl.append(exclusion_metrics(mem, sel, byz))
                g_pois = [c for c in mem if c in pois]
                g_hon = [c for c in mem if c not in byz and c not in pois]
                sel_pois += len(set(sel) & set(g_pois))
                n_pois += len(g_pois)
                sel_hon += len(set(sel) & set(g_hon))
                n_hon += len(g_hon)
                if g_pois:
                    camo.append(camouflage_ratio(released, g_hon, g_pois))
            global_vec = global_vec + np.average(np.stack(agg_parts), axis=0, weights=weights)
            for key in ("excl_precision", "excl_recall", "benign_excluded"):
                row[key] = float(np.nanmean([e[key] for e in excl])) if excl else float("nan")
            row["poisoned_selected_rate"] = sel_pois / n_pois if n_pois else float("nan")
            row["honest_selected_rate"] = sel_hon / n_hon if n_hon else float("nan")
            row["camouflage_ratio"] = float(np.nanmean(camo)) if camo else float("nan")

        # validation reconstruction error (benign windows)
        losses = []
        for c in ids:
            set_vec(eval_model, local_vecs[c] if fl["mode"] == "local" else global_vec)
            v = clients[c]
            losses.append(float(sae_scores(eval_model, v.X_val[v.y_val == 0]).mean()))
        row["val_recon_mean"] = float(np.mean(losses))

        # RQ5: freeze detectors before poisoning starts, then track the target behaviour
        if pois:
            eval_hosts = [c for c in ids if c not in pois and c not in byz and (clients[c].a_test == target).any()]
            if t == int(cfg["poison"]["start_round"]) - 1:
                for c in eval_hosts:
                    snap = SAE(d, m["hidden"], m["latent"])
                    set_vec(snap, local_vecs[c] if fl["mode"] == "local" else global_vec)
                    frozen[c] = LocalDetector(snap, clients[c].X_train, cfg, forest=forests[c]).calibrate(
                        clients[c].X_val, clients[c].y_val)
            if frozen:
                rec = {"sae": [], "hybrid": []}
                fpr = {"sae": [], "hybrid": []}
                for c, det in frozen.items():
                    set_vec(eval_model, local_vecs[c] if fl["mode"] == "local" else global_vec)
                    v = clients[c]
                    s_t = _frozen_scores(det, eval_model, v.X_test[v.a_test == target])
                    s_b = _frozen_scores(det, eval_model, v.X_test[v.y_test == 0])
                    for k in rec:
                        rec[k].append(float((s_t[k] > det.thr[k]).mean()))
                        fpr[k].append(float((s_b[k] > det.thr[k]).mean()))
                for k in rec:
                    row[f"target_recall_{k}"] = float(np.mean(rec[k]))
                    row[f"fpr_{k}"] = float(np.mean(fpr[k]))
            row["poison_rate"] = rate
        log_rows.append(row)
        if verbose and (t == 1 or t % 5 == 0 or t == T):
            extra = f" target_recall_sae={row['target_recall_sae']:.3f}" if "target_recall_sae" in row else ""
            print(f"round {t:3d}/{T}  val_recon={row['val_recon_mean']:.5f}{extra}", flush=True)

    # ---------------- final evaluation ----------------
    per_client, detectors = [], {}
    for c in ids:
        model_c = SAE(d, m["hidden"], m["latent"])
        set_vec(model_c, local_vecs[c] if fl["mode"] == "local" else global_vec)
        v = clients[c]
        forest = forests[c]
        if c in pois:                       # its local data is poisoned too
            forest = fit_iforest(current_train[c], cfg["detection"]["if_trees"], cfg["detection"]["if_samples"], seed)
        det = LocalDetector(model_c, current_train[c], cfg, forest=forest).calibrate(v.X_val, v.y_val)
        detectors[c] = det
        sc = det.scores(v.X_test)
        rec = {"client": c, "role": v.role, "region": region_of.get(c, ""), "byzantine": c in byz,
               "poisoned": c in pois, "alpha": det.alpha}
        for k in ("sae", "if", "hybrid"):
            for key, val in detection_metrics(v.y_test, sc[k], det.thr[k], v.a_test).items():
                rec[f"{k}_{key}"] = val
        per_client.append(rec)
    pc = pd.DataFrame(per_client)
    clean = pc[~pc["byzantine"] & ~pc["poisoned"]]
    summary = {"name": cfg["name"], "seed": seed, "runtime_sec": round(time.time() - t_start, 1)}
    for k in ("sae", "if", "hybrid"):
        for key in ("precision", "recall", "f1", "fpr", "pr_auc"):
            summary[f"{k}_{key}"] = float(clean[f"{k}_{key}"].mean())
    # privacy accounting
    delta = float(pcfg["delta"])
    if track == "A":
        eps = {c: trainers[c].epsilon(delta) for c in ids}
    elif track == "B":
        eps = {c: track_b_epsilon(part_count[c], pcfg["B"]["noise_multiplier"], delta) for c in ids}
    else:
        eps = {c: float("inf") for c in ids}
    summary["epsilon_max"] = float(max(eps.values()))
    summary["epsilon_mean"] = float(np.mean(list(eps.values())))
    log = pd.DataFrame(log_rows)
    for key in ("excl_precision", "excl_recall", "benign_excluded", "poisoned_selected_rate",
                "honest_selected_rate", "camouflage_ratio"):
        if key in log:
            summary[f"{key}_mean"] = float(log[key].mean())
    if pois and "target_recall_sae" in log:
        start = int(cfg["poison"]["start_round"])
        base = log.loc[log["round"] == start - 1]
        for k in ("sae", "hybrid"):
            b0 = float(base[f"target_recall_{k}"].iloc[0]) if len(base) else float("nan")
            summary[f"target_recall_{k}_before"] = b0
            summary[f"target_recall_{k}_final"] = float(log[f"target_recall_{k}"].iloc[-1])
            # first round (counted from the start of poisoning) at which recall on the target
            # behaviour has fallen to half of its pre-poisoning value; None = never / undefined
            after = log[(log["round"] >= start) & (log[f"target_recall_{k}"] <= 0.5 * b0)]
            summary[f"rounds_to_concealment_{k}"] = (int(after["round"].iloc[0] - start + 1)
                                                     if len(after) and b0 > 0 else None)
            summary[f"fpr_{k}_final"] = float(log[f"fpr_{k}"].iloc[-1])

    if run_dir:
        os.makedirs(run_dir, exist_ok=True)
        with open(os.path.join(run_dir, "config.yaml"), "w") as f:
            yaml.safe_dump(cfg, f, sort_keys=False)
        log.to_csv(os.path.join(run_dir, "round_log.csv"), index=False)
        pc.to_csv(os.path.join(run_dir, "per_client.csv"), index=False)
        with open(os.path.join(run_dir, "privacy.json"), "w") as f:
            json.dump({"track": track, "delta": delta, "epsilon": eps}, f, indent=2)
        if upd_log:
            np.savez_compressed(os.path.join(run_dir, "updates.npz"),
                                rounds=np.array([u[0] for u in upd_log]), clients=np.array([u[1] for u in upd_log]),
                                roles=np.array([u[2] for u in upd_log]), vecs=np.stack([u[3] for u in upd_log]))
        if cfg.get("save_artifacts"):
            art = os.path.join(run_dir, "artifacts")
            os.makedirs(art, exist_ok=True)
            set_vec(eval_model, global_vec)
            torch.save({"state_dict": eval_model.state_dict(), "d": d, "hidden": m["hidden"],
                        "latent": m["latent"], "features": feats,
                        "scale_cap": float(cfg["data"].get("scale_cap", 1e5))}, os.path.join(art, "global_sae.pt"))
            for c, det in detectors.items():
                joblib.dump({"forest": det.forest, "n_sae": (det.n_sae.lo, det.n_sae.hi),
                             "n_if": (det.n_if.lo, det.n_if.hi), "alpha": det.alpha, "thr": det.thr},
                            os.path.join(art, f"detector_{c}.joblib"))
        with open(os.path.join(run_dir, "final_metrics.json"), "w") as f:
            json.dump(summary, f, indent=2)
    if verbose:
        keys = ("sae_f1", "if_f1", "hybrid_f1", "hybrid_fpr", "epsilon_max")
        print(json.dumps({k: summary[k] for k in keys}, indent=None))
    return summary

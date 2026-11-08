"""Detection and aggregation metrics."""
import numpy as np
from sklearn.metrics import average_precision_score, f1_score, precision_score, recall_score


def detection_metrics(y, score, thr, attacks=None):
    pred = (score > thr).astype(int)
    out = {
        "precision": float(precision_score(y, pred, zero_division=0)),
        "recall": float(recall_score(y, pred, zero_division=0)),
        "f1": float(f1_score(y, pred, zero_division=0)),
        "fpr": float(pred[y == 0].mean()) if (y == 0).any() else float("nan"),
        "fn": int(((pred == 0) & (y == 1)).sum()),
        "pr_auc": float(average_precision_score(y, score)) if 0 < y.sum() < len(y) else float("nan"),
    }
    if attacks is not None:
        for a in sorted(set(attacks) - {""}):
            m = attacks == a
            out[f"recall_{a}"] = float(pred[m].mean())
    return out


def exclusion_metrics(group_ids, selected, malicious):
    """Precision/recall of excluding malicious updates, and the fraction of benign
    updates that were wrongly excluded, for one aggregation group in one round."""
    excluded = set(group_ids) - set(selected)
    mal = set(group_ids) & set(malicious)
    ben = set(group_ids) - mal
    tp = len(excluded & mal)
    return {
        "excl_precision": tp / len(excluded) if excluded else float("nan"),
        "excl_recall": tp / len(mal) if mal else float("nan"),
        "benign_excluded": len(excluded & ben) / len(ben) if ben else float("nan"),
    }


def camouflage_ratio(updates_by_id, honest_ids, target_ids):
    """Distance of each target (poisoned) update to the honest mean, divided by the
    median distance of honest updates to that mean. Values near 1 mean the poisoned
    update looks like an ordinary honest update."""
    if not target_ids or len(honest_ids) < 2:
        return float("nan")
    H = np.stack([updates_by_id[i] for i in honest_ids])
    mu = H.mean(axis=0)
    med = np.median(np.linalg.norm(H - mu, axis=1)) + 1e-12
    return float(np.mean([np.linalg.norm(updates_by_id[t] - mu) / med for t in target_ids]))

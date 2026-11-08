#!/usr/bin/env python3
"""RQ6: can an honest-but-curious aggregator tell a host's role from its updates?

Usage:
    python scripts/property_inference.py --run results/<run_name>
The run must have been made with log_updates=true. A classifier is trained on the
released updates of some hosts and tested on hosts it has never seen (leave-one-
host-out), so it cannot just memorise host identities. Output: macro one-vs-rest AUC
(0.5 = chance) in <run>/property_inference.json.
"""
import argparse
import json
import os

import numpy as np
from sklearn.decomposition import PCA
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import roc_auc_score
from sklearn.model_selection import LeaveOneGroupOut
from sklearn.pipeline import make_pipeline
from sklearn.preprocessing import StandardScaler, label_binarize


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--run", required=True)
    ap.add_argument("--components", type=int, default=20)
    args = ap.parse_args()
    z = np.load(os.path.join(args.run, "updates.npz"))
    X, roles, hosts = z["vecs"].astype(np.float64), z["roles"], z["clients"]
    classes = np.unique(roles)
    if len(classes) < 2:
        raise SystemExit("Need at least two different roles")
    proba = np.zeros((len(X), len(classes)))
    for tr, te in LeaveOneGroupOut().split(X, roles, hosts):
        if len(np.unique(roles[tr])) < len(classes):
            raise SystemExit("Each role needs at least two hosts for leave-one-host-out")
        k = min(args.components, len(tr) - 1, X.shape[1])
        clf = make_pipeline(StandardScaler(), PCA(n_components=k, random_state=0),
                            LogisticRegression(max_iter=3000))
        clf.fit(X[tr], roles[tr])
        p = clf.predict_proba(X[te])
        for j, c in enumerate(clf.classes_):
            proba[te, list(classes).index(c)] = p[:, j]
    y = label_binarize(roles, classes=classes)
    if y.shape[1] == 1:
        auc = roc_auc_score(y.ravel(), proba[:, 1])
    else:
        auc = roc_auc_score(y, proba, average="macro", multi_class="ovr")
    acc = float((classes[proba.argmax(1)] == roles).mean())
    res = {"macro_auc": float(auc), "accuracy": acc, "chance_accuracy": float(1 / len(classes)),
           "n_updates": int(len(X)), "roles": classes.tolist()}
    with open(os.path.join(args.run, "property_inference.json"), "w") as f:
        json.dump(res, f, indent=2)
    print(json.dumps(res, indent=2))


if __name__ == "__main__":
    main()

#!/usr/bin/env python3
"""Quick check that every part of the pipeline runs (about 5-10 minutes on a laptop).

Usage (repository root, venv active):
    python tests/smoke_test.py
It creates a tiny synthetic dataset, runs every mode for a few rounds and prints
PASS/FAIL for each. Results go to results/smoke/ and can be deleted afterwards.
"""
import os
import subprocess
import sys
import time

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
os.chdir(REPO)
DATA = "data/processed/smoke_windows.csv"
COMMON = [f"data.path={DATA}", "fl.rounds=5", "poison.start_round=3", "poison.ramp_rounds=2",
          "out_dir=results/smoke"]
CASES = {
    "fedavg": ["aggregation.rule=fedavg"],
    "krum": ["aggregation.rule=krum"],
    "multikrum": ["aggregation.rule=multikrum"],
    "distance_filter": ["aggregation.rule=distance_filter"],
    "flat": ["fl.hierarchy=flat"],
    "global_place": ["aggregation.place=global", "aggregation.f=auto"],
    "local_only": ["fl.mode=local"],
    "fedprox": ["fl.prox_mu=0.01"],
    "trackA": ["privacy.track=A"],
    "trackB": ["privacy.track=B", "privacy.B.noise_multiplier=2.0"],
    "gaussian": ["byzantine.clients=[fs-dev-1]", "byzantine.attack=gaussian"],
    "signflip": ["byzantine.clients=[fs-dev-1]", "byzantine.attack=signflip"],
    "scale": ["byzantine.clients=[fs-dev-1]", "byzantine.attack=scale"],
    "lie": ["byzantine.clients=[fs-dev-1]", "byzantine.attack=lie"],
    "minmax": ["byzantine.clients=[fs-dev-1,fs-web-3]", "byzantine.attack=minmax"],
    "minmax_partial": ["byzantine.clients=[fs-dev-1]", "byzantine.attack=minmax", "byzantine.knowledge=partial"],
    "replacement": ["byzantine.clients=[fs-dev-1]", "byzantine.attack=replacement"],
    "f_misestimated": ["byzantine.clients=[fs-dev-1,fs-dev-2]", "byzantine.attack=lie", "aggregation.f=1",
                       "regions={}", "fl.hierarchy=flat"],
    "lie_trackB": ["byzantine.clients=[fs-dev-1]", "byzantine.attack=lie", "privacy.track=B"],
    "poison": ["poison.clients=[fs-db-1]", "poison.pdr=0.3"],
    "poison_local": ["poison.clients=[fs-db-1]", "poison.pdr=0.3", "fl.mode=local"],
    "poison_trackA": ["poison.clients=[fs-db-1]", "poison.pdr=0.2", "privacy.track=A"],
    "poison_trackB": ["poison.clients=[fs-db-1]", "poison.pdr=0.2", "privacy.track=B"],
    "poison_pdr0": ["poison.clients=[fs-db-1]", "poison.pdr=0.0"],
    "updates_artifacts": ["log_updates=true", "save_artifacts=true", "privacy.track=B"],
}


def main():
    py = sys.executable
    subprocess.run([py, "scripts/make_synthetic.py", "--sessions", "4", "--windows-per-session", "300",
                    "--attack-windows", "30", "--out", DATA], check=True)
    failed = []
    for name, sets in CASES.items():
        t = time.time()
        r = subprocess.run([py, "scripts/run_experiment.py", "--name", name, "--set", *COMMON, *sets],
                           capture_output=True, text=True)
        ok = r.returncode == 0 and os.path.exists(f"results/smoke/{name}/final_metrics.json")
        print(f"{'PASS' if ok else 'FAIL'}  {name:<18} {time.time() - t:5.1f}s", flush=True)
        if not ok:
            failed.append(name)
            print(r.stdout[-1500:], r.stderr[-3000:])
    # property inference on the logged updates
    r = subprocess.run([py, "scripts/property_inference.py", "--run", "results/smoke/updates_artifacts"],
                       capture_output=True, text=True)
    print(f"{'PASS' if r.returncode == 0 else 'FAIL'}  property_inference")
    if r.returncode != 0:
        failed.append("property_inference")
        print(r.stderr[-3000:])
    print("\nALL PASSED" if not failed else f"\nFAILED: {failed}")
    sys.exit(1 if failed else 0)


if __name__ == "__main__":
    main()

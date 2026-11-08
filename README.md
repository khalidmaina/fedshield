# FedShield

eBPF-enhanced hierarchical federated learning for privacy-preserving threat detection, integrated with the Wazuh SIEM.
Thesis project of Hasib Al Tahsin and Khalid Maina.

12 Docker containers play the monitored hosts, one eBPF collector turns their kernel activity into 10-second feature
windows, and a federated learning simulation trains a shared sparse autoencoder (plus a local Isolation Forest per
host) under differential privacy and Multi-Krum. The main research question is **normality poisoning**: can a
compromised host teach the shared detector that the attacker's activity is normal? See
[docs/architecture.md](docs/architecture.md).

## Setup (Ubuntu 24.04)

```bash
sudo apt update && sudo apt install -y git make python3-venv python3-dev build-essential \
    bpftrace linux-headers-$(uname -r) docker.io docker-compose-v2
sudo usermod -aG docker $USER          # then log out and back in

git clone git@github.com:khalidmaina/fedshield.git ~/fedshield && cd ~/fedshield
python3 -m venv .venv && source .venv/bin/activate
make install                           # PyTorch (CPU), pinned libraries, dev tools
make test                              # unit tests
make smoke                             # every FL mode on synthetic data (~5-10 min)
```

Use Ubuntu 24.04 (Python 3.12): the pinned libraries do not install on newer Python versions.

## Common commands

| Command | What it does |
|---|---|
| `make lint` / `make test` / `make smoke-quick` | What CI runs on every pull request |
| `make testbed-up` / `make testbed-down` | Start / stop the 12 hosts + c2-server |
| `sudo python3 collector/collector.py --duration 7200` | Collect 2 hours of feature windows |
| `python scripts/run_experiment.py --set key=value --name NAME` | One experiment |
| `python scripts/run_grid.py --grid configs/grids/FILE.yaml --workers 2` | A whole grid |
| `make help` | Everything else |

## Repository

| Folder | Contents |
|---|---|
| `testbed/` | Docker Compose testbed: 12 hosts (web, db, build, dev), c2-server, 5 simulated attacks |
| `collector/` | bpftrace script + collector (19 features per 10-second window, counts only) |
| `fedshield/` | Python package: features, data, models, aggregation, privacy, attacks, poisoning, FL simulation |
| `scripts/` | Command-line tools (schedule, dataset, experiments, plots, live detection) |
| `configs/` | `base.yaml` and one experiment grid per research question |
| `wazuh/` | Wazuh rule and log-reading configuration |
| `tests/` | `unit/` (CI), `integration/` (manual on Linux), `smoke_test.py` |
| `docs/` | Architecture, decision notes, data protocol, experiment register, daily log |
| `thesis/` | Thesis sources |

## Working on it

Read [CONTRIBUTING.md](CONTRIBUTING.md): one branch per issue, pull requests reviewed by the partner, CI must pass,
and freeze points protect the data and the results. Synthetic data is only for testing code; no synthetic number
goes into the thesis.

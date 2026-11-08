# FedShield

eBPF-enhanced hierarchical federated learning for privacy-preserving threat detection, integrated with the Wazuh SIEM.
Thesis project of Hasib Al Tahsin and Khalid Maina.

12 Docker containers will play the monitored hosts, one eBPF collector will turn their kernel activity into
10-second feature windows, and a federated learning simulation will train a shared sparse autoencoder (plus a local
Isolation Forest per host) under differential privacy and Multi-Krum. The main research question is **normality
poisoning**: can a compromised host teach the shared detector that the attacker's activity is normal? The target
design is in [docs/architecture.md](docs/architecture.md).

## Build status

The system is rebuilt module by module, one sprint at a time
([decision 0004](docs/decisions/0004-rebuild-from-scratch.md)). The original reference code is kept read-only at the
tag [`reference-v0`](https://github.com/khalidmaina/fedshield/tree/reference-v0).

| Sprint | Module | Folder | Status |
|---|---|---|---|
| S0 | Project skeleton, CI, docs | `.github/`, `docs/`, `Makefile` | done |
| S1 | Testbed: 12 hosts, c2-server, 5 attacks, in-host agent | `testbed/`, `fedshield/control.py` | in review |
| S2 | eBPF collector and features | `collector/`, `fedshield/features.py` | next |
| S3 | Attack schedule and dataset builder | `scripts/`, `fedshield/data.py` | planned |
| S4 | Detectors: SAE, Isolation Forest, hybrid | `fedshield/models.py` | planned |
| S5 | FL core, configs, grid runner, smoke test | `fedshield/fl.py`, `configs/` | planned |
| S6-S11 | Robustness, privacy, RQ4, RQ5, RQ6 | `fedshield/` | planned |
| S12 | Wazuh and overhead | `wazuh/`, `scripts/` | planned |

## Setup (Ubuntu 24.04)

```bash
sudo apt update && sudo apt install -y git make python3-venv python3-dev build-essential \
    bpftrace linux-headers-$(uname -r) docker.io docker-compose-v2
sudo usermod -aG docker $USER          # then log out and back in

git clone git@github.com:khalidmaina/fedshield.git ~/fedshield && cd ~/fedshield
python3 -m venv .venv && source .venv/bin/activate
make install                           # PyTorch (CPU), pinned libraries, dev tools
make lint && make test
```

Use Ubuntu 24.04 (Python 3.12): the pinned libraries do not install on newer Python versions.

## Working on it

Read [CONTRIBUTING.md](CONTRIBUTING.md): one branch per issue, pull requests reviewed by the partner, CI must pass,
freeze points protect the data and the results, and the reference code is read, never copied. `make help` lists the
common commands.

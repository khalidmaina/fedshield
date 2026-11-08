# FedShield

eBPF-enhanced hierarchical federated learning for privacy-preserving threat detection,
integrated with the Wazuh SIEM. Thesis project of Hasib Al Tahsin and Khalid Maina.

| Folder | What it contains |
|---|---|
| `collector/` | eBPF collector (bpftrace) that turns container activity into 10-second feature windows |
| `testbed/` | Docker testbed: 12 simulated hosts, lab C2 server, simulated attacks |
| `fedshield/` | Python package: data, models, aggregation, privacy, attacks, FL simulation |
| `scripts/` | Command-line tools (build dataset, run experiments and grids, plots, live detection) |
| `configs/` | `base.yaml` and experiment grids for RQ1-RQ6 |
| `wazuh/` | Wazuh rule and log-reading configuration |
| `tests/` | `smoke_test.py` checks every mode in a few minutes |
| `docs/` | Daily log |

Quick check after installing: `python tests/smoke_test.py`

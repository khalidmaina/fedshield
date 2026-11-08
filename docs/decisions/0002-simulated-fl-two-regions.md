# 0002. Simulated federated learning with two regions of six

- Status: accepted
- Date: 2026-11-08
- Deciders: Hasib, Khalid

## Context

The proposal describes clients, regional aggregators and a global coordinator as separate machines. RQ5 alone needs
about 288 runs with exact poisoning rates and seeds. Multi-Krum needs `n >= 2f + 3` updates in each region.

## Options

1. Real networked FL (e.g. Flower) with separate processes or containers per client and aggregator.
2. Simulation in one process; data collected once and replayed.
3. Regions: 4 x 3, 3 x 4 or 2 x 6 hosts.

## Decision

Simulate FL in one process (`fedshield/fl.py`), replaying one frozen dataset. Use **2 regions of 6** with mixed roles
(`configs/base.yaml`): the smallest split in which Multi-Krum tolerates one Byzantine client per region. A Flower
demo for real network cost is a "could" item for RQ7.

## Consequences

- Runs are exactly reproducible from a seed, and fast enough for the grids.
- Bytes per round are computed (parameters x 4 bytes x clients), not measured.
- With 4 x 3 or 3 x 4, Multi-Krum could not run at all (f = 0).
- The default compromised host `fs-build-2` sits in Region B; spread to the other region is measured on Region A hosts.
- Open point for Sprint 5: the global coordinator currently weights a region by the samples of the clients its rule
  *selected*, not by the region's total. The proposal requires this alternative to be labelled; decide whether to
  keep it (and document it) or switch to the regional total.
- Open point for later: role-grouped vs mixed regions changes how easily a poisoned update hides (RQ5 "could" axis).

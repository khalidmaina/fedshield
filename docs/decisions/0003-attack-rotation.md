# 0003. Attack rotation and number of sessions

- Status: proposed (decide in Sprint 3, before data collection starts)
- Date: 2026-11-08
- Deciders: Hasib, Khalid

## Context

`scripts/make_schedule.py` gives host `k` attack `ATTACKS[(k + session) % 5]` in a fixed time slot, and
`fedshield/data.py` splits each host's windows 60 / 15 / 25 in time order. With 5 sessions this puts every host's
single beacon session in train, validation or test. A check on 5 synthetic sessions gave:

| Beacon falls in | Hosts |
|---|---|
| training pool | web-3, db-1, db-2, build-2, build-3, dev-1 |
| validation | web-2, build-1 |
| test | web-1 (A), db-3 (B), dev-2 (B), dev-3 (B) |

So RQ5 is evaluated on only **4 hosts** with 48 beacon windows each, and spread into the region without the
compromised host (`fs-build-2`, Region B) on **one** host (`web-1`).

## Options

1. More sessions (e.g. 8, one held out for the SIEM replay) with the same rotation.
2. A rotation designed so beacon falls in the test portion of at least 6 hosts, spread over both regions, while the
   compromised hosts keep beacon in training.
3. Beacon in more than one slot per session.

## Decision

To be taken in Sprint 3 using `scripts/dataset_report.py` on a synthetic dataset built with the candidate schedule.

## Consequences

Fixes the evaluation base of the main research question before any real data is collected.

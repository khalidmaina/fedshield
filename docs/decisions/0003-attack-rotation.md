# 0003. Eight sessions split by session; two attacks per host per session; every host evaluable for RQ5

- Status: accepted (was proposed; decided in Sprint 3)
- Date: 2026-11-12
- Deciders: Hasib, Khalid

## Context

The reference design gave each host one attack per session in a fixed time slot, rotating 5 attacks over 5 sessions,
and split each host's windows 60 / 15 / 25 by time. A check on 5 synthetic sessions put beacon in the test portion
of only **4 hosts** (one of them in the region without the default compromised host), 48 windows each. RQ5 would
rest on very few hosts, and which host could be "compromised" depended on accidents of the rotation.

## Options

1. More sessions with the same rotation.
2. A rotation tuned so beacon lands in test for more hosts.
3. Split by session and design each split's attacks explicitly.

## Decision

Option 3 (`fedshield/schedule.py`, schedules committed in `testbed/schedules/`):

| Session | Split | Per host |
|---|---|---|
| 1-4 | train | 8 attacks: beacon twice (different sessions), each other attack at least once |
| 5 | val | beacon + 1 other |
| 6-7 | test | beacon + 3 others (val + test cover all 5 for every host) |
| 8 | holdout | beacon + 1 other; never used for training (SIEM replay, RQ7) |

- 2 attacks per host per session, one in each half (start between minutes 6-49 and 63-106), 8 minutes each, at
  random quarter-minute times (seed 7); the first and last 6 minutes and the middle 6 minutes are quiet.
- At most 4 attacks at once and never two miners at once, so one attack's CPU load does not change other hosts'
  normal behaviour.
- The split comes from the session, so training data always precedes test data in time, as in a deployment.

## Evidence (2026-11-12)

The generated plan (`make schedules`) gives every host every attack in train with beacon twice, beacon once in val,
test and holdout, all 5 attacks across val + test, and at most 4 attacks at once in every session (unit-tested).

End to end on the live testbed, with a 16-minute version of session 1 (24 one-minute attacks, real collector and
agents): 24/24 attacks ran cleanly; 12/12 hosts, no missing windows, 0 lost events; 1,112 labelled windows with
28 ambiguous edge windows dropped. Labels match the kernel signals exactly: every window labelled as an attack shows
that attack's signal feature (beacon 24/24, cred_access 30/30, miner 30/30, persistence 37/37, scan 25/25), and none
of the 966 benign windows shows any of them.

## Consequences

- **Any host can be the compromised one** (beacon in its training data, 96 windows) and **all 11 others can be
  evaluated** (beacon in their test data), in both regions. RQ5 placements (same region, other region, two hosts)
  are all possible.
- Attack windows are about 13% of each session (16 of 120 minutes per host), versus 7% before.
- Collection takes 8 sessions x 2 hours. Session 8 must not be used to train or tune anything.
- Labels come from the times the hosts report and keep exit codes (`fedshield/session.py`); windows overlapping an
  attack by less than half are dropped as ambiguous, windows touching a failed attack are dropped as excluded
  (`fedshield/dataset.py`).

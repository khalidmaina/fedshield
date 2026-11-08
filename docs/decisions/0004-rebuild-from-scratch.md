# 0004. Rebuild the system module by module; keep the reference code as a guide only

- Status: accepted
- Date: 2026-11-08
- Deciders: Hasib, Khalid

## Context

Sprint 0 imported the reference codebase (`fedshield_pkg`, about 2,900 lines) unchanged so the smoke test could run
from day one. A code review found issues to fix (Track B noise scale, RQ5 evaluation base, grid resume by position,
eBPF overhead measurement, regional weighting). We must be able to explain and defend every design choice in the
thesis.

## Options

1. Keep the reference code on `main` and harden one module per sprint.
2. Strip `main` back to the project skeleton and rebuild each module in its sprint, with the reference as a guide.

## Decision

Option 2. The reference code is kept, unchanged and read-only, at the Git tag **`reference-v0`**
([browse on GitHub](https://github.com/khalidmaina/fedshield/tree/reference-v0)). `main` keeps only the
infrastructure: CI, tooling, templates, docs and decision notes. Each sprint writes its module from scratch.

Rules for using the reference:

- Read the reference module first, understand it, then close it and write our own version.
- Never copy whole files or functions. Short idioms (an argument parser line, a library call) are fine.
- Where our version deliberately differs, say so in the PR and, if it changes the design, in a decision note.
- Known issues from the review are fixed in the first version we write, not later.
- Each module's PR includes its unit tests, written by us. The reference tests can be read as a checklist of what to
  test.

## Consequences

- We own and can explain every line; examiners' "why" questions have answers.
- Slower than option 1: each sprint now writes, not only reviews. If a sprint runs late, `could` items in the plan
  move out first (MoSCoW), and the supervisor is told at the sprint review.
- CI steps for parts not rebuilt yet (smoke test, compose check) are skipped until their files exist, then turn on
  by themselves.
- Build order follows the data flow: testbed (S1), collector and features (S2), schedule and dataset (S3), detectors
  (S4), FL core and smoke test (S5), then one research question at a time.

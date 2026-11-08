---
name: Experiment
about: Run a grid and record its result
title: "exp: "
labels: ["type: experiment"]
---

**Research question:** RQ…

**Hypothesis** (from the proposal, Section 7):

**Grid file:** `configs/grids/….yaml`   **Runs (from `--dry-run`):** …   **Estimated time:** …

**Output:** table / figure that answers the question (`results/summaries/…`)

**Acceptance criteria**
- [ ] Dry run checked, one seed inspected before the full grid
- [ ] Grid finished: … ok / … failed
- [ ] Row in `docs/experiment_register.md` (commit, dataset hash, one-line finding)
- [ ] One paragraph of interpretation, negative results included

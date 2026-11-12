# Decision notes

Short records of design decisions, so the thesis can explain *why* and neither of us re-argues settled points.
One file per decision, numbered: `NNNN-short-title.md`. Never edit an accepted note's decision; write a new note that
supersedes it.

Template:

```markdown
# NNNN. Title

- Status: proposed | accepted | superseded by NNNN
- Date: YYYY-MM-DD
- Deciders: Hasib, Khalid

## Context
What problem or question, and what constrains the answer.

## Options
1. ...
2. ...

## Decision
What we chose, in one or two sentences.

## Consequences
What this makes easier, what it costs, what the thesis must state.
```

| No. | Title | Status |
|---|---|---|
| 0001 | Native Ubuntu 24.04 with Docker Compose | accepted |
| 0002 | Simulated federated learning with two regions of six | accepted |
| 0003 | Eight sessions split by session; two attacks per host per session | accepted |
| 0004 | Rebuild module by module; reference code at tag `reference-v0` | accepted |
| 0005 | Attacks started by an in-host agent; harness leaves no trace in the telemetry | accepted |
| 0006 | Collector: stream events, counts only on disk, loss and overhead per window | accepted |
| 0007 | Toolchain: bpftrace 0.20.2 static build on Ubuntu 22.04/24.04, kernel 6.8; recorded per session | accepted |
| 0008 | Web workload uses 127.0.0.1; all sessions collected on one machine | accepted |
| 0009 | Control folders belong to the user; session runner checks them first | accepted |

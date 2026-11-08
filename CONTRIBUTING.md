# Contributing to FedShield

Two developers, one rule: **nothing reaches `main` without a pull request reviewed by the other person and a green CI run.**
The full plan (sprints, epics, freeze points) is in the FedShield Agile Development Plan doc.

## Daily routine

```bash
cd ~/fedshield && source .venv/bin/activate
git switch main && git pull                     # start of day: get the partner's merged work
git switch -c feat/42-short-name                # new issue -> new branch (or: git switch <your branch>)
# ... work, commit as you go ...
./scripts/daily_push.sh "what I did today"      # end of day: push YOUR BRANCH (never main)
```

Also leave a short comment on your active issue and a block in `docs/daily_log.md`.

## Branches

One short-lived branch per issue, named `<type>/<issue number>-<short-name>`:

| Prefix | For |
|---|---|
| `feat/` | new capability |
| `fix/` | bug fix |
| `exp/` | running an experiment grid and recording its result |
| `spike/` | time-boxed investigation (ends in a decision note) |
| `docs/` | documentation or thesis text |
| `chore/` | tooling, CI, housekeeping |

## Commits

[Conventional Commits](https://www.conventionalcommits.org/): `type(area): what changed (#issue)`.

```
feat(collector): record lost events per window (#42)
fix(fl): resume grid runs by settings, not by position (#57)
test(aggregation): krum picks the honest cluster (#61)
docs(decisions): 0003 attack rotation (#12)
```

## Pull requests

- Small: ideally under 400 changed lines. Split bigger work.
- Fill in the template checklist; write `Closes #42` so the issue closes on merge.
- The other person reviews within one working day. Review for correctness and understanding: if you could not explain the change, ask.
- Squash-merge, then delete the branch.

## Before you open a PR

```bash
make lint          # ruff
make test          # unit tests
make smoke-quick   # a few FL modes on synthetic data
```

Changes to `testbed/` or `collector/` cannot be tested in CI (no eBPF, no live containers there).
Run the matching check from `tests/integration/README.md` on your machine and tick it in the PR.

## Using the reference code

The original code is kept read-only at the tag `reference-v0`
([browse](https://github.com/khalidmaina/fedshield/tree/reference-v0)); see
[decision 0004](docs/decisions/0004-rebuild-from-scratch.md).

```bash
git fetch --tags
git show reference-v0:fedshield/aggregation.py | less      # read one file
git ls-tree -r --name-only reference-v0                     # list everything in it
```

- Read it, understand it, then write your own version. Never copy whole files or functions.
- Fix the known issues from the review in the first version you write.
- If your version differs on purpose, say why in the PR (and in a decision note if the design changes).

## Freeze points

- **Collector freeze (end of Sprint 2):** after this, `collector/`, `fedshield/features.py`, `testbed/host/` and
  `testbed/attacks/` change only through a decision note in `docs/decisions/` agreed by both of you.
- **Data freeze (end of Sprint 4):** the dataset hash in `docs/data_protocol.md` is final.
- **Code freeze (start of Sprint 13):** bug fixes only; thesis numbers come from the tag `v1.0-results`.

## Never commit

Raw data (`data/`), run outputs (`results/` except `results/summaries/`), credentials, or the CICIDS files.
`.gitignore` already excludes them.

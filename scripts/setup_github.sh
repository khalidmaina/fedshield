#!/bin/bash
# One-time GitHub setup: labels, the 14 epic milestones and protection of main.
# Needs the GitHub CLI logged in as an owner of the repository:
#   sudo apt install -y gh && gh auth login
# Usage (from the repository root):
#   ./scripts/setup_github.sh                 # labels + milestones
#   ./scripts/setup_github.sh --protect       # also protect main (run AFTER the first CI run)
# Safe to run again: existing labels are updated, existing milestones are skipped.
# Uses only GitHub's REST API (gh api), so it also works where GraphQL is unavailable.
set -e
# owner/repo from the origin remote (git@github.com:owner/repo.git or https://github.com/owner/repo)
REPO="$(git remote get-url origin | sed -E 's#^(git@github\.com:|https://github\.com/)##; s#\.git$##')"
echo "Setting up $REPO"

urlencode() { python3 -c 'import sys, urllib.parse; print(urllib.parse.quote(sys.argv[1], safe=""))' "$1"; }

label() {
  if gh api "repos/$REPO/labels" -f name="$1" -f color="$2" -f description="$3" >/dev/null 2>&1; then
    echo "  created $1"
  else
    gh api -X PATCH "repos/$REPO/labels/$(urlencode "$1")" -f color="$2" -f description="$3" >/dev/null
    echo "  updated $1"
  fi
}

echo "Labels:"
# type
label "type: feature"    1d76db "New capability"
label "type: bug"        d73a4a "Something is wrong"
label "type: experiment" 5319e7 "Runs a grid and records a result"
label "type: spike"      fbca04 "Time-boxed investigation that ends in a decision note"
label "type: docs"       0075ca "Documentation or thesis text"
label "type: chore"      cfd3d7 "Tooling, CI, housekeeping"
# area
for a in testbed collector data detector fl robustness privacy siem thesis infra; do
  label "area: $a" c5def5 "Part of the system: $a"
done
# research question
for q in 1 2 3 4 5 6 7; do
  label "RQ$q" bfd4f2 "Research question $q"
done
# priority (MoSCoW)
label "priority: must"   b60205 "Required for the thesis"
label "priority: should" e99695 "Important, dropped only if time runs out"
label "priority: could"  f9d0c4 "Nice to have"

echo "Milestones:"
milestone() {
  if gh api "repos/$REPO/milestones?state=all&per_page=100" -q '.[].title' | grep -qxF "$1"; then
    echo "  exists  $1"
  else
    gh api "repos/$REPO/milestones" -f title="$1" -f description="$2" >/dev/null && echo "  created $1"
  fi
}
milestone "E0 Foundations"           "Repo, board, CI, both machines on Ubuntu 24.04, smoke test passes"
milestone "E1 Testbed"               "12 hosts + c2 run for 2 hours; each attack verified"
milestone "E2 Telemetry"             "Collector: 19 features per 10 s window, lost events per window, overhead method"
milestone "E3 Dataset"               "Rotation redesign, sessions collected, backed up, frozen with a hash"
milestone "E4 Detectors (RQ1)"       "SAE, Isolation Forest, hybrid; local and federated baselines"
milestone "E5 FL core (RQ1)"         "Flat and hierarchical FedAvg, FedProx, local mode, region weighting"
milestone "E6 Robustness (RQ3)"      "Krum, Multi-Krum, distance filter, update attacks, misestimated f"
milestone "E7 Privacy (RQ2)"         "Track A (Opacus) and Track B with measured clipping norm"
milestone "E8 DP x robustness (RQ4)" "Noise sweep including small sigma"
milestone "E9 Normality poisoning (RQ5)" "Main grid, same-region placement, sigma sweep, local reference"
milestone "E10 Property inference (RQ6)" "Role inference with and without each privacy track"
milestone "E11 SIEM and overhead (RQ7)"  "Wazuh alerts, latency, held-out alert rate, per-host overhead"
milestone "E12 Evaluation"           "Final grids at v1.0-results, tables, figures, reproducibility"
milestone "E13 Thesis"               "Chapters drafted, reviewed, submitted"

if [ "${1:-}" = "--protect" ]; then
  echo "Protecting main (PR + 1 approval + CI check 'checks', no force-push):"
  gh api -X PUT "repos/$REPO/branches/main/protection" --input - >/dev/null <<'JSON'
{
  "required_status_checks": {"strict": true, "contexts": ["checks"]},
  "enforce_admins": false,
  "required_pull_request_reviews": {"required_approving_review_count": 1},
  "restrictions": null,
  "allow_force_pushes": false,
  "allow_deletions": false
}
JSON
  echo "  main is protected"
fi
echo "Done."

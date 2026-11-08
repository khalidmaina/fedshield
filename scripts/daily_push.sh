#!/bin/bash
# End-of-day routine: save today's work on YOUR BRANCH and upload it.
# It never commits to main: main only changes through reviewed pull requests.
# Usage:  ./scripts/daily_push.sh "what I did today"
set -e
cd "$(dirname "$0")/.."
MSG="${1:-work in progress}"
BRANCH="$(git rev-parse --abbrev-ref HEAD)"
if [ "$BRANCH" = "main" ]; then
  echo "You are on main. Create a branch for your issue first, for example:"
  echo "  git switch -c feat/42-short-name"
  exit 1
fi
git fetch origin
git add -A
if git diff --cached --quiet; then
  echo "Nothing new to commit."
else
  git commit -m "wip: $MSG"
fi
git push -u origin "$BRANCH"
echo "Done: branch $BRANCH is on GitHub. Open or update its pull request when ready."

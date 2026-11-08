#!/bin/bash
# Daily Git routine: get the latest version, save today's work, upload it.
# Usage:  ./scripts/daily_push.sh "what I did today"
set -e
cd "$(dirname "$0")/.."
MSG="${1:-daily update}"
git pull --rebase
git add -A
if git diff --cached --quiet; then
  echo "Nothing new to commit today."
  exit 0
fi
git commit -m "$(date +%F): $MSG"
git push
echo "Done: today's work is on GitHub."

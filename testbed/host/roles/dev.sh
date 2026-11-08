#!/bin/bash
# Developer workstation role: browsing files, small scripts, edits, process listings, archives.
# Kernel activity: a mix of everything, including many /proc reads (ps).
set -u
source "$ROLE_DIR/lib.sh"

PROJECT=/home/dev/project
mkdir -p "$PROJECT" && cd "$PROJECT" || exit 1
for i in $(seq 1 20); do printf 'line %d of notes\n' "$i" > "notes$i.txt"; done

while true; do
  for (( n = 0; n < INTENSITY; n++ )); do
    case $(( RANDOM % 6 )) in
      0) ls -la "$PROJECT" > /dev/null ;;
      1) grep -r "line 1" "$PROJECT" > /dev/null ;;
      2) python3 -c "import json, random; print(json.dumps([random.random() for _ in range(100)]))" > /tmp/out.json ;;
      3) sed -i "s/notes/Notes/" "notes$(( RANDOM % 20 + 1 )).txt" ;;
      4) ps aux > /dev/null; cat /etc/os-release > /dev/null ;;
      5) tar -cf /tmp/project.tar "$PROJECT" 2>/dev/null ;;
    esac
  done
  pause_ms 1000 1500
done

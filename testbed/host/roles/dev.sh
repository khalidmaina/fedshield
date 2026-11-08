#!/bin/bash
# Developer workstation role: browsing files, small scripts, editing and archiving.
mkdir -p /home/dev/project && cd /home/dev/project
for i in $(seq 1 20); do echo "line $i of notes" > "notes$i.txt"; done
while true; do
  for n in $(seq 1 "$INTENSITY"); do
    case $((RANDOM % 6)) in
      0) ls -la /home/dev/project > /dev/null ;;
      1) grep -r "line 1" /home/dev/project > /dev/null ;;
      2) python3 -c "import json, random; print(json.dumps([random.random() for _ in range(100)]))" > /tmp/out.json ;;
      3) sed -i "s/notes/Notes/" "notes$((RANDOM % 20 + 1)).txt" ;;
      4) ps aux > /dev/null; cat /etc/os-release > /dev/null ;;
      5) tar -cf /tmp/project.tar /home/dev/project 2>/dev/null ;;
    esac
  done
  sleep "$(awk -v r=$RANDOM 'BEGIN{print 1.0 + (r % 150) / 100}')"
done

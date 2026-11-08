#!/bin/bash
# Web server role: serves static pages and requests pages from itself and from a peer.
# Kernel activity: mostly network connections (curl), file reads (pages), log writes.
set -u
source "$ROLE_DIR/lib.sh"

mkdir -p /srv/www /var/log/web
for i in $(seq 1 50); do
  printf '<html><body>page %d</body></html>\n' "$i" > "/srv/www/page$i.html"
done
python3 -m http.server 8080 --directory /srv/www >> /var/log/web/access.log 2>&1 &
pause_ms 2000 1

while true; do
  for (( n = 0; n < INTENSITY; n++ )); do
    curl -s -o /dev/null "http://localhost:8080/page$(( RANDOM % 50 + 1 )).html"
    if [ -n "${PEER:-}" ]; then
      curl -s -m 2 -o /dev/null "http://$PEER:8080/page$(( RANDOM % 50 + 1 )).html" || true
    fi
  done
  one_in 20 && gzip -kf /var/log/web/access.log
  pause_ms 500 1000
done

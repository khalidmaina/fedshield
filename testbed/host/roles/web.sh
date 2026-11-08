#!/bin/bash
# Web server role: serves static pages and requests pages from itself and a peer.
mkdir -p /srv/www /var/log/web
for i in $(seq 1 50); do echo "<html><body>page $i</body></html>" > /srv/www/page$i.html; done
cd /srv/www && python3 -m http.server 8080 >> /var/log/web/access.log 2>&1 &
sleep 2
while true; do
  for n in $(seq 1 "$INTENSITY"); do
    curl -s -o /dev/null "http://localhost:8080/page$((RANDOM % 50 + 1)).html"
    if [ -n "${PEER:-}" ]; then
      curl -s -m 2 -o /dev/null "http://$PEER:8080/page$((RANDOM % 50 + 1)).html" || true
    fi
  done
  if [ $((RANDOM % 20)) -eq 0 ]; then
    gzip -kf /var/log/web/access.log
  fi
  sleep "$(awk -v r=$RANDOM 'BEGIN{print 0.5 + (r % 100) / 100}')"
done

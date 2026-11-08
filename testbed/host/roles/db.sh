#!/bin/bash
# Database role: inserts, queries and periodic backups with sqlite3.
mkdir -p /var/lib/appdb /var/backups/appdb
DB=/var/lib/appdb/app.db
sqlite3 "$DB" "CREATE TABLE IF NOT EXISTS orders(id INTEGER PRIMARY KEY, item TEXT, qty INT, ts TEXT);"
while true; do
  for n in $(seq 1 "$INTENSITY"); do
    sqlite3 "$DB" "INSERT INTO orders(item, qty, ts) VALUES('item$((RANDOM % 100))', $((RANDOM % 10 + 1)), datetime('now'));"
    sqlite3 "$DB" "SELECT item, SUM(qty) FROM orders GROUP BY item ORDER BY 2 DESC LIMIT 5;" > /dev/null
  done
  if [ $((RANDOM % 15)) -eq 0 ]; then
    cp "$DB" "/var/backups/appdb/app-$(date +%H%M%S).db"
    ls -1t /var/backups/appdb/*.db | tail -n +6 | xargs -r rm -f
  fi
  if [ $((RANDOM % 40)) -eq 0 ]; then
    sqlite3 "$DB" "DELETE FROM orders WHERE id % 7 = 0; VACUUM;"
  fi
  sleep "$(awk -v r=$RANDOM 'BEGIN{print 0.7 + (r % 100) / 100}')"
done

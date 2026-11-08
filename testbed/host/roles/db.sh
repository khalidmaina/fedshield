#!/bin/bash
# Database role: inserts, queries, periodic backups and clean-ups with sqlite3.
# Kernel activity: mostly file opens and writes, few processes, almost no network.
set -u
source "$ROLE_DIR/lib.sh"

DB=/var/lib/appdb/app.db
BACKUPS=/var/backups/appdb
mkdir -p /var/lib/appdb "$BACKUPS"
sqlite3 "$DB" "CREATE TABLE IF NOT EXISTS orders(id INTEGER PRIMARY KEY, item TEXT, qty INT, ts TEXT);"

while true; do
  for (( n = 0; n < INTENSITY; n++ )); do
    sqlite3 "$DB" "INSERT INTO orders(item, qty, ts) VALUES('item$(( RANDOM % 100 ))', $(( RANDOM % 10 + 1 )), datetime('now'));"
    sqlite3 "$DB" "SELECT item, SUM(qty) FROM orders GROUP BY item ORDER BY 2 DESC LIMIT 5;" > /dev/null
  done
  if one_in 15; then                       # backup, keep the newest 5
    cp "$DB" "$BACKUPS/app-$EPOCHSECONDS.db"
    ls -1t "$BACKUPS"/*.db | tail -n +6 | xargs -r rm -f
  fi
  one_in 40 && sqlite3 "$DB" "DELETE FROM orders WHERE id % 7 = 0; VACUUM;"
  pause_ms 700 1000
done

#!/bin/bash
# Build server role: repeatedly compiles and runs a small C program, sometimes archives it.
# Kernel activity: many short-lived processes (make, gcc, cc1, as, ld) and file writes.
set -u
source "$ROLE_DIR/lib.sh"

mkdir -p /opt/build && cd /opt/build || exit 1
cat > app.c <<'EOF'
#include <stdio.h>
int main(void) { long s = 0; for (long i = 0; i < 2000000; i++) s += i % 7; printf("%ld\n", s); return 0; }
EOF
printf 'app: app.c\n\tgcc -O2 -o app app.c\nclean:\n\trm -f app\n' > Makefile

while true; do
  for (( n = 0; n < INTENSITY; n++ )); do
    make -s clean && make -s app && ./app > /dev/null
  done
  one_in 10 && tar -czf "/tmp/artifact-$(( RANDOM % 5 )).tgz" app app.c 2>/dev/null
  pause_ms 1000 1000
done

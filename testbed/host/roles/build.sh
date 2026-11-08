#!/bin/bash
# Build server role: repeatedly compiles and runs a small C program.
mkdir -p /opt/build && cd /opt/build
cat > app.c <<'EOF'
#include <stdio.h>
int main(void){ long s=0; for(long i=0;i<2000000;i++) s+=i%7; printf("%ld\n", s); return 0; }
EOF
printf 'app: app.c\n\tgcc -O2 -o app app.c\nclean:\n\trm -f app\n' > Makefile
while true; do
  for n in $(seq 1 "$INTENSITY"); do
    make -s clean && make -s app && ./app > /dev/null
  done
  if [ $((RANDOM % 10)) -eq 0 ]; then
    tar -czf "/tmp/artifact-$((RANDOM % 5)).tgz" app app.c 2>/dev/null
  fi
  sleep "$(awk -v r=$RANDOM 'BEGIN{print 1.0 + (r % 100) / 100}')"
done

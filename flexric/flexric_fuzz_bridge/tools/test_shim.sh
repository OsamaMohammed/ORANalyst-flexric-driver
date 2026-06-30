#!/usr/bin/env bash
# Verifies the shim flushes gcov on abort and on SIGUSR1.
set -u
TOOLS="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TMP="$(mktemp -d)"; trap 'rm -rf "$TMP"' EXIT
cd "$TMP"

# Force gcov symbols (dump/reset/init/master) to resolve through the dynamic
# linker so the LD_PRELOAD shim can intercept them.  Without this, GCC 13
# statically links libgcov and all calls are PC-relative (bypassing PLT).
cat > gcov.dynlist <<'EOF'
{
  __gcov_dump;
  __gcov_reset;
  __gcov_init;
  __gcov_master;
};
EOF

# tiny instrumented program: touch some lines, then abort after a SIGUSR1-able wait
cat > prog.c <<'EOF'
#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
volatile int x;
int main(void){ for(int i=0;i<10;i++) x+=i; printf("started pid=%d\n",getpid()); fflush(stdout);
  sleep(2); for(int i=0;i<5;i++) x-=i; abort(); return 0; }
EOF
gcc --coverage -O0 -g -Wl,--dynamic-list=gcov.dynlist prog.c -o prog
LD_PRELOAD="$TOOLS/libgcovflush.so" ./prog &
PID=$!
sleep 1
kill -USR1 "$PID"     # live flush
sleep 0.3
[ -f prog.gcda ] && echo "USR1-FLUSH-OK" || echo "USR1-FLUSH-FAIL"
wait "$PID" 2>/dev/null   # it aborts ~1s later -> fatal handler dumps again
sleep 0.3
[ -f prog.gcda ] && echo "ABORT-FLUSH-OK" || echo "ABORT-FLUSH-FAIL"

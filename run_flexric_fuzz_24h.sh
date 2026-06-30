#!/usr/bin/env bash
# 24h coverage fuzzing campaign: black-box go-fuzz -> bridge -> coverage-built
# FlexRIC RIC, with gcov flush shim, a 30-min coverage sampler, and a crash
# collector. Restarts the stack on each crash; stops at the deadline.
set -u

export PATH="$HOME/.local/go/bin:$HOME/.local/bin:$PATH"
export GOTOOLCHAIN=local

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
FLEXRIC="$ROOT/flexric"
BRIDGE="$FLEXRIC/flexric_fuzz_bridge"
TOOLS="$BRIDGE/tools"
FUZZER="$ROOT/ORANalyst/O-RAN-SC/oran-input-gen"
RIC_BIN="$FLEXRIC/build-cov/examples/ric/nearRT-RIC"
RIC_CONF="$FLEXRIC/flexric.conf"
BRIDGE_BIN="$BRIDGE/build/flexric_fuzz_bridge"
SHIM="$TOOLS/libgcovflush.so"

DURATION_SEC="${DURATION_SEC:-86400}"
SAMPLE_SEC="${SAMPLE_SEC:-1800}"

T0="$(date +%s)"
DEADLINE=$(( T0 + DURATION_SEC ))
STAMP="$(date +%Y%m%d-%H%M)"
CAMP="$ROOT/campaign-$STAMP"
LOGDIR="$CAMP/logs"
mkdir -p "$LOGDIR" "$CAMP/crashers"
COV_CSV="$CAMP/coverage_timeseries.csv"
CRASH_CSV="$CAMP/unique_crashes_timeseries.csv"
RIC_PIDFILE="$CAMP/ric.pid"

echo "[campaign] start=$T0 deadline=$DEADLINE sample=${SAMPLE_SEC}s out=$CAMP"

# Background measurement daemons
python3 "$TOOLS/coverage_sampler.py" --flexric-root "$FLEXRIC" --build-cov "$FLEXRIC/build-cov" \
  --ric-pid-file "$RIC_PIDFILE" --out "$COV_CSV" --t0 "$T0" --interval "$SAMPLE_SEC" \
  --deadline "$DEADLINE" >"$CAMP/sampler.out" 2>&1 &
SAMPLER_PID=$!
python3 "$TOOLS/crash_collector.py" --logs-glob "$LOGDIR/ric-*.log" \
  --out "$CRASH_CSV" --t0 "$T0" --deadline "$DEADLINE" >"$CAMP/collector.out" 2>&1 &
COLLECTOR_PID=$!

stop_all() {
  echo "[campaign] stopping..."
  [ -n "${RIC_PID:-}" ] && kill -USR1 "$RIC_PID" 2>/dev/null   # final coverage flush
  sleep 1
  [ -n "${FUZZ_PID:-}" ] && kill "$FUZZ_PID" 2>/dev/null
  [ -n "${BRIDGE_PID:-}" ] && kill "$BRIDGE_PID" 2>/dev/null
  [ -n "${RIC_PID:-}" ] && kill -TERM "$RIC_PID" 2>/dev/null
  pkill -f flexric_fuzz_bridge 2>/dev/null
  pkill -f 'build-cov/examples/ric/nearRT-RIC' 2>/dev/null
  pkill -f go-fuzz-bin 2>/dev/null; pkill -f sonar.exe 2>/dev/null
  sleep 2
  # let the sampler finish its in-flight/final gcovr sample (it self-exits at deadline)
  for _ in $(seq 1 120); do kill -0 "$SAMPLER_PID" 2>/dev/null || break; sleep 1; done
  # let the collector drain the last logs (it self-exits at deadline+5)
  for _ in $(seq 1 8); do kill -0 "$COLLECTOR_PID" 2>/dev/null || break; sleep 1; done
  kill "$SAMPLER_PID" "$COLLECTOR_PID" 2>/dev/null
  echo "[campaign] done. CSVs in $CAMP"
  exit 0
}
trap stop_all INT TERM

ROUND=0
while true; do
  if [ "$(date +%s)" -ge "$DEADLINE" ]; then echo "[campaign] deadline reached"; stop_all; fi
  ROUND=$((ROUND+1))
  echo "[campaign] === round $ROUND ($(($(date +%s)-T0))s elapsed) ==="

  LD_PRELOAD="$SHIM" "$RIC_BIN" -c "$RIC_CONF" >"$LOGDIR/ric-$ROUND.log" 2>&1 &
  RIC_PID=$!
  echo "$RIC_PID" > "$RIC_PIDFILE"
  sleep 3
  if ! kill -0 "$RIC_PID" 2>/dev/null; then
    echo "[campaign] RIC failed to start (round $ROUND)"; sleep 2; continue
  fi

  ( cd "$BRIDGE" && "$BRIDGE_BIN" --ric-ip 127.0.0.1 --ric-port 36421 \
      --setup setup_req.bin --crashers "$CAMP/crashers" ) \
      >"$LOGDIR/bridge-$ROUND.log" 2>&1 &
  BRIDGE_PID=$!
  sleep 2
  if ! grep -q "association up" "$LOGDIR/bridge-$ROUND.log"; then
    echo "[campaign] handshake not confirmed (round $ROUND); restarting"
    kill "$BRIDGE_PID" 2>/dev/null; kill -TERM "$RIC_PID" 2>/dev/null; sleep 2; continue
  fi

  ( cd "$FUZZER" && make run-fuzzer ) >"$LOGDIR/fuzzer-$ROUND.log" 2>&1 &
  FUZZ_PID=$!
  echo "[campaign] running RIC=$RIC_PID bridge=$BRIDGE_PID fuzzer=$FUZZ_PID"

  # Wait for the bridge to exit OR the deadline (poll, so 24h boundary is honored mid-round).
  while kill -0 "$BRIDGE_PID" 2>/dev/null; do
    [ "$(date +%s)" -ge "$DEADLINE" ] && { echo "[campaign] deadline during round $ROUND"; stop_all; }
    sleep 5
  done
  wait "$BRIDGE_PID"; BRC=$?
  echo "[campaign] bridge exited code $BRC (round $ROUND)"

  kill "$FUZZ_PID" 2>/dev/null
  kill -TERM "$RIC_PID" 2>/dev/null      # shim dumps coverage on SIGTERM
  pkill -f 'build-cov/examples/ric/nearRT-RIC' 2>/dev/null
  pkill -f go-fuzz-bin 2>/dev/null; pkill -f sonar.exe 2>/dev/null
  sleep 2
  # any exit (42 crash or otherwise) -> loop again until the deadline
done

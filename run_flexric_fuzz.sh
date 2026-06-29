#!/usr/bin/env bash
# Supervisor: run FlexRIC RIC + fuzz bridge + ORANalyst fuzzer; restart on crash.
set -u

# Go toolchain (adjust if your Go 1.20 lives elsewhere).
export PATH="$HOME/.local/go/bin:$PATH"
export GOTOOLCHAIN=local

# Repo root = directory this script lives in (works wherever you clone the repo).
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
FLEXRIC="$ROOT/flexric"
BRIDGE="$FLEXRIC/flexric_fuzz_bridge"
FUZZER="$ROOT/ORANalyst/O-RAN-SC/oran-input-gen"
RIC_BIN="$FLEXRIC/build/examples/ric/nearRT-RIC"
RIC_CONF="$FLEXRIC/flexric.conf"
BRIDGE_BIN="$BRIDGE/build/flexric_fuzz_bridge"

LOGDIR="$ROOT/fuzz-logs"
mkdir -p "$LOGDIR" "$BRIDGE/crashers"

cleanup() {
  echo "[supervisor] shutting down..."
  [ -n "${FUZZ_PID:-}" ] && kill "$FUZZ_PID" 2>/dev/null
  [ -n "${BRIDGE_PID:-}" ] && kill "$BRIDGE_PID" 2>/dev/null
  [ -n "${RIC_PID:-}" ] && kill "$RIC_PID" 2>/dev/null
  pkill -f flexric_fuzz_bridge 2>/dev/null
  pkill -f nearRT-RIC 2>/dev/null
  pkill -f go-fuzz-bin 2>/dev/null
  pkill -f sonar.exe 2>/dev/null
  exit 0
}
trap cleanup INT TERM

ROUND=0
while true; do
  ROUND=$((ROUND+1))
  echo "[supervisor] === round $ROUND ==="

  # 1. RIC
  "$RIC_BIN" -c "$RIC_CONF" >"$LOGDIR/ric-$ROUND.log" 2>&1 &
  RIC_PID=$!
  sleep 3
  if ! kill -0 "$RIC_PID" 2>/dev/null; then
    echo "[supervisor] RIC failed to start; see $LOGDIR/ric-$ROUND.log"; sleep 2; continue
  fi

  # 2. Bridge (does handshake, then serves 19960/19999)
  ( cd "$BRIDGE" && "$BRIDGE_BIN" --ric-ip 127.0.0.1 --ric-port 36421 \
      --setup setup_req.bin --crashers crashers ) \
      >"$LOGDIR/bridge-$ROUND.log" 2>&1 &
  BRIDGE_PID=$!
  sleep 2
  if ! grep -q "association up" "$LOGDIR/bridge-$ROUND.log"; then
    echo "[supervisor] handshake not confirmed; restarting"; kill "$BRIDGE_PID" "$RIC_PID" 2>/dev/null; sleep 2; continue
  fi

  # 3. Fuzzer (resumes from on-disk corpus automatically)
  ( cd "$FUZZER" && make run-fuzzer ) >"$LOGDIR/fuzzer-$ROUND.log" 2>&1 &
  FUZZ_PID=$!
  echo "[supervisor] running: RIC=$RIC_PID bridge=$BRIDGE_PID fuzzer=$FUZZ_PID"

  # 4. Wait for the bridge to exit; its code tells us what happened.
  wait "$BRIDGE_PID"
  BRC=$?
  echo "[supervisor] bridge exited with code $BRC"

  # tear down fuzzer + RIC before next round
  kill "$FUZZ_PID" 2>/dev/null
  kill "$RIC_PID" 2>/dev/null
  pkill -f nearRT-RIC 2>/dev/null
  pkill -f go-fuzz-bin 2>/dev/null
  pkill -f sonar.exe 2>/dev/null
  sleep 2

  if [ "$BRC" -eq 42 ]; then
    echo "[supervisor] CRASH detected (round $ROUND). Crasher saved under $BRIDGE/crashers/. Restarting stack..."
    continue
  else
    echo "[supervisor] bridge exited normally (code $BRC); stopping."
    cleanup
  fi
done

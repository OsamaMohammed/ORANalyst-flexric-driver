# 24h Coverage Fuzzing Campaign

Runs the black-box ORANalyst→FlexRIC E2 fuzzer for a fixed duration against a
**gcov-instrumented** FlexRIC, producing two CSVs:

- `campaign-<stamp>/coverage_timeseries.csv` — `elapsed_min,covered_edges,covered_lines`
  sampled every 30 min (or `$SAMPLE_SEC`).
- `campaign-<stamp>/unique_crashes_timeseries.csv` — one row per first-seen crash
  signature: `elapsed_min,timestamp,cumulative_unique,signature`.

Coverage is cumulative across RIC crash/restart rounds because every round reuses
the same `build-cov` binaries and the LD_PRELOAD shim flushes `.gcda` to disk on
SIGUSR1, SIGTERM, and fatal signals before the process exits.

---

## One-time setup

### 1. Coverage tools

```bash
pip3 install --break-system-packages gcovr   # or: pipx install gcovr
export PATH="$HOME/.local/bin:$PATH"
gcovr --version   # should print 8.6 or later
```

### 2. gcov flush shim

```bash
cd flexric/flexric_fuzz_bridge/tools
gcc -shared -fPIC -O2 -o libgcovflush.so gcov_flush_preload.c -lgcov
```

The shim intercepts SIGUSR1 (sampler flush), SIGTERM (graceful shutdown), and
fatal signals (SIGABRT/SIGSEGV) to call `__gcov_dump()` before the process exits,
preserving cumulative `.gcda` data across restarts.

### 3. Coverage build of FlexRIC

```bash
cd /home/osa240000/oranalyst   # repo root
cmake -S flexric -B flexric/build-cov \
  -DCMAKE_BUILD_TYPE=Debug \
  -DCMAKE_C_FLAGS="--coverage -fprofile-update=atomic -g -O0" \
  -DCMAKE_EXE_LINKER_FLAGS="--coverage -Wl,--dynamic-list=$(pwd)/flexric/flexric_fuzz_bridge/tools/gcov.dynlist" \
  -DCMAKE_SHARED_LINKER_FLAGS="--coverage -Wl,--dynamic-list=$(pwd)/flexric/flexric_fuzz_bridge/tools/gcov.dynlist"
cmake --build flexric/build-cov -j$(nproc)
```

The `--dynamic-list` flag exports `__gcov_*` symbols so the LD_PRELOAD shim can
call them from outside the binary.

---

## Run the real 24h campaign (detached, survives logout)

```bash
cd /home/osa240000/oranalyst
setsid nohup ./run_flexric_fuzz_24h.sh >campaign.out 2>&1 &
echo "started PID=$!; outputs in campaign-<stamp>/"
```

Outputs land in `campaign-<stamp>/`:

| File | Description |
|---|---|
| `coverage_timeseries.csv` | `elapsed_min,covered_edges,covered_lines` every 30 min |
| `unique_crashes_timeseries.csv` | one row per unique crash signature |
| `logs/ric-N.log`, `logs/bridge-N.log`, `logs/fuzzer-N.log` | per-round logs |
| `crashers/crash-*.bin` | raw payloads that triggered a crash |
| `sampler.out`, `collector.out` | daemon stderr |

Stop early (flushes coverage, finalizes CSVs via the SIGTERM trap):

```bash
pkill -f run_flexric_fuzz_24h
```

---

## Dry-run (validate in ~6 min)

```bash
cd /home/osa240000/oranalyst
DURATION_SEC=360 SAMPLE_SEC=60 ./run_flexric_fuzz_24h.sh >/tmp/campaign_dry.out 2>&1 &
sleep 390
CAMP=$(ls -dt campaign-* | head -1)
cat "$CAMP/coverage_timeseries.csv"
cat "$CAMP/unique_crashes_timeseries.csv"
grep -c '=== round' /tmp/campaign_dry.out   # how many rounds completed
tail -5 /tmp/campaign_dry.out
```

Expected results (verified dry-run, 31 rounds, campaign-20260629-2025):

- `coverage_timeseries.csv`: header + 4 data rows, all non-zero (`covered_edges=339`
  at baseline); post-campaign gcovr confirmed growth to 1290 edges / 2995 lines
  across 31 restart rounds.
- `unique_crashes_timeseries.csv`: 19 unique FlexRIC assertion signatures from
  `e2ap_msg_dec_asn.c`, cumulative_unique increments 1→19.
- Supervisor printed `[campaign] deadline during round 31` then `[campaign] done.`
- No leftover processes after stop.

**Note on sampler timing:** `gcovr` takes ~90 s over the full `src/` tree. With
`SAMPLE_SEC=60`, consecutive gcovr calls overlap — the CSV rows reflect the
coverage state when each gcovr run *finishes*, not when it starts. For a 6-minute
dry-run this means only 3–4 data rows appear. The true accumulated coverage is
best read with a single gcovr invocation after the campaign ends:

```bash
gcovr -r flexric --filter flexric/src/ --gcov-executable gcov \
      --gcov-ignore-parse-errors --json-summary - flexric/build-cov
```

---

## Definitions

- **`covered_edges`** = gcov *branches covered*; **`covered_lines`** = gcov *lines
  covered*; scope = `flexric/src/` (the RIC stack, not examples or tests).
- **Coverage is measured, not fed back to the fuzzer** (black-box fuzzing).
- **Crash detection** is SCTP-association-loss based: the bridge exits with code 42
  when the E2 association drops (SIGABRT/SIGSEGV kills the RIC). The supervisor
  restarts the full stack within a few seconds.
- **Coverage survives crashes** via the LD_PRELOAD shim: `__gcov_dump()` is called
  on SIGTERM and fatal signals so `.gcda` files accumulate monotonically across all
  restart rounds.
- **Crash signature** = parsed glibc assert line (`file:line: func: Assertion '...'
  failed`) or shim backtrace (`SIGNAME in first_FlexRIC_frame`). Deduplicated by
  the crash_collector; only the first occurrence is recorded.

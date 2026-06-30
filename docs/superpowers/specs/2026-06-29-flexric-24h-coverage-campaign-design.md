# FlexRIC 24h Coverage Fuzzing Campaign — Design

**Date:** 2026-06-29
**Status:** Approved (design); pending implementation plan
**Depends on:** the FlexRIC E2 fuzzing driver (`flexric/flexric_fuzz_bridge/`, `run_flexric_fuzz.sh`)

## 1. Goal

Run the ORANalyst → FlexRIC E2 fuzzer for a **24-hour** unattended session and produce two CSV files:

- **`coverage_timeseries.csv`** — cumulative FlexRIC source coverage sampled every ~30 minutes:
  ```
  elapsed_min,covered_edges,covered_lines
  0,1729,4204
  30,2776,6233
  61,2801,6278
  ...
  ```
- **`unique_crashes_timeseries.csv`** — one row per first-seen unique crash (assertions **and** other fatal crashes):
  ```
  elapsed_min,timestamp,cumulative_unique,signature
  0,2026-06-29 13:43:24,1,"e2ap_msg_dec_asn.c:2375: e2ap_dec_e42_setup_request: Assertion `ran_list->criticality == Criticality_reject' failed"
  ...
  ```

The campaign runs detached in the background, restarts FlexRIC on every crash, resumes fuzzing, and stops at the 24h mark.

## 2. Decisions (locked during brainstorming)

| Decision | Choice |
|---|---|
| Coverage instrumentation | **gcov** — rebuild FlexRIC with `gcc --coverage`; `covered_lines` = gcov covered lines, `covered_edges` = gcov covered branches (CFG edges taken). Sample with **gcovr** (`pip --user`). |
| Fuzzer guidance | **Out-of-band measurement** — the existing black-box go-fuzz + bridge stack is unchanged (bridge still returns stub feedback); coverage is read from FlexRIC's gcov data, not fed back to the fuzzer. |
| Crash signatures | **Assertions:** full `file.c:line: func: Assertion \`expr' failed`. **Non-assert fatal signals:** `SIGNAME in <top-frame func> (file.c:line)` from a backtrace. Both deduped by signature string. |
| Coverage scope | **`src/` only** (gcovr `--filter 'src/'`): the RIC, E2AP lib, agent, service models, decoders. Excludes `examples/`, `test/`, `build/`, generated/third-party code. |
| Crash-survival of coverage | **`LD_PRELOAD` shim** flushes gcov on crash and on demand — **no FlexRIC source change**. |
| Sampling cadence | Real elapsed time (~30–31 min spacing; values drift, matching the example). Row 0 = baseline at start. |

## 3. Background / constraints

- The driver project established: `flexric_fuzz_bridge` (SCTP client + inject:19960 + stub-feedback:19999), `run_flexric_fuzz.sh` supervisor, and the ORANalyst go-fuzz fuzzer (Go 1.20 at `$HOME/.local/go`, e2ap mutator + corpus). The fuzzer drives mutated E2AP over SCTP; FlexRIC dies by **SIGABRT** (assert) after ~50 PDUs per lifetime; the supervisor restarts the stack and go-fuzz resumes from its on-disk corpus.
- gcov writes `.gcda` only on **clean exit / `__gcov_dump()`** — a raw crash loses coverage. Hence the flush shim.
- Tooling present: `gcov` 13.4. Absent: `gcovr`/`lcov`/`llvm-cov` → install `gcovr` via `pip --user`. No sudo available.
- FlexRIC's CMake: gcc-13, `CMAKE_BUILD_TYPE` Debug/Release, `set(UNITY_BUILD ON)`. The coverage build should disable unity build if feasible (cleaner per-file line mapping); gcov still works with unity builds otherwise.

## 4. Architecture

```
 go-fuzz ──inject:19960──► flexric_fuzz_bridge ──SCTP:36421──► nearRT-RIC
                                                               (build-cov, LD_PRELOAD=libgcovflush.so)
                                                                  │ .gcda  (accumulates across rounds)
 coverage_sampler ──SIGUSR1 (live flush)───────────────────────────┘
        └─► gcovr --filter src/ ─► coverage_timeseries.csv          [every ~30 min + at t=0 + final]
 RIC stderr (per round) ─► crash_collector ─► unique_crashes_timeseries.csv  [per new signature]
 run_flexric_fuzz_24h.sh : start RIC+bridge+fuzzer · restart on crash (bridge exit 42) · stop at start+24h
```

The fuzzing data path is identical to the existing driver; only the RIC **binary** changes (coverage build + preload) and three measurement/orchestration pieces are added.

## 5. Components

### 5.1 Coverage build — `flexric/build-cov/`
- Configure FlexRIC with coverage flags, e.g.:
  ```
  cmake -S flexric -B flexric/build-cov \
    -DCMAKE_BUILD_TYPE=Debug \
    -DCMAKE_C_FLAGS="--coverage -fprofile-update=atomic -g -O0" \
    -DCMAKE_EXE_LINKER_FLAGS="--coverage" \
    -DCMAKE_SHARED_LINKER_FLAGS="--coverage"
  cmake --build flexric/build-cov -j
  ```
  Disable unity build for the coverage build if the project allows (cleaner line mapping); otherwise proceed — gcov maps via `.gcno`.
- Produces an instrumented `build-cov/examples/ric/nearRT-RIC` and `.gcno` next to each object. `.gcda` files are written under `build-cov/` (absolute paths embedded at compile time), so reusing this tree every round accumulates cumulative coverage (libgcov merges by addition).
- The original `build/` (release) is left intact and still used for capturing `setup_req.bin` etc.

### 5.2 gcov flush shim — `flexric/flexric_fuzz_bridge/tools/gcov_flush_preload.c` → `libgcovflush.so`
- Built standalone: `gcc -shared -fPIC -o libgcovflush.so gcov_flush_preload.c`.
- A `__attribute__((constructor))` installs handlers:
  - **`SIGUSR1`**: `__gcov_dump(); __gcov_reset();` then return (live snapshot without dying; reset prevents double-counting on the next dump).
  - **`SIGABRT`, `SIGSEGV`, `SIGFPE`, `SIGILL`, `SIGBUS`**: write a `backtrace()/backtrace_symbols_fd()` backtrace to stderr (tagged, e.g. `=== FATAL <signame> backtrace ===`), call `__gcov_dump()`, then `signal(sig, SIG_DFL); raise(sig)` so the process dies normally and the supervisor observes the crash.
  - **`SIGTERM`**: `__gcov_dump()` then default-terminate (captures final coverage when stopped at the deadline).
- `__gcov_dump`/`__gcov_reset` are declared `extern void` (provided by libgcov in the instrumented binary).
- Launched via `LD_PRELOAD=.../libgcovflush.so` on the coverage RIC only.
- Known limitation: `__gcov_dump` on a live multithreaded process (SIGUSR1 path) is covered-or-not accurate, not perfectly count-consistent — acceptable for coverage. On the crash path the process is dying.

### 5.3 Coverage sampler — `flexric/flexric_fuzz_bridge/tools/coverage_sampler.py` (or .sh)
- Inputs: campaign start time `T0`, RIC-pid file (current live RIC pid, written by the supervisor each round), `build-cov` path, output CSV path, interval (default 1800 s), deadline.
- Writes the header and the **t=0 baseline row** once at start (after the first handshake): SIGUSR1 the RIC, then sample.
- Loop until deadline: sleep to next ~30-min boundary (real elapsed), `kill -USR1 <ric_pid>` to flush the live RIC, copy the `.gcda`+`.gcno` tree to a temp snapshot, run
  `gcovr --filter 'src/' --json-summary` (or `--csv`) over the snapshot, extract **covered lines** and **covered branches**, append `round(elapsed_sec/60),covered_edges,covered_lines`.
- Robustness: if the RIC pid is momentarily absent (mid-restart) skip the flush but still sample the on-disk gcda; if gcovr errors, log and repeat the previous row's values (coverage is monotonic). Do a **final sample at the deadline** after the supervisor's final flush.

### 5.4 Crash collector — `flexric/flexric_fuzz_bridge/tools/crash_collector.py`
- Inputs: campaign start `T0`, the logs directory (per-round RIC stderr), output CSV path.
- Tails all `logs/ric-*.log` (and the shim's backtrace output) in near-real-time.
- Parsers:
  - **Assertion:** regex `^(?P<file>[\w./-]+\.c):(?P<line>\d+):\s*(?P<func>\w+):\s*Assertion\s+`(?P<expr>.*)'\s+failed\.?` → signature `"{basename_or_repo_relative}.c:{line}: {func}: Assertion \`{expr}' failed"` (path normalized to match the example's `file.c:line` form).
  - **Fatal signal:** from the shim's `=== FATAL <sig> backtrace ===` block, take the top in-FlexRIC frame → signature `"<SIG> in <func> (<file>.c:<line>)"`. If no symbol info, fall back to `"<SIG> in <module>+<offset>"`.
- Dedup by signature in a set. On each **new** signature: `cumulative_unique += 1`; append `elapsed_min,timestamp,cumulative_unique,"signature"` where `timestamp` = wall-clock when observed (`YYYY-MM-DD HH:MM:SS`) and `elapsed_min = round((now-T0)/60)`. CSV-quote the signature. Flush to disk per row.

### 5.5 24h supervisor — `run_flexric_fuzz_24h.sh` (extends `run_flexric_fuzz.sh`)
- New behavior on top of the existing supervisor:
  - Compute `DEADLINE = now + 24h` (override via `$DURATION_SEC` for the dry-run).
  - Create `campaign-<YYYYMMDD-HHMM>/` with `logs/`, `crashers/`, and the two CSVs.
  - Use the **coverage RIC**: `LD_PRELOAD=<libgcovflush.so> build-cov/examples/ric/nearRT-RIC -c flexric.conf`; write the live RIC pid to `campaign/ric.pid` each round.
  - Launch `coverage_sampler` and `crash_collector` as background children at start (pass `T0`, paths, interval, deadline).
  - Round loop = existing logic (RIC → bridge handshake → fuzzer → wait on bridge; on exit 42 restart) **plus** a deadline check each iteration: if `now >= DEADLINE`, break.
  - On stop (deadline or signal): `kill -USR1` the live RIC for a final flush (or `SIGTERM` via the shim), trigger one **final coverage sample**, stop sampler/collector, tear down RIC/bridge/fuzzer (incl. `go-fuzz-bin`/`sonar.exe`).
  - Reap children on `INT`/`TERM`.
- Invoked detached for the real run: `setsid nohup ./run_flexric_fuzz_24h.sh >campaign.out 2>&1 &` so it survives session/terminal exit.

## 6. Outputs (in `campaign-<YYYYMMDD-HHMM>/`)
- `coverage_timeseries.csv` — `elapsed_min,covered_edges,covered_lines`.
- `unique_crashes_timeseries.csv` — `elapsed_min,timestamp,cumulative_unique,signature`.
- `logs/ric-N.log`, `bridge-N.log`, `fuzzer-N.log`; `crashers/`; `campaign.out` (supervisor stdout).

## 7. Testing & verification

Cannot wait 24h to validate, so:
- **Dry-run** with shrunk timings via env overrides: `DURATION_SEC=360 SAMPLE_SEC=60 ./run_flexric_fuzz_24h.sh`. Confirm (with observed evidence):
  - both CSVs are created with correct headers;
  - `coverage_timeseries.csv` gets a t=0 baseline + rows every ~1 min, `covered_edges`/`covered_lines` are non-zero and **non-decreasing**, and coverage **survived at least one RIC crash** (value > 0 after a restart);
  - `unique_crashes_timeseries.csv` gets ≥1 assertion row with a correctly-formatted signature, `cumulative_unique` increments only on new signatures, and a repeated signature does **not** add a row;
  - the run stops at `DURATION_SEC` with a final sample, and all processes are reaped.
- **Unit checks:** the assertion/backtrace parser + dedup against sample log lines (incl. a duplicate and a non-assert backtrace); the gcovr-summary → (edges, lines) extraction.
- **Shim check:** force one crash, confirm `.gcda` mtimes advance and gcovr reports > 0 (flush-on-crash works); send `SIGUSR1` to a live RIC and confirm a flush without killing it.

## 8. Out of scope
- Coverage-**guided** fuzzing (feeding coverage back to go-fuzz) — measurement only.
- Crash **triage**/root-causing beyond signature dedup.
- HTML coverage reports / per-file breakdowns (only the two CSVs are required; gcovr can produce more later).
- Modifying FlexRIC **source** (only a separate coverage build + preload shim).

## 9. Risks & mitigations
- **Coverage lost on crash** → `LD_PRELOAD` shim dumps in the fatal-signal handler before re-raising.
- **Double-counting on live flush** → dump+reset on `SIGUSR1`; crash path dumps once as the process dies.
- **gcda accumulation correctness** → identical `build-cov` binaries every round ⇒ matching gcda keys ⇒ libgcov merges by addition (cumulative).
- **Shim handler overridden by FlexRIC** → FlexRIC handles SIGINT/SIGTERM (clean shutdown), not SIGABRT/SIGSEGV; the dry-run verifies the dump actually fires on a real assert.
- **gcovr/gcc version skew** → gcovr invokes the matching `gcov` (13.x) to read gcc-13 gcda; avoid `gcov-tool` (15.x) merging.
- **Unity build line mapping** → prefer unity-off for the coverage build; otherwise accept gcov's `.gcno`-based mapping.
- **Sampler reads gcda mid-dump** → snapshot (copy) the gcda tree before running gcovr; `-fprofile-update=atomic`.
- **24h process longevity** → detached via `setsid`/`nohup`; outputs streamed to disk so partial results survive an early termination.

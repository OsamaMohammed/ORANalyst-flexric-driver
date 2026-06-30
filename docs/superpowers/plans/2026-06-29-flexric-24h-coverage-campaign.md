# FlexRIC 24h Coverage Fuzzing Campaign Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Run the existing ORANalyst→FlexRIC E2 fuzzer for 24h unattended, restarting FlexRIC on every crash, and produce `coverage_timeseries.csv` (cumulative gcov edges+lines every ~30 min) and `unique_crashes_timeseries.csv` (one row per first-seen assertion/crash signature).

**Architecture:** A separate gcov-instrumented FlexRIC build (`build-cov/`) runs under the unchanged black-box fuzzer/bridge stack. An `LD_PRELOAD` shim flushes gcov counters on crash and on a `SIGUSR1` request so coverage survives the constant SIGABRTs and accumulates across restarts. A 30-min sampler (gcovr) and a crash-log collector write the two CSVs; a 24h supervisor drives the loop and stops at the deadline. Coverage is measured out-of-band — the fuzzer is NOT coverage-guided.

**Tech Stack:** C (gcc-13 `--coverage`, `__gcov_dump`/`__gcov_reset`, `LD_PRELOAD`), Python 3 stdlib (`unittest`) for the sampler/collector, `gcovr` (pip `--user`), Bash (supervisor), the existing `flexric_fuzz_bridge` + go-fuzz stack.

## Global Constraints

- **gcov metrics:** `covered_lines` = gcovr covered lines; `covered_edges` = gcovr covered **branches**. Source scope = **`src/` only** (gcovr `--filter` on the FlexRIC `src/` path). Use the gcc-13-matched `gcov` (do NOT use `gcov-tool` 15.x to merge).
- **Coverage survives crashes** via `LD_PRELOAD=libgcovflush.so`; **no FlexRIC source change**. `SIGUSR1` → `__gcov_dump(); __gcov_reset();` (live, keep running). `SIGABRT/SIGSEGV/SIGFPE/SIGILL/SIGBUS` → backtrace to stderr, `__gcov_dump()`, re-raise default. `SIGTERM` → `__gcov_dump()` then terminate.
- **Cumulative coverage:** the same `build-cov/` binaries are reused every round so libgcov merges `.gcda` by addition; dump+reset on `SIGUSR1` prevents double-counting.
- **Out-of-band:** the bridge still returns stub feedback; the fuzzer is unchanged.
- **CSV formats (exact headers):**
  - `coverage_timeseries.csv`: `elapsed_min,covered_edges,covered_lines`
  - `unique_crashes_timeseries.csv`: `elapsed_min,timestamp,cumulative_unique,signature` (signature CSV-quoted; timestamp `YYYY-MM-DD HH:MM:SS`)
- **elapsed_min** = `round((now - T0)/60)`, real elapsed (values drift; row 0 is the baseline at start).
- **Crash signatures:** assertions → `file.c:line: func: Assertion \`expr' failed` (path reduced to basename). Non-assert fatal signals → `SIG<NAME> in <func> (<file>.c:<line>)` from the shim backtrace; fallback `SIG<NAME> in <module>+<offset>`. Dedup by exact signature string; one CSV row per **new** signature.
- **Durations overridable for the dry-run:** `DURATION_SEC` (default 86400) and `SAMPLE_SEC` (default 1800).
- **Paths:** repo root `/home/osa240000/oranalyst`. FlexRIC `flexric/`. Bridge `flexric/flexric_fuzz_bridge/`. Fuzzer `ORANalyst/O-RAN-SC/oran-input-gen`. Go at `$HOME/.local/go/bin` (`GOTOOLCHAIN=local`). Tools live in `flexric/flexric_fuzz_bridge/tools/`.
- Commit bridge/tools changes in the `flexric` repo; the supervisor at repo root.

---

## File Structure

**New:**
- `flexric/flexric_fuzz_bridge/tools/gcov_flush_preload.c` — `LD_PRELOAD` shim.
- `flexric/flexric_fuzz_bridge/tools/coverage_sampler.py` — gcovr → `coverage_timeseries.csv`.
- `flexric/flexric_fuzz_bridge/tools/crash_collector.py` — parse logs → `unique_crashes_timeseries.csv`.
- `flexric/flexric_fuzz_bridge/tools/test_coverage_sampler.py` — unit tests (gcovr-summary parse, CSV row).
- `flexric/flexric_fuzz_bridge/tools/test_crash_collector.py` — unit tests (assertion/backtrace parse, dedup, CSV).
- `flexric/flexric_fuzz_bridge/tools/README.md` — how to build the shim, install gcovr, run the campaign.
- `run_flexric_fuzz_24h.sh` (repo root) — 24h supervisor.

**Reused unchanged:** `run_flexric_fuzz.sh` (reference), `flexric_fuzz_bridge` binary, the go-fuzz fuzzer, `setup_req.bin`.

---

## Task 1: gcov flush shim (`libgcovflush.so`)

**Files:**
- Create: `flexric/flexric_fuzz_bridge/tools/gcov_flush_preload.c`
- Test: build a tiny instrumented program and verify the shim flushes on abort + on SIGUSR1 (shell-driven, in Step 2/5).

**Interfaces:**
- Produces: a shared object `libgcovflush.so` that, when `LD_PRELOAD`ed into any `--coverage`-built program, dumps gcov data on `SIGUSR1` (and keeps running) and on fatal signals/`SIGTERM` (and dies).

- [ ] **Step 1: Write `tools/gcov_flush_preload.c`**

```c
/* gcov_flush_preload.c — LD_PRELOAD shim to flush gcov coverage on demand and
 * on crash, so coverage survives FlexRIC's SIGABRT/SIGSEGV deaths.
 *
 * Build: gcc -shared -fPIC -O2 -o libgcovflush.so gcov_flush_preload.c
 * Use:   LD_PRELOAD=/abs/path/libgcovflush.so <coverage-instrumented program>
 */
#define _GNU_SOURCE
#include <signal.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <execinfo.h>

/* Provided by libgcov in a program compiled with --coverage. */
extern void __gcov_dump(void);
extern void __gcov_reset(void);

static void write_str(int fd, const char* s) { (void)!write(fd, s, strlen(s)); }

/* Live snapshot: dump accumulated counters, then reset so the next dump only
 * adds the delta (prevents double-counting into the on-disk .gcda). */
static void on_usr1(int sig)
{
  (void)sig;
  __gcov_dump();
  __gcov_reset();
}

/* Fatal signal: print a backtrace (for crash signatures), dump coverage, then
 * re-raise with the default handler so the process dies and the supervisor
 * observes the crash. */
static void on_fatal(int sig)
{
  void* bt[64];
  int n = backtrace(bt, 64);
  write_str(STDERR_FILENO, "\n=== FATAL signal ");
  switch (sig) {
    case SIGABRT: write_str(STDERR_FILENO, "SIGABRT"); break;
    case SIGSEGV: write_str(STDERR_FILENO, "SIGSEGV"); break;
    case SIGFPE:  write_str(STDERR_FILENO, "SIGFPE");  break;
    case SIGILL:  write_str(STDERR_FILENO, "SIGILL");  break;
    case SIGBUS:  write_str(STDERR_FILENO, "SIGBUS");  break;
    default:      write_str(STDERR_FILENO, "SIGNAL");  break;
  }
  write_str(STDERR_FILENO, " backtrace ===\n");
  backtrace_symbols_fd(bt, n, STDERR_FILENO);
  write_str(STDERR_FILENO, "=== end backtrace ===\n");

  __gcov_dump();

  signal(sig, SIG_DFL);
  raise(sig);
}

/* SIGTERM (supervisor stop at deadline): dump then terminate. */
static void on_term(int sig)
{
  __gcov_dump();
  signal(sig, SIG_DFL);
  raise(sig);
}

__attribute__((constructor))
static void install_handlers(void)
{
  struct sigaction sa;
  memset(&sa, 0, sizeof(sa));
  sigemptyset(&sa.sa_mask);

  sa.sa_handler = on_usr1;  sigaction(SIGUSR1, &sa, NULL);

  sa.sa_handler = on_fatal;
  sigaction(SIGABRT, &sa, NULL);
  sigaction(SIGSEGV, &sa, NULL);
  sigaction(SIGFPE,  &sa, NULL);
  sigaction(SIGILL,  &sa, NULL);
  sigaction(SIGBUS,  &sa, NULL);

  sa.sa_handler = on_term;  sigaction(SIGTERM, &sa, NULL);
}
```

- [ ] **Step 2: Write the failing test (shell), run it to see it fail**

Create `flexric/flexric_fuzz_bridge/tools/test_shim.sh`:

```bash
#!/usr/bin/env bash
# Verifies the shim flushes gcov on abort and on SIGUSR1.
set -u
TOOLS="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TMP="$(mktemp -d)"; trap 'rm -rf "$TMP"' EXIT
cd "$TMP"

# tiny instrumented program: touch some lines, then abort after a SIGUSR1-able wait
cat > prog.c <<'EOF'
#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
volatile int x;
int main(void){ for(int i=0;i<10;i++) x+=i; printf("started pid=%d\n",getpid()); fflush(stdout);
  sleep(2); for(int i=0;i<5;i++) x-=i; abort(); return 0; }
EOF
gcc --coverage -O0 -g prog.c -o prog
LD_PRELOAD="$TOOLS/libgcovflush.so" ./prog &
PID=$!
sleep 1
kill -USR1 "$PID"     # live flush
sleep 0.3
[ -f prog.gcda ] && echo "USR1-FLUSH-OK" || echo "USR1-FLUSH-FAIL"
wait "$PID" 2>/dev/null   # it aborts ~1s later -> fatal handler dumps again
sleep 0.3
[ -f prog.gcda ] && echo "ABORT-FLUSH-OK" || echo "ABORT-FLUSH-FAIL"
```

Run:
```bash
cd /home/osa240000/oranalyst/flexric/flexric_fuzz_bridge/tools
chmod +x test_shim.sh && ./test_shim.sh
```
Expected: FAIL — `libgcovflush.so` doesn't exist yet (LD_PRELOAD warning; no `prog.gcda` from a signal flush, prints `USR1-FLUSH-FAIL`).

- [ ] **Step 3: Build the shim**

Run:
```bash
cd /home/osa240000/oranalyst/flexric/flexric_fuzz_bridge/tools
gcc -shared -fPIC -O2 -o libgcovflush.so gcov_flush_preload.c
ls -l libgcovflush.so
```
Expected: `libgcovflush.so` built, no errors.

- [ ] **Step 4: Run the test to verify it passes**

Run:
```bash
cd /home/osa240000/oranalyst/flexric/flexric_fuzz_bridge/tools
./test_shim.sh
```
Expected: prints `USR1-FLUSH-OK` and `ABORT-FLUSH-OK` (gcda written by the SIGUSR1 handler and present after abort).

- [ ] **Step 5: Commit**

```bash
cd /home/osa240000/oranalyst/flexric
git add flexric_fuzz_bridge/tools/gcov_flush_preload.c flexric_fuzz_bridge/tools/test_shim.sh
git commit -m "feat(campaign): gcov flush LD_PRELOAD shim (USR1 live dump, fatal dump+backtrace)"
```
(Do not commit the built `libgcovflush.so`; it is rebuilt and git-ignored.)

---

## Task 2: Coverage build of FlexRIC + install gcovr

**Files:**
- Create: `flexric/build-cov/` (out-of-source build; not committed)
- Document: append a "Coverage build" note to `flexric/flexric_fuzz_bridge/tools/README.md` (created in Task 6)

This task is mechanical; verification is "instrumented RIC runs and gcovr reports `src/` numbers."

- [ ] **Step 1: Install gcovr (user-local, no sudo)**

Run:
```bash
pip3 install --user gcovr || pipx install gcovr
export PATH="$HOME/.local/bin:$PATH"
gcovr --version
```
Expected: prints a gcovr version (≥5). If `pip3 --user` is blocked by PEP 668, use `pipx install gcovr` or `pip3 install --user --break-system-packages gcovr`. Record the working install command for the README.

- [ ] **Step 2: Configure + build the instrumented FlexRIC**

Run:
```bash
cd /home/osa240000/oranalyst/flexric
cmake -S . -B build-cov \
  -DCMAKE_BUILD_TYPE=Debug \
  -DCMAKE_C_FLAGS="--coverage -fprofile-update=atomic -g -O0" \
  -DCMAKE_EXE_LINKER_FLAGS="--coverage" \
  -DCMAKE_SHARED_LINKER_FLAGS="--coverage"
cmake --build build-cov -j 2>&1 | tail -15
ls -l build-cov/examples/ric/nearRT-RIC
```
Expected: build completes; instrumented `nearRT-RIC` exists. (If FlexRIC's unity build interferes with line mapping, add `-DUNITY_BUILD=OFF`; if that option is not honored, proceed — gcov maps via `.gcno`.) Compilation is large and may take many minutes.

- [ ] **Step 3: Verify instrumentation produced `.gcno` and the binary runs + flushes**

Run:
```bash
cd /home/osa240000/oranalyst/flexric
find build-cov -name '*.gcno' | head -3            # instrumentation present
LD_PRELOAD="$PWD/flexric_fuzz_bridge/tools/libgcovflush.so" \
  ./build-cov/examples/ric/nearRT-RIC -c flexric.conf >/tmp/covric.log 2>&1 &
RP=$!; sleep 3; kill -USR1 "$RP"; sleep 1
find build-cov -name '*.gcda' | head -3            # SIGUSR1 flush wrote gcda
kill -TERM "$RP" 2>/dev/null; sleep 1
```
Expected: `.gcno` files exist; after `SIGUSR1`, `.gcda` files appear (flush works on the real RIC).

- [ ] **Step 4: Verify gcovr reports `src/` line + branch coverage**

Run:
```bash
cd /home/osa240000/oranalyst/flexric
gcovr -r "$PWD" --filter "$PWD/src/" --gcov-executable gcov \
  --gcov-ignore-parse-errors --json-summary -o /tmp/cov.json build-cov
python3 - <<'PY'
import json
d=json.load(open('/tmp/cov.json'))
print('covered_lines=', d.get('line_covered'), 'covered_branches=', d.get('branch_covered'))
PY
```
Expected: prints non-zero `covered_lines` and `covered_branches` (the baseline numbers after a brief RIC run). These map to `covered_lines` and `covered_edges`.

- [ ] **Step 5: Commit (gitignore the build + artifacts)**

Add to `flexric/.gitignore` (create if absent) the lines `build-cov/` and `flexric_fuzz_bridge/tools/libgcovflush.so` and `flexric_fuzz_bridge/tools/*.gcda` `*.gcno`, then:
```bash
cd /home/osa240000/oranalyst/flexric
git add .gitignore
git commit -m "chore(campaign): ignore coverage build dir and shim/gcov artifacts"
```

---

## Task 3: Coverage sampler

**Files:**
- Create: `flexric/flexric_fuzz_bridge/tools/coverage_sampler.py`
- Test: `flexric/flexric_fuzz_bridge/tools/test_coverage_sampler.py`

**Interfaces:**
- Produces (importable functions):
  - `parse_gcovr_summary(json_text: str) -> tuple[int, int]` → `(covered_edges, covered_lines)` = `(branch_covered, line_covered)`.
  - `append_row(csv_path: str, elapsed_min: int, edges: int, lines: int) -> None` → writes header if new file, then one row.
  - CLI `main()` driving the sampling loop (tested via the integration step, not unit-tested).
- Consumes: `gcovr` on PATH; the `build-cov` dir; a `--ric-pid-file` to `SIGUSR1` the live RIC.

- [ ] **Step 1: Write the failing tests `tools/test_coverage_sampler.py`**

```python
import os, tempfile, unittest
import coverage_sampler as cs

class TestSampler(unittest.TestCase):
    def test_parse_summary_picks_branches_as_edges(self):
        js = '{"line_total":6300,"line_covered":4204,"branch_total":5000,"branch_covered":1729}'
        edges, lines = cs.parse_gcovr_summary(js)
        self.assertEqual(edges, 1729)   # branches -> edges
        self.assertEqual(lines, 4204)

    def test_parse_summary_missing_keys_is_zero(self):
        edges, lines = cs.parse_gcovr_summary('{}')
        self.assertEqual((edges, lines), (0, 0))

    def test_append_row_writes_header_then_rows(self):
        with tempfile.TemporaryDirectory() as d:
            p = os.path.join(d, "coverage_timeseries.csv")
            cs.append_row(p, 0, 1729, 4204)
            cs.append_row(p, 30, 2776, 6233)
            lines = open(p).read().strip().splitlines()
            self.assertEqual(lines[0], "elapsed_min,covered_edges,covered_lines")
            self.assertEqual(lines[1], "0,1729,4204")
            self.assertEqual(lines[2], "30,2776,6233")

if __name__ == "__main__":
    unittest.main()
```

- [ ] **Step 2: Run tests to verify they fail**

Run:
```bash
cd /home/osa240000/oranalyst/flexric/flexric_fuzz_bridge/tools
python3 -m unittest test_coverage_sampler -v
```
Expected: FAIL — `ModuleNotFoundError`/`AttributeError` (coverage_sampler not written yet).

- [ ] **Step 3: Write `tools/coverage_sampler.py`**

```python
#!/usr/bin/env python3
"""Sample cumulative FlexRIC src/ coverage every interval and append to a CSV.

Flushes the live RIC via SIGUSR1 (the gcov_flush shim) before each gcovr run,
so the snapshot reflects current coverage. Coverage is cumulative across RIC
restarts because every round reuses the same build-cov binaries.
"""
import argparse, json, os, subprocess, sys, time

HEADER = "elapsed_min,covered_edges,covered_lines"

def parse_gcovr_summary(json_text):
    try:
        d = json.loads(json_text)
    except Exception:
        return (0, 0)
    edges = int(d.get("branch_covered", 0) or 0)   # branches -> edges
    lines = int(d.get("line_covered", 0) or 0)
    return (edges, lines)

def append_row(csv_path, elapsed_min, edges, lines):
    new = not os.path.exists(csv_path) or os.path.getsize(csv_path) == 0
    with open(csv_path, "a") as f:
        if new:
            f.write(HEADER + "\n")
        f.write(f"{elapsed_min},{edges},{lines}\n")
        f.flush()

def run_gcovr(flexric_root, build_cov):
    cmd = ["gcovr", "-r", flexric_root,
           "--filter", os.path.join(flexric_root, "src") + os.sep,
           "--gcov-executable", "gcov",
           "--gcov-ignore-parse-errors", "--json-summary"]
    try:
        out = subprocess.run(cmd + [build_cov], capture_output=True, text=True,
                             timeout=600)
        return out.stdout
    except Exception as e:
        sys.stderr.write(f"[sampler] gcovr failed: {e}\n")
        return "{}"

def flush_live_ric(ric_pid_file):
    try:
        pid = int(open(ric_pid_file).read().strip())
        os.kill(pid, 10)  # SIGUSR1
        time.sleep(0.5)
    except Exception:
        pass  # RIC mid-restart; sample on-disk gcda anyway

def sample_once(flexric_root, build_cov, ric_pid_file, csv_path, t0, last):
    flush_live_ric(ric_pid_file)
    edges, lines = parse_gcovr_summary(run_gcovr(flexric_root, build_cov))
    if (edges, lines) == (0, 0) and last is not None:
        edges, lines = last           # transient gcovr error -> repeat last
    elapsed_min = round((time.time() - t0) / 60)
    append_row(csv_path, elapsed_min, edges, lines)
    return (edges, lines)

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--flexric-root", required=True)
    ap.add_argument("--build-cov", required=True)
    ap.add_argument("--ric-pid-file", required=True)
    ap.add_argument("--out", required=True)
    ap.add_argument("--t0", type=float, required=True)
    ap.add_argument("--interval", type=int, default=1800)
    ap.add_argument("--deadline", type=float, required=True)
    a = ap.parse_args()

    last = sample_once(a.flexric_root, a.build_cov, a.ric_pid_file, a.out, a.t0, None)  # row 0
    while time.time() < a.deadline:
        # sleep to next interval boundary but wake by deadline
        nap = min(a.interval, max(1, a.deadline - time.time()))
        time.sleep(nap)
        if time.time() >= a.deadline:
            break
        last = sample_once(a.flexric_root, a.build_cov, a.ric_pid_file, a.out, a.t0, last)
    # final sample at the deadline
    sample_once(a.flexric_root, a.build_cov, a.ric_pid_file, a.out, a.t0, last)

if __name__ == "__main__":
    main()
```

- [ ] **Step 4: Run unit tests to verify they pass**

Run:
```bash
cd /home/osa240000/oranalyst/flexric/flexric_fuzz_bridge/tools
python3 -m unittest test_coverage_sampler -v
```
Expected: PASS (3 tests).

- [ ] **Step 5: Integration smoke (one real sample against build-cov)**

Run:
```bash
cd /home/osa240000/oranalyst/flexric
export PATH="$HOME/.local/bin:$PATH"
LD_PRELOAD="$PWD/flexric_fuzz_bridge/tools/libgcovflush.so" \
  ./build-cov/examples/ric/nearRT-RIC -c flexric.conf >/tmp/covric.log 2>&1 &
RP=$!; echo $RP > /tmp/ric.pid; sleep 3
python3 flexric_fuzz_bridge/tools/coverage_sampler.py \
  --flexric-root "$PWD" --build-cov "$PWD/build-cov" --ric-pid-file /tmp/ric.pid \
  --out /tmp/coverage_timeseries.csv --t0 "$(date +%s)" --interval 5 --deadline "$(($(date +%s)+8))"
kill -TERM "$RP" 2>/dev/null
cat /tmp/coverage_timeseries.csv
```
Expected: CSV with the header and ≥2 rows (row 0 baseline + final), non-zero non-decreasing `covered_edges,covered_lines`.

- [ ] **Step 6: Commit**

```bash
cd /home/osa240000/oranalyst/flexric
git add flexric_fuzz_bridge/tools/coverage_sampler.py flexric_fuzz_bridge/tools/test_coverage_sampler.py
git commit -m "feat(campaign): coverage_sampler (gcovr src/ -> coverage_timeseries.csv)"
```

---

## Task 4: Crash collector

**Files:**
- Create: `flexric/flexric_fuzz_bridge/tools/crash_collector.py`
- Test: `flexric/flexric_fuzz_bridge/tools/test_crash_collector.py`

**Interfaces:**
- Produces (importable):
  - `assertion_signature(line: str) -> str | None` → normalized `file.c:line: func: Assertion \`expr' failed` or `None`.
  - `backtrace_signature(block_lines: list[str], signame: str) -> str` → `SIG<NAME> in <func> (<file>.c:<line>)` from a shim backtrace block, fallback `SIG<NAME> in <module>+<offset>`.
  - `CrashDedup` class: `.observe(signature, now, t0) -> bool` (True if new), writing rows to the CSV via `append_crash_row`.
  - `append_crash_row(csv_path, elapsed_min, timestamp, cumulative_unique, signature)`.
- Consumes: per-round RIC stderr logs in a directory.

- [ ] **Step 1: Write the failing tests `tools/test_crash_collector.py`**

```python
import os, tempfile, unittest
import crash_collector as cc

ASSERT_LINE = ("nearRT-RIC: /home/x/flexric/src/lib/e2ap/e2ap_msg_dec_asn.c:2375: "
               "e2ap_dec_e42_setup_request: Assertion `ran_list->criticality == "
               "Criticality_reject' failed.")

class TestCollector(unittest.TestCase):
    def test_assertion_signature_normalizes_to_basename(self):
        sig = cc.assertion_signature(ASSERT_LINE)
        self.assertEqual(sig, "e2ap_msg_dec_asn.c:2375: e2ap_dec_e42_setup_request: "
                              "Assertion `ran_list->criticality == Criticality_reject' failed")

    def test_non_assertion_line_returns_none(self):
        self.assertIsNone(cc.assertion_signature("just a log line"))

    def test_backtrace_signature_uses_top_flexric_frame(self):
        block = ["=== FATAL signal SIGSEGV backtrace ===",
                 "/lib/x.so(+0x1)[0x1]",
                 "/home/x/flexric/build-cov/examples/ric/nearRT-RIC(e2ap_dec_x+0x4c)[0xdead]",
                 "=== end backtrace ==="]
        sig = cc.backtrace_signature(block, "SIGSEGV")
        self.assertTrue(sig.startswith("SIGSEGV in e2ap_dec_x"))

    def test_dedup_only_new_signatures_write_rows(self):
        with tempfile.TemporaryDirectory() as d:
            p = os.path.join(d, "unique_crashes_timeseries.csv")
            dd = cc.CrashDedup(p, t0=1000.0)
            self.assertTrue(dd.observe("sigA", now=1000.0))   # new -> row 1
            self.assertFalse(dd.observe("sigA", now=1100.0))  # dup -> no row
            self.assertTrue(dd.observe("sigB", now=1130.0))   # new -> row 2
            rows = open(p).read().strip().splitlines()
            self.assertEqual(rows[0], "elapsed_min,timestamp,cumulative_unique,signature")
            self.assertEqual(len(rows), 3)                    # header + 2
            self.assertTrue(rows[1].startswith("0,"))
            self.assertIn(',1,"sigA"', rows[1])
            self.assertIn(',2,"sigB"', rows[2])

if __name__ == "__main__":
    unittest.main()
```

- [ ] **Step 2: Run tests to verify they fail**

Run:
```bash
cd /home/osa240000/oranalyst/flexric/flexric_fuzz_bridge/tools
python3 -m unittest test_crash_collector -v
```
Expected: FAIL — module/attributes not defined.

- [ ] **Step 3: Write `tools/crash_collector.py`**

```python
#!/usr/bin/env python3
"""Collect unique FlexRIC crash signatures from per-round RIC logs.

Assertions are parsed from glibc assert output; non-assert fatal signals from
the gcov_flush shim's backtrace block. One CSV row per first-seen signature.
"""
import argparse, csv, glob, os, re, time

HEADER = ["elapsed_min", "timestamp", "cumulative_unique", "signature"]

_ASSERT_RE = re.compile(
    r"(?P<path>[\w./+-]+\.c):(?P<line>\d+):\s*(?P<func>\w+):\s*"
    r"Assertion\s+`(?P<expr>.*)'\s+failed\.?\s*$")

_FRAME_RE = re.compile(r"\((?P<func>[\w.$]+)\+0x[0-9a-fA-F]+\)")

def assertion_signature(line):
    m = _ASSERT_RE.search(line)
    if not m:
        return None
    base = os.path.basename(m.group("path"))
    return f"{base}:{m.group('line')}: {m.group('func')}: Assertion `{m.group('expr')}' failed"

def backtrace_signature(block_lines, signame):
    # first frame that names a function and looks like FlexRIC code
    for ln in block_lines:
        if "nearRT-RIC" in ln or "/flexric/" in ln or "libe2" in ln:
            m = _FRAME_RE.search(ln)
            if m:
                return f"{signame} in {m.group('func')}"
    # fallback: any framed function, else module+offset of the first frame
    for ln in block_lines:
        m = _FRAME_RE.search(ln)
        if m:
            return f"{signame} in {m.group('func')}"
    return f"{signame} in <unknown>"

def append_crash_row(csv_path, elapsed_min, timestamp, cumulative_unique, signature):
    new = not os.path.exists(csv_path) or os.path.getsize(csv_path) == 0
    with open(csv_path, "a", newline="") as f:
        w = csv.writer(f, quoting=csv.QUOTE_MINIMAL)
        if new:
            w.writerow(HEADER)
        w.writerow([elapsed_min, timestamp, cumulative_unique, signature])
        f.flush()

class CrashDedup:
    def __init__(self, csv_path, t0):
        self.csv_path = csv_path
        self.t0 = t0
        self.seen = set()
        self.count = 0

    def observe(self, signature, now=None):
        if signature in self.seen:
            return False
        now = time.time() if now is None else now
        self.seen.add(signature)
        self.count += 1
        elapsed_min = round((now - self.t0) / 60)
        ts = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(now))
        append_crash_row(self.csv_path, elapsed_min, ts, self.count, signature)
        return True

def _iter_new_lines(paths, offsets):
    for p in paths:
        try:
            with open(p, "r", errors="replace") as f:
                f.seek(offsets.get(p, 0))
                for line in f:
                    yield p, line.rstrip("\n")
                offsets[p] = f.tell()
        except FileNotFoundError:
            continue

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--logs-glob", required=True, help="e.g. campaign/logs/ric-*.log")
    ap.add_argument("--out", required=True)
    ap.add_argument("--t0", type=float, required=True)
    ap.add_argument("--deadline", type=float, required=True)
    a = ap.parse_args()

    dd = CrashDedup(a.out, a.t0)
    offsets = {}
    bt_block = None
    bt_sig = None
    while time.time() < a.deadline + 5:   # small grace to catch final crash
        for _, line in _iter_new_lines(sorted(glob.glob(a.logs_glob)), offsets):
            sig = assertion_signature(line)
            if sig:
                dd.observe(sig)
                continue
            if "=== FATAL signal" in line:
                m = re.search(r"FATAL signal (\w+)", line)
                bt_sig = m.group(1) if m else "SIGNAL"
                bt_block = []
            elif bt_block is not None and "=== end backtrace ===" in line:
                dd.observe(backtrace_signature(bt_block, bt_sig))
                bt_block = None
            elif bt_block is not None:
                bt_block.append(line)
        time.sleep(2)

if __name__ == "__main__":
    main()
```

- [ ] **Step 4: Run unit tests to verify they pass**

Run:
```bash
cd /home/osa240000/oranalyst/flexric/flexric_fuzz_bridge/tools
python3 -m unittest test_crash_collector -v
```
Expected: PASS (4 tests).

- [ ] **Step 5: Commit**

```bash
cd /home/osa240000/oranalyst/flexric
git add flexric_fuzz_bridge/tools/crash_collector.py flexric_fuzz_bridge/tools/test_crash_collector.py
git commit -m "feat(campaign): crash_collector (assertions+backtraces -> unique_crashes_timeseries.csv)"
```

---

## Task 5: 24h supervisor (`run_flexric_fuzz_24h.sh`)

**Files:**
- Create: `run_flexric_fuzz_24h.sh` (repo root)

**Interfaces:**
- Consumes: `build-cov` RIC, `libgcovflush.so`, the bridge binary, the fuzzer, `coverage_sampler.py`, `crash_collector.py`.
- Produces: a `campaign-<stamp>/` dir with `coverage_timeseries.csv`, `unique_crashes_timeseries.csv`, `logs/`, `crashers/`, `ric.pid`.
- Env overrides: `DURATION_SEC` (default 86400), `SAMPLE_SEC` (default 1800).

- [ ] **Step 1: Write `run_flexric_fuzz_24h.sh`**

```bash
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
```

- [ ] **Step 2: Syntax check**

Run:
```bash
chmod +x /home/osa240000/oranalyst/run_flexric_fuzz_24h.sh
bash -n /home/osa240000/oranalyst/run_flexric_fuzz_24h.sh && echo "syntax ok"
```
Expected: `syntax ok`.

- [ ] **Step 3: Commit**

```bash
cd /home/osa240000/oranalyst
git add run_flexric_fuzz_24h.sh
git commit -m "feat(campaign): 24h supervisor with coverage build, flush shim, sampler+collector"
```
(Root `oranalyst` repo. Per project convention, git hygiene is informal here.)

---

## Task 6: End-to-end dry-run verification + README

**Files:**
- Create: `flexric/flexric_fuzz_bridge/tools/README.md`

This task validates the whole campaign at shrunk timings and documents the real 24h launch. Prerequisite: Tasks 1–5 done and `build-cov` built (Task 2).

- [ ] **Step 1: Run the shrunk dry-run (6 min, 1-min sampling)**

Run:
```bash
cd /home/osa240000/oranalyst
DURATION_SEC=360 SAMPLE_SEC=60 ./run_flexric_fuzz_24h.sh >/tmp/campaign_dry.out 2>&1 &
SUP=$!
# let it run the full 6 minutes + cleanup
sleep 380
CAMP=$(ls -dt campaign-* | head -1)
echo "=== $CAMP ==="
echo "--- coverage_timeseries.csv ---"; cat "$CAMP/coverage_timeseries.csv"
echo "--- unique_crashes_timeseries.csv ---"; cat "$CAMP/unique_crashes_timeseries.csv"
echo "--- rounds ---"; grep -c '=== round' /tmp/campaign_dry.out
# ensure clean
pkill -f run_flexric_fuzz_24h; pkill -f 'build-cov/examples/ric/nearRT-RIC'; pkill -f flexric_fuzz_bridge; pkill -f go-fuzz-bin; pkill -f sonar.exe
```
Expected (observed evidence required):
- `coverage_timeseries.csv` has the header, a row 0 baseline, ~1-min-spaced rows, **non-zero non-decreasing** `covered_edges,covered_lines`, with coverage **surviving multiple RIC crash/restart rounds** (value stays > 0 and grows after restarts).
- `unique_crashes_timeseries.csv` has the header and ≥1 assertion row with a correctly-formatted signature; `cumulative_unique` increments only on new signatures.
- The supervisor stopped at ~360 s with a final coverage sample; no leftover processes.

- [ ] **Step 2: If a check fails, debug and re-run (record the fix)**

Common issues and fixes:
- gcovr reports 0 → confirm `.gcda` exist after a `SIGUSR1` (shim path correct in supervisor) and the `--filter` matches the real `src/` absolute path; adjust the filter.
- No crash rows → confirm `ric-*.log` actually contains the assert text (the coverage build still asserts); confirm `--logs-glob` matches.
- Coverage resets to 0 after a round → `.gcda` not accumulating; verify all rounds use the identical `build-cov` binary and the shim re-raises (not `_exit`) so libgcov merges.
Re-run Step 1 until all three checks pass.

- [ ] **Step 3: Write `tools/README.md`**

````markdown
# 24h Coverage Fuzzing Campaign

Runs the black-box ORANalyst→FlexRIC E2 fuzzer for a fixed duration against a
**gcov-instrumented** FlexRIC, producing two CSVs.

## One-time setup
```bash
# 1. coverage tools
pip3 install --user gcovr        # or: pipx install gcovr
export PATH="$HOME/.local/bin:$PATH"

# 2. gcov flush shim
cd flexric/flexric_fuzz_bridge/tools
gcc -shared -fPIC -O2 -o libgcovflush.so gcov_flush_preload.c

# 3. coverage build of FlexRIC (large; minutes)
cd ../../..   # repo root
cmake -S flexric -B flexric/build-cov -DCMAKE_BUILD_TYPE=Debug \
  -DCMAKE_C_FLAGS="--coverage -fprofile-update=atomic -g -O0" \
  -DCMAKE_EXE_LINKER_FLAGS="--coverage" -DCMAKE_SHARED_LINKER_FLAGS="--coverage"
cmake --build flexric/build-cov -j
```

## Run the real 24h campaign (detached, survives logout)
```bash
cd /home/osa240000/oranalyst
setsid nohup ./run_flexric_fuzz_24h.sh >campaign.out 2>&1 &
echo "started; outputs land in campaign-<stamp>/"
```
- `campaign-<stamp>/coverage_timeseries.csv`   — `elapsed_min,covered_edges,covered_lines` every 30 min.
- `campaign-<stamp>/unique_crashes_timeseries.csv` — `elapsed_min,timestamp,cumulative_unique,signature`.
- `logs/`, `crashers/`, `sampler.out`, `collector.out` for diagnostics.

Stop early: `pkill -f run_flexric_fuzz_24h` (the trap flushes + finalizes the CSVs).

## Dry-run (validate in ~6 min)
```bash
DURATION_SEC=360 SAMPLE_SEC=60 ./run_flexric_fuzz_24h.sh
```

## Definitions
- `covered_edges` = gcov **branches** covered; `covered_lines` = gcov lines covered; scope = FlexRIC `src/`.
- Coverage is **measured**, not fed back to the fuzzer (black-box).
- Crash detection is SCTP-association-loss based (catches SIGABRT/SIGSEGV); coverage survives crashes via the LD_PRELOAD shim.
````

- [ ] **Step 4: Commit**

```bash
cd /home/osa240000/oranalyst/flexric
git add flexric_fuzz_bridge/tools/README.md
git commit -m "docs(campaign): tools README — setup, 24h launch, dry-run, definitions"
```

---

## Self-Review

**Spec coverage:**
- gcov build (§5.1) → Task 2. ✓
- LD_PRELOAD flush shim w/ SIGUSR1/fatal/SIGTERM (§5.2) → Task 1. ✓
- coverage_sampler, gcovr src/ filter, row 0 + 30-min + final, monotonic fallback (§5.3) → Task 3. ✓
- crash_collector, assertion + backtrace signatures, dedup, CSV (§5.4) → Task 4. ✓
- 24h supervisor: build-cov + shim, ric.pid, launch daemons, deadline, final flush, restart on crash (§5.5) → Task 5. ✓
- Outputs (§6) → campaign dir in Task 5; verified Task 6. ✓
- Testing: dry-run + unit checks + shim check (§7) → Tasks 1/3/4 unit, Task 6 e2e. ✓
- Out-of-band (fuzzer unchanged) → no fuzzer task; supervisor reuses `make run-fuzzer`. ✓

**Placeholder scan:** No TBD/TODO; every code step shows complete code; commands have expected output.

**Type/name consistency:** `parse_gcovr_summary`→`(edges,lines)`, `append_row`, `assertion_signature`, `backtrace_signature`, `CrashDedup.observe`, `append_crash_row` are used consistently across tasks and tests. CSV headers match the Global Constraints verbatim. `ric.pid` written by the supervisor (Task 5) is consumed by `coverage_sampler --ric-pid-file` (Task 3). The shim's `=== FATAL signal <SIG> backtrace ===` / `=== end backtrace ===` markers (Task 1) are exactly what `crash_collector` parses (Task 4).

**Highest-risk step for the executor:** Task 2 (coverage build of FlexRIC) — large/long compile, possible unity-build line-mapping wrinkles, and gcovr install under PEP 668. If gcovr reports zero in Task 6, treat as a debugging sub-task: verify `.gcda` appear after `SIGUSR1` and that `--filter` matches the absolute `src/` path.

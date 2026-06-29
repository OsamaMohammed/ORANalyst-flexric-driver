# ORANalyst → FlexRIC E2 Fuzzing Driver

A driver that lets the [ORANalyst](https://github.com/SyNSec-den/ORANalyst) fuzzer
black-box fuzz the **E2 interface** of the [FlexRIC](https://gitlab.eurecom.fr/mosaic5g/flexric)
near-RT RIC.

The core component is **`flexric_fuzz_bridge`**: a standalone C program that
connects to FlexRIC's near-RT RIC over SCTP, completes the E2 Setup handshake by
replaying a captured real E2 Setup Request, and then forwards ORANalyst's mutated
E2AP messages onto the live E2 interface — while emulating ORANalyst's
coverage-feedback protocol so the unmodified go-fuzz loop stays in sync. A
reader thread detects target death (SCTP association loss) as a crash, persists
the offending input, and a supervisor script auto-restarts the stack so fuzzing
resumes from the on-disk corpus.

> **Status:** working and verified end-to-end. In a 10-minute run the fuzzer
> drove FlexRIC to **genuine `assert()` aborts (SIGABRT) reachable from the E2
> interface** — real robustness bugs in the RIC (see [Findings](#findings)).

---

## Architecture

```
 ORANalyst go-fuzz (go-fuzz-bin + fuzz.zip)
         │ spawns
         ▼
   sonar.exe (oran-input-gen/main.go, UNMODIFIED logic)
         │ per input: connect TCP 19960 ──► [INJECT raw E2AP bytes]
         │ persistent: TCP 19999 ◄──────── [FEEDBACK: 1 + 3145728 + 24 bytes, zero coverage]
         ▼
 ┌──────────────────────────────────────────────┐
 │  flexric_fuzz_bridge (this repo)               │
 │   • SCTP client ──► FlexRIC near-RT RIC :36421 │
 │   • E2 Setup handshake (replays setup_req.bin) │
 │   • TCP 19960 inject server → SCTP send        │
 │   • TCP 19999 feedback server (stub coverage)  │
 │   • crash/loss detection → save input, exit 42 │
 └──────────────────────────────────────────────┘
         │ SCTP / E2AP
         ▼
   FlexRIC near-RT RIC  (flexric/build/examples/ric/nearRT-RIC)
```

The bridge unifies the two roles that are normally split in ORANalyst (the
RAN-simulator injector on port 19960 and the instrumented target's coverage
server on port 19999). Because it reproduces both ports' wire protocols exactly,
**ORANalyst's `main.go` runs unmodified**. This is **black-box** fuzzing: the
coverage channel returns zeroed coverage of the exact size the go-fuzz loop
expects (`1 + (CoverSize+MaxInputSize+SonarRegionSize) + 24 = 3 145 753` bytes
per input), which keeps the loop from deadlocking without requiring FlexRIC to be
instrumented.

---

## Repository layout

```
ORANalyst-flexric-driver/
├── flexric/                              # FlexRIC source (no build artifacts)
│   └── flexric_fuzz_bridge/              # ◀── THE DRIVER (new)
│       ├── src/                          #     sctp_client / fuzz_ports / crasher / main
│       ├── include/                      #     headers + constants (bridge.h)
│       ├── test/                         #     CTest unit tests
│       ├── CMakeLists.txt
│       ├── setup_req.bin                 #     captured real E2 Setup Request (1153 B)
│       └── README.md
├── ORANalyst/O-RAN-SC/oran-input-gen/    # ORANalyst fuzzer (source + e2ap seed corpus)
│   └── BUILD_NOTES.txt                   #     exact edits made to build it here
├── run_flexric_fuzz.sh                   # supervisor: run + auto-restart the stack
├── configure_paths.sh                    # rewrite ORANalyst's absolute cgo paths to this clone
├── docs/superpowers/                     # design spec + implementation plan
└── README.md                             # this file
```

---

## Prerequisites

Tested on Ubuntu (gcc-13). Install:

```bash
sudo apt update
sudo apt install -y build-essential gcc-13 g++-13 cmake libsctp-dev libpcre2-dev cmake-curses-gui
```

**Go 1.20** is required for the ORANalyst fuzzer (the project's go-fuzz tooling is
known to be incompatible with Go ≥ 1.21). Install user-local (no sudo):

```bash
cd /tmp
wget https://go.dev/dl/go1.20.14.linux-amd64.tar.gz
mkdir -p "$HOME/.local" && tar -C "$HOME/.local" -xzf go1.20.14.linux-amd64.tar.gz
export PATH="$HOME/.local/go/bin:$PATH"
export GOTOOLCHAIN=local      # prevents auto-upgrade to a newer toolchain
go version                    # -> go1.20.14
```

---

## Build

### 1. FlexRIC (the target)

Follow FlexRIC's own build (see `flexric/README.md`). In short:

```bash
cd flexric
mkdir -p build && cd build
cmake .. && make -j
# produces build/examples/ric/nearRT-RIC and the service-model plugins
```

### 2. The fuzz bridge (the driver)

```bash
cd flexric/flexric_fuzz_bridge
cmake -S . -B build && cmake --build build
ctest --test-dir build --output-on-failure     # 3 unit tests, all pass
```

### 3. The ORANalyst fuzzer

The fuzzer embeds absolute cgo/`replace` paths from its original build host.
Rewrite them to this clone, then build:

```bash
./configure_paths.sh                            # from the repo root
export PATH="$HOME/.local/go/bin:$PATH" GOTOOLCHAIN=local
cd ORANalyst/O-RAN-SC/oran-input-gen
rm -rf corpus && cp -r corpus_e2ap_final corpus  # e2ap seed corpus
make fuzzer                                      # -> go-fuzz-bin, fuzz.zip, sonar.exe
```

The e2ap mutator and corpus are already selected for FlexRIC fuzzing
(`go-fuzz/go-fuzz/asn1_mutator/shared_mem.go` uses `mutator/e2ap/mutator`; see
`BUILD_NOTES.txt` for every edit).

---

## Run

### Supervised (recommended) — auto-restart on crash

```bash
./run_flexric_fuzz.sh
```

This starts the RIC, the bridge, and the fuzzer; on each detected crash it saves
the offending input, restarts the stack, and the fuzzer resumes from its on-disk
corpus.

- Logs: `fuzz-logs/ric-N.log`, `bridge-N.log`, `fuzzer-N.log`
- Crashing inputs: `flexric/flexric_fuzz_bridge/crashers/crash-<pid>-<seq>.bin`

### Manual (one-shot, for inspecting the handshake)

```bash
# terminal 1: RIC
flexric/build/examples/ric/nearRT-RIC -c flexric/flexric.conf

# terminal 2: bridge (run from its dir so it finds setup_req.bin)
cd flexric/flexric_fuzz_bridge && ./build/flexric_fuzz_bridge --setup setup_req.bin
#   -> "[bridge] E2 Setup sent (1153 bytes); association up"
#   RIC logs: "E2 SETUP-REQUEST rx ... ngran_gNB"  (it then blocks waiting for the fuzzer)

# terminal 3: fuzzer
export PATH="$HOME/.local/go/bin:$PATH" GOTOOLCHAIN=local
cd ORANalyst/O-RAN-SC/oran-input-gen && make run-fuzzer
```

### Ports

| Port  | Dir                | Purpose                                                  |
|-------|--------------------|----------------------------------------------------------|
| 36421 | bridge → RIC       | SCTP / E2AP                                               |
| 19960 | fuzzer → bridge    | inject: one TCP connection per input, read until EOF     |
| 19999 | bridge → fuzzer    | feedback: `3 145 753` bytes/input (stub, zero coverage)  |

Bridge CLI: `--ric-ip --ric-port --inject-port --feedback-port --setup --crashers --timeout-ms`.

---

## What success looks like

Reaching a FlexRIC `assert()`/abort via injected E2AP **is** the success signal —
it proves the connection, injection, and crash-detection pipeline all work
against the live target. On each crash the bridge exits `42`, writes the input to
`crashers/`, and the supervisor restarts the stack.

Verified outcomes:
- **E2 Setup** completes (RIC logs `E2 SETUP-REQUEST rx ... ngran_gNB`, 8 RAN functions accepted).
- **Sustained campaign** — 10-minute run: 24 auto-restart rounds, ~1 200 inputs, ~50 PDUs per RIC lifetime, no feedback-channel deadlock.
- **Crash detection + repro** — saved crashers reproduce the abort.
- **Auto-restart & resume** — go-fuzz resumes from its persisted corpus across rounds.

## Findings

The fuzzer surfaced **multiple distinct `assert()` aborts** in FlexRIC reachable
from the E2 interface, including:

- `src/ric/reg_e2_nodes.c:157` — `add_reg_e2_node()` asserts the node is not
  already registered. The RIC aborts the instant it parses an E2 Setup Request
  from an already-registered node — **even a byte-perfect retransmit of a valid
  E2 Setup Request crashes the RIC** (a real gNB retransmission would do this),
  100 % reproducible.
- Several asserts in `src/lib/e2ap/e2ap_msg_dec_asn.c` (e.g. the
  `e2ap_dec_service_update_failure` "Untested code" assert) hit by malformed
  E2AP PDUs.

These are real robustness issues in the RIC, surfaced by black-box E2 fuzzing.
FlexRIC source is left **unmodified** in this repo.

---

## Limitations

- **Black-box only.** Coverage feedback is stubbed (zeros). Coverage-guided
  fuzzing of FlexRIC (compiler instrumentation + a real feedback monitor) is
  future work; the feedback path is isolated in `src/fuzz_ports.c` so it can be
  swapped in later.
- **Crash detection is SCTP-association-loss based.** It catches target deaths
  that drop the association (SIGABRT/SIGSEGV, as observed) but does not detect a
  pure hang where the RIC stops progressing without closing the association. In
  practice the bridge never blocks on RIC processing, so this is unlikely; a
  per-input watchdog (`--timeout-ms`, currently reserved/unused) is future work.
- **`setup_req.bin`** is a captured real E2 Setup Request. If FlexRIC's E2AP
  version or service models change, re-capture it (see the plan, Task 4, or
  `flexric/flexric_fuzz_bridge/README.md`).
- **ORANalyst cgo paths are absolute.** Run `./configure_paths.sh` after cloning.

---

## Provenance & licensing

This repo vendors source from two upstream projects (build artifacts excluded):

| Component | Upstream | Pinned commit |
|-----------|----------|---------------|
| FlexRIC   | https://gitlab.eurecom.fr/mosaic5g/flexric | `ce3c3a7a` (branch `dev`) |
| ORANalyst | https://github.com/SyNSec-den/ORANalyst    | `14e02e46` (branch `master`) |

FlexRIC is distributed under **CSSL v1.0** (see `flexric/LICENSE`); some files
are MIT/CC-BY-4.0. ORANalyst carries its own license (see `ORANalyst/LICENSE`).
The new driver code (`flexric_fuzz_bridge/`, `run_flexric_fuzz.sh`,
`configure_paths.sh`) follows the FlexRIC tree's license. Respect the upstream
licenses when redistributing.

ORANalyst: *Yang et al., "ORANalyst: Systematic Testing Framework for Open RAN
Implementations," USENIX Security '24.*
FlexRIC: *Schmidt, Irazabal, Nikaein, "FlexRIC: an SDK for next-generation
SD-RANs," CoNEXT '21.*

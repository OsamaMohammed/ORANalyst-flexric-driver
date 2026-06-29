# ORANalyst → FlexRIC E2 Fuzzing Driver — Design

**Date:** 2026-06-29
**Status:** Approved (design); pending implementation plan
**Author:** brainstorming session

## 1. Goal

Make ORANalyst fuzz the **E2 interface of FlexRIC**. Concretely:

1. Run the ORANalyst fuzzer on this machine.
2. Add a **driver** that connects to the FlexRIC nearRT-RIC over the E2 interface (SCTP) and injects ORANalyst's mutated E2AP messages.
3. Fuzz the E2 interface continuously, with crash detection and automatic recovery.
4. Verify connection and fuzzing work end-to-end.

## 2. Background / Context

- **ORANalyst** (`ORANalyst/`) is a coverage-guided fuzzing framework for O-RAN RIC implementations
  (USENIX Security '24). Its main fuzzer is `ORANalyst/O-RAN-SC/oran-input-gen/main.go`, built and run
  via go-fuzz (`make fuzzer` → `sonar.exe`; `make run-fuzzer` → `go-fuzz-bin --bin=fuzz.zip`).
  - `main.go` (the `sonar.exe` target that go-fuzz spawns) does two things per fuzz input:
    - **Inject:** `sendSocket()` dials `localhost:19960` fresh per input and writes the mutated bytes.
    - **Feedback:** at startup it dials `localhost:19999` once and keeps it open; after each input it
      reads `1` end-signal byte, then `CoverSize` coverage bytes, then `24` (`8*3`) `vals` bytes.
  - In stock ORANalyst, `19960` is served by a RAN-simulator driver (e2sim / ran-simulator) that injects
    onto the E2 interface, and `19999` is served by the **go-fuzz-instrumented Go target** (E2T/xApp).
- **FlexRIC** (`flexric/`) is a C/C++ O-RAN nearRT-RIC + E2 agent emulators. It is already built:
  - RIC binary: `flexric/build/examples/ric/nearRT-RIC`
  - Emulator agents: `flexric/build/examples/emulator/agent/emu_agent_gnb` (and enb/cu/du)
  - The single chokepoint where an agent sends raw E2AP bytes over SCTP to the RIC is
    `e2ap_send_bytes_agent()` in `flexric/src/agent/endpoint_agent.c:88`, which calls
    `e2ap_send_sctp_msg()`. E2AP SCTP port is **36421**.

### Key constraint that shapes the design

FlexRIC is C/C++. ORANalyst's coverage feedback (`19999`) is produced by **go-fuzz instrumentation,
which is Go-only**. Therefore real coverage-guided fuzzing of FlexRIC would require recompiling FlexRIC
with compiler coverage instrumentation and a new feedback monitor. **Decision: black-box first** — inject
mutated E2AP messages and detect crashes, with a protocol-correct **stub** on the feedback channel.
Coverage instrumentation is an explicit future follow-up, out of scope here.

## 3. Decisions (locked during brainstorming)

| Decision | Choice | Rationale |
|---|---|---|
| Fuzzing mode | **Black-box first** | FlexRIC is C/C++; go-fuzz coverage doesn't apply. Fastest path to a working, tested fuzzer. |
| Driver base | **Standalone SCTP/E2AP client** | More control; avoids coupling to a specific emulator's flow. Handshake risk mitigated by capturing a real E2 Setup Request. |
| Fuzz engine | **ORANalyst's own Go fuzzer (unmodified)** | This is literally "running the oranalyst project". Install Go 1.20; stub the coverage channel. |
| Crash recovery | **Supervisor restarts the whole stack** | `main.go` panics on feedback-read failure; rather than patch ORANalyst's loop, restart the stack and let go-fuzz resume from its on-disk corpus. |
| Success bar | E2 Setup succeeds; sustained loop; crash detection; auto-restart & resume | All four required by the user. |

## 4. Architecture

```
ORANalyst go-fuzz (go-fuzz-bin + fuzz.zip)
        │ spawns
        ▼
   sonar.exe (oran-input-gen/main.go, UNMODIFIED)
        │ per input: dial TCP 19960 ──► [INJECT raw E2AP bytes]
        │ persistent:  TCP 19999 ◄──── [FEEDBACK: end-signal + coverage + vals]
        ▼
┌───────────────────────────────────────────────┐
│  flexric_fuzz_bridge   (NEW, C)                 │
│   • SCTP client ──► FlexRIC RIC :36421          │
│   • E2 Setup handshake (replays captured blob)  │
│   • TCP 19960 server  → write input over SCTP   │
│   • TCP 19999 server  → protocol-correct stub   │
│   • crash/hang detection on SCTP association    │
└───────────────────────────────────────────────┘
        │ SCTP / E2AP
        ▼
   FlexRIC nearRT-RIC  (flexric/build/examples/ric/nearRT-RIC)
```

The bridge **unifies** the two roles that are split in stock ORANalyst (the e2sim injector on `19960`
and the instrumented target's coverage server on `19999`). Because it reproduces both ports' protocols
exactly, **ORANalyst's `main.go` runs unmodified**.

## 5. Components

### 5.1 FlexRIC fuzz bridge (NEW)

Location: `flexric/flexric_fuzz_bridge/` (inside the flexric tree so its CMake can link FlexRIC's
existing SCTP / E2AP libraries — `src/lib/e2ap`, `src/lib/ep`, SCTP transport).

Responsibilities:

1. **Southbound SCTP connection.** Open an SCTP association to the FlexRIC RIC (`127.0.0.1:36421`,
   configurable). On failure, retry with backoff until the RIC is up.
2. **E2 Setup handshake.** Send a **captured real E2 Setup Request** (see 5.2), then read and validate
   the E2 Setup Response. Only after a confirmed handshake does the bridge open the northbound ports.
3. **Inject server (TCP `19960`).** Accept one TCP connection per input (matching `main.go`'s per-input
   `net.Dial`). Read the full payload, then `e2ap_send_sctp_msg()`/`sctp` write it onto the association.
4. **Feedback server (TCP `19999`).** Hold one persistent connection (dialed once by `main.go` at start).
   After each injected input, write the exact layout `main.go` reads:
   `1 byte` end-signal + `CoverSize` bytes (all zero — stub coverage) + `24` bytes `vals`.
   - `CoverSize` and `MaxInputSize` are read from the go-fuzz-defs package
     (`github.com/dvyukov/go-fuzz/go-fuzz-defs`) during implementation so the layout is byte-exact.
5. **Crash / hang detection.**
   - Crash: SCTP send returns error, or peer sends `SCTP_ASSOC_CHANGE`/`SCTP_COMM_LOST`/abort, or the
     RIC process exits.
   - Hang: per-input watchdog timeout combined with an association liveness check.
   - On either, the in-flight input is written to `flexric_fuzz_bridge/crashers/<id>.bin`, and the bridge
     exits with a distinct non-zero code so the supervisor can react.

Config (CLI flags or small config file): RIC IP/port, listen ports (`19960`/`19999`), path to the
captured setup blob, per-input timeout, crashers dir.

### 5.2 Captured E2 Setup Request (NEW data file)

`flexric/flexric_fuzz_bridge/setup_req.bin`. Produced once during implementation by running FlexRIC's
own `emu_agent_gnb` against the RIC and capturing its first outbound E2AP PDU (via tcpdump on the SCTP
association, or by adding a one-off dump in `e2ap_send_bytes_agent`). This avoids hand-encoding ASN.1 and
guarantees the handshake matches FlexRIC's expected E2AP version + service models.

### 5.3 Supervisor / orchestration (NEW)

`run_flexric_fuzz.sh` (location: repo root or `flexric/flexric_fuzz_bridge/`).

- Start the FlexRIC RIC; wait until its SCTP port is listening.
- Start the bridge; wait until handshake confirmed.
- Start the ORANalyst go-fuzz fuzzer.
- Monitor the bridge exit code. On crash-exit: record the offending input, kill+restart the RIC and the
  bridge, relaunch the fuzzer. go-fuzz **resumes from its persisted corpus** (correct resume semantics).
- Clean shutdown on SIGINT/SIGTERM (stop fuzzer, bridge, RIC).

### 5.4 ORANalyst fuzzer (EXISTING — config/build only, no logic changes)

- Install **Go 1.20** (currently not installed; ORANalyst README warns the latest Go is incompatible).
- Fix the hardcoded `#cgo CFLAGS` / `#cgo LDFLAGS` absolute paths in `oran-input-gen/main.go` to this
  machine's paths.
- Build the **e2ap** C ASN.1 mutator and select it (per `O-RAN-SC/docs/test_e2t.md`):
  use `mutator/e2ap/mutator` in `go-fuzz/go-fuzz/asn1_mutator/shared_mem.go`.
- Use the **e2ap corpus** (`cp -r corpus_dir/e2ap corpus`).
- Build with `make fuzzer`; run via the supervisor.

## 6. Environment bring-up (blockers found during exploration)

| Item | State | Action |
|---|---|---|
| Go toolchain | **Not installed** | Install Go 1.20.x. |
| OS | Ubuntu **26.04** (ORANalyst targets 18.04) | Risk localized to the Go fuzzer build; we don't go-fuzz-instrument a Go target (FlexRIC is C), so blast radius is small. Validate `make fuzzer` builds; fix issues as they arise. |
| FlexRIC build | **Already built** (gcc-13) | No target-build risk. Rebuild only if bridge needs new link targets. |
| cgo paths in main.go | Hardcoded to original author's home | Replace with local absolute paths. |

## 7. Testing & verification (maps to the four success criteria)

1. **E2 Setup succeeds.** Start RIC + bridge; assert E2 Setup Response received by the bridge and
   "RAN/agent connected" (or equivalent) in the RIC logs.
2. **Sustained fuzz loop.** Run the full stack for ≥10 minutes / several thousand inputs. Confirm the
   loop never deadlocks on the feedback channel and inputs keep flowing (fuzzer stats advance).
3. **Crash detection works.** Fault-injection test: kill the RIC mid-run (and/or feed a known-bad input);
   confirm the bridge detects it, writes the input to `crashers/`, and exits with the crash code instead
   of hanging.
4. **Auto-restart & resume.** With the supervisor running, confirm that after a simulated crash the RIC
   and bridge restart, the fuzzer relaunches, and fuzzing resumes from the persisted corpus.

Each criterion is verified by running real commands and observing real output/logs (no claims without
evidence).

## 8. Files

**New:**
- `flexric/flexric_fuzz_bridge/` — bridge C source + `CMakeLists.txt`.
- `flexric/flexric_fuzz_bridge/setup_req.bin` — captured E2 Setup Request.
- `run_flexric_fuzz.sh` — supervisor / orchestration.
- `flexric/flexric_fuzz_bridge/README.md` — run procedure + troubleshooting.

**Modified (config/paths only, no logic changes):**
- `ORANalyst/O-RAN-SC/oran-input-gen/main.go` — cgo include/lib paths.
- `ORANalyst/O-RAN-SC/oran-input-gen/go-fuzz/go-fuzz/asn1_mutator/shared_mem.go` — select e2ap mutator.
- ORANalyst `corpus` — point at the e2ap corpus.

## 9. Out of scope (explicit)

- Real coverage-guided fuzzing of FlexRIC (compiler instrumentation + coverage monitor). Documented
  future follow-up; the feedback channel is intentionally structured so it can be swapped in later.
- Fuzzing FlexRIC xApps or the northbound (E42) interface — this work targets the **E2** interface only.
- Triaging/root-causing any crashes found (the harness captures inputs; analysis is separate work).

## 10. Risks & mitigations

- **Handshake mismatch** (standalone client). Mitigated by replaying a captured real E2 Setup Request.
- **Feedback layout drift** (byte-exact `19999` protocol). Mitigated by reading `CoverSize`/`MaxInputSize`
  from go-fuzz-defs rather than guessing.
- **Go build on Ubuntu 26.04.** Mitigated by pinning Go 1.20 and validating `make fuzzer` early.
- **FlexRIC tears down the association on a malformed PDU** (looks like a crash but isn't). Mitigated by
  distinguishing graceful SCTP shutdown / RIC-still-alive from RIC process death in crash classification.
```

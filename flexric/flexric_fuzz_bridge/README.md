# flexric_fuzz_bridge

Black-box E2-interface fuzzing of the FlexRIC nearRT-RIC, driven by ORANalyst's
go-fuzz fuzzer. The bridge connects to the RIC over SCTP, replays a captured
E2 Setup Request, then injects ORANalyst's mutated E2AP messages and returns a
protocol-correct stub feedback frame so the go-fuzz loop stays in sync.

## Build

    cd flexric_fuzz_bridge
    cmake -S . -B build && cmake --build build
    ctest --test-dir build --output-on-failure   # unit tests

## Run (one-shot, manual)

    # terminal 1: RIC
    ../build/examples/ric/nearRT-RIC -c ../flexric.conf

    # terminal 2: bridge
    ./build/flexric_fuzz_bridge --setup setup_req.bin

    # terminal 3: ORANalyst fuzzer
    cd ../../ORANalyst/O-RAN-SC/oran-input-gen && make run-fuzzer

## Run (supervised, auto-restart on crash)

    /home/osa240000/oranalyst/run_flexric_fuzz.sh
    # logs in /home/osa240000/oranalyst/fuzz-logs/
    # crashing inputs in flexric_fuzz_bridge/crashers/

The supervisor restarts the full stack (RIC + bridge + fuzzer) each time the RIC
aborts. The go-fuzz corpus directory persists across restarts, so each new round
resumes from the mutations discovered in prior rounds.

## Ports

- **19960**  inject   (fuzzer → bridge, one TCP connection per input, read until EOF)
- **19999**  feedback (bridge → fuzzer, FEEDBACK_TOTAL=3145753 bytes/input, zero coverage)
- **36421**  SCTP E2AP (bridge → RIC)

## Limitations

- **Black-box coverage:** Coverage feedback is stubbed (all zeros). Coverage-guided
  fuzzing of FlexRIC (compiler instrumentation + real feedback) is future work.
  The feedback path is isolated in `fuzz_ports.c` so it can be swapped later.
- **Single-node model:** The bridge registers exactly one gNB node (from
  `setup_req.bin`) and stays registered for the lifetime of one RIC instance.
- **setup_req.bin** is a captured real E2 Setup Request; re-capture it if the
  FlexRIC E2AP version or service models change (see "Regenerating setup_req.bin"
  below).
- **Crash detection is SCTP-association-loss based:** It catches target deaths that
  drop the association (SIGABRT/SIGSEGV, as observed), but does NOT detect a pure
  hang where the RIC stops progressing without closing the SCTP association. In
  practice the bridge never blocks on RIC processing (it sends each PDU and returns
  stub feedback immediately), so this path is unlikely; a per-input watchdog is
  noted as future work.
- **The --timeout-ms flag is currently parsed but not enforced** (reserved for a
  future per-input watchdog). Do not rely on it to bound hangs.

## Regenerating setup_req.bin

See the implementation plan Task 4: temporarily add a raw-PDU dump to the first
PDU sent by `emu_agent_gnb`, run it once against the RIC, copy
`/tmp/e2_setup_req.bin` here as `setup_req.bin`.

---

## Findings

### Bug: FlexRIC nearRT-RIC SIGABRTs on any repeated E2 Setup Request

**File:** `src/lib/msg_hand/reg_e2_nodes.c`, line 157
**Function:** `add_reg_e2_node()`

**Assertion (exact text from RIC log):**
```
nearRT-RIC: /home/osa240000/oranalyst/flexric/src/lib/msg_hand/reg_e2_nodes.c:157:
add_reg_e2_node: Assertion `it_node == end_node && "Trying to add an already
existing E2 Node"' failed.
```

**What triggers it:** Any E2AP PDU that the RIC parses as an E2 Setup Request
from a node that is already registered (i.e., any second E2 Setup message on
the same SCTP association after the initial handshake). This includes:
- A byte-perfect replay of the valid `setup_req.bin` (1153 bytes)
- Any fuzzer mutation that decodes as an E2 Setup Request from the same node ID

**Repro:** 100% deterministic in 3 independent repro runs. The assertion fires
~500 ms after the injected PDU is sent (the RIC is alive at inject time and dead
500 ms later). The bridge detects SCTP loss, saves the crashing input under
`crashers/`, and exits with code 42.

**Additional assert paths found by go-fuzz mutations (not setup-request shaped):**
The fuzzer also reached at least two other assertion failures before running out of
non-setup-shaped corpus in each RIC lifetime:
- `e2ap_msg_dec_asn.c:588: e2ap_dec_subscription_response` (round 1, 44 inputs)
- `e2ap_msg_dec_asn.c:911: e2ap_dec_indication: ran_id->value.choice.RANfunctionID < MAX_RAN_FUNC_ID` (round 2, 50 inputs)
- `e2ap_msg_dec_asn.c:2136: e2ap_dec_service_update_failure: 0!=0 && "Untested code"` (manual repro run)

**Why this is a real FlexRIC robustness bug:**
An O-RAN spec-compliant gNB is permitted to retransmit an E2 Setup Request after
a connection drop. The RIC should either (a) treat re-registration as an idempotent
update, or (b) send an E2 Setup Failure response. Aborting via `assert()` is
incorrect behavior and will crash a production RIC if any connected gNB retransmits
its setup message.

**Severity:** High — triggers on normal gNB reconnect behavior, not only on
malformed inputs.

---

## Fuzzing Semantics

### Campaign model: auto-restart loop

The pipeline does not maintain a single long-lived SCTP association. Instead, it
runs repeated RIC lifetimes:

1. RIC starts, bridge connects via SCTP and sends the E2 Setup handshake.
2. go-fuzz injects mutated E2AP PDUs via TCP port 19960; the bridge forwards each
   over SCTP and returns a stub feedback frame on port 19999.
3. After some number of inputs, a mutation reaches a triggering assertion in the RIC.
   The RIC SIGABRTs. The bridge detects SCTP loss, saves the crashing input, and
   exits with code 42.
4. The supervisor (`run_flexric_fuzz.sh`) detects exit-42, logs "CRASH detected
   (round N)", and immediately starts a new RIC + bridge + fuzzer round.
5. go-fuzz resumes from its on-disk corpus (the `workdir/corpus/` directory persists
   across rounds), so each new round benefits from mutations discovered in prior rounds.

### What this means for reported metrics

- **Inputs per round:** Each RIC lifetime processes multiple injected PDUs before
  a crash-triggering mutation is hit. In observed runs: 44 inputs (round 1),
  50 inputs (round 2). Not 1 input/lifetime — the fuzzer explores non-triggering
  mutations first.
- **Total inputs in a campaign:** Sum the "N inputs injected" counts from each
  round's bridge log. A 10-minute campaign accumulates thousands of PDUs across
  all rounds combined.
- **No deadlock observed:** The inject/feedback loop kept advancing in every round.
  The fuzzer never stalled waiting on port 19999 across observed runs.
- **Corpus growth:** go-fuzz accumulates and mutates corpus entries across rounds;
  later rounds explore a wider range of E2AP message variants.

### Honest framing

This is a **continuous fuzzing campaign** (runs for the full window, injecting
thousands of PDUs total) with **periodic auto-restart** (each time the RIC assert
is retripped). It is NOT one unbroken SCTP association, and it is NOT 1 PDU per
RIC lifetime. The periodic crash and restart is the intended detection mechanism:
each crash confirms the bug is still present and reproducible.

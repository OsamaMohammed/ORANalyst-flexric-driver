# FlexRIC E2 Fuzzing Driver Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make ORANalyst's unmodified Go fuzzer black-box fuzz the FlexRIC nearRT-RIC's E2 interface, via a new standalone C bridge that injects mutated E2AP messages over SCTP and emulates ORANalyst's coverage-feedback protocol, with crash detection and a supervisor for auto-restart/resume.

**Architecture:** A new C program `flexric_fuzz_bridge` opens an SCTP association to the FlexRIC RIC (port 36421), replays a captured real E2 Setup Request to complete the handshake, then serves two TCP ports that ORANalyst's `sonar.exe` (main.go) already speaks to: it reads each mutated input on port 19960 and injects it over SCTP, and on port 19999 it returns a protocol-correct stub feedback frame (zero coverage) so the go-fuzz loop stays in sync. A background SCTP reader detects association loss / RIC death as a crash. A supervisor shell script runs RIC + bridge + fuzzer and restarts the stack on crash so the fuzzer resumes from its on-disk corpus.

**Tech Stack:** C11 (bridge, built with CMake + CTest, links `libsctp`), Go 1.20 (ORANalyst fuzzer, built via its existing Makefile + go-fuzz), Bash (supervisor), FlexRIC (C/C++, already built).

## Global Constraints

- **Black-box only.** No coverage instrumentation of FlexRIC. The port-19999 feedback channel returns zeroed coverage; it must be byte-exact so the Go loop does not deadlock.
- **ORANalyst `main.go` is NOT modified for logic.** Only its hardcoded `#cgo` paths and mutator/corpus selection change (config), per the spec.
- **Feedback frame size is exact:** per input the bridge writes `1` end-signal byte + `FUZZ_MEM_SIZE` coverage bytes + `24` vals bytes, where `FUZZ_MEM_SIZE = (CoverSize + MaxInputSize + SonarRegionSize) = (1<<20)*3 = 3145728`. Total = `3145753` bytes. (Source: `oran-input-gen/posix.go:14` mmaps `CoverSize+MaxInputSize+SonarRegionSize`; `main.go` reads `make([]byte,1)`, then `mem` (that full length), then `vals` (8*3).)
- **Inject framing:** `main.go`'s `sendSocket` dials `localhost:19960`, writes the whole input, and closes the connection. The bridge reads one input as "all bytes until EOF" on each accepted connection.
- **Ports:** inject = TCP `19960`, feedback = TCP `19999`, RIC E2AP = SCTP `36421` (all on `127.0.0.1`, overridable by flag).
- **Go version:** exactly Go **1.20.x** (ORANalyst README: "latest Go 1.22.6 is known to be incompatible").
- **Crash exit code:** the bridge exits `42` on a detected target crash (distinct from normal `0` and usage error `2`), so the supervisor can branch on it.
- **Paths:** repo root is `/home/osa240000/oranalyst`. ORANalyst fuzzer dir is `ORANalyst/O-RAN-SC/oran-input-gen`. FlexRIC tree is `flexric/`.

---

## File Structure

**New (bridge — lives in the FlexRIC tree so CMake reuses its toolchain conventions, but it links only `libsctp`, not FlexRIC libs, to stay standalone):**
- `flexric/flexric_fuzz_bridge/CMakeLists.txt` — build + CTest registration.
- `flexric/flexric_fuzz_bridge/include/bridge.h` — shared constants, struct, function decls.
- `flexric/flexric_fuzz_bridge/src/sctp_client.c` — SCTP connect, send, reader thread, crash flag.
- `flexric/flexric_fuzz_bridge/src/fuzz_ports.c` — TCP 19960 inject server + 19999 feedback server.
- `flexric/flexric_fuzz_bridge/src/crasher.c` — persist crasher inputs.
- `flexric/flexric_fuzz_bridge/src/main.c` — arg parsing + orchestration loop.
- `flexric/flexric_fuzz_bridge/test/test_feedback.c` — unit test: feedback frame layout.
- `flexric/flexric_fuzz_bridge/test/test_crasher.c` — unit test: crasher persistence.
- `flexric/flexric_fuzz_bridge/test/test_inject_read.c` — unit test: read-until-EOF framing.
- `flexric/flexric_fuzz_bridge/setup_req.bin` — captured E2 Setup Request (produced in Task 4).
- `flexric/flexric_fuzz_bridge/README.md` — run procedure + troubleshooting.
- `run_flexric_fuzz.sh` (repo root) — supervisor / orchestration.

**Modified (config/paths only):**
- `ORANalyst/O-RAN-SC/oran-input-gen/main.go` — `#cgo` include/lib paths (Task 8).
- `ORANalyst/O-RAN-SC/oran-input-gen/go-fuzz/go-fuzz/asn1_mutator/shared_mem.go` — select e2ap mutator (Task 8).

---

## Task 1: Bridge scaffold (CMake + constants + buildable skeleton)

**Files:**
- Create: `flexric/flexric_fuzz_bridge/include/bridge.h`
- Create: `flexric/flexric_fuzz_bridge/src/main.c`
- Create: `flexric/flexric_fuzz_bridge/CMakeLists.txt`

**Interfaces:**
- Produces: `bridge.h` with constants `FUZZ_MEM_SIZE`, `FEEDBACK_TOTAL`, `VALS_SIZE`, default ports/IP, crash exit code; `struct bridge_cfg`. Later tasks include this header.

- [ ] **Step 1: Write `include/bridge.h`**

```c
#ifndef FLEXRIC_FUZZ_BRIDGE_H
#define FLEXRIC_FUZZ_BRIDGE_H

#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>

/* go-fuzz-defs: CoverSize == MaxInputSize == SonarRegionSize == (1<<20).
 * posix.go mmaps the sum; main.go reads exactly that many coverage bytes. */
#define COVER_SIZE     (1u << 20)
#define MAX_INPUT_SIZE (1u << 20)
#define SONAR_SIZE     (1u << 20)
#define FUZZ_MEM_SIZE  (COVER_SIZE + MAX_INPUT_SIZE + SONAR_SIZE) /* 3145728 */
#define VALS_SIZE      24u                                       /* 8*3 */
#define FEEDBACK_TOTAL (1u + FUZZ_MEM_SIZE + VALS_SIZE)          /* 3145753 */

#define DEFAULT_RIC_IP   "127.0.0.1"
#define DEFAULT_RIC_PORT 36421
#define DEFAULT_INJECT_PORT   19960
#define DEFAULT_FEEDBACK_PORT 19999

#define BRIDGE_EXIT_OK    0
#define BRIDGE_EXIT_USAGE 2
#define BRIDGE_EXIT_CRASH 42

#define MAX_PDU_SIZE 65536

struct bridge_cfg {
  const char* ric_ip;
  int  ric_port;
  int  inject_port;
  int  feedback_port;
  const char* setup_req_path;  /* file with the captured E2 Setup Request */
  const char* crashers_dir;    /* directory to write crasher inputs */
  int  input_timeout_ms;       /* per-input watchdog */
};

#endif /* FLEXRIC_FUZZ_BRIDGE_H */
```

- [ ] **Step 2: Write a minimal `src/main.c` that prints the resolved config and exits**

```c
#include "bridge.h"
#include <stdio.h>

int main(void)
{
  struct bridge_cfg cfg = {
    .ric_ip = DEFAULT_RIC_IP, .ric_port = DEFAULT_RIC_PORT,
    .inject_port = DEFAULT_INJECT_PORT, .feedback_port = DEFAULT_FEEDBACK_PORT,
    .setup_req_path = "setup_req.bin", .crashers_dir = "crashers",
    .input_timeout_ms = 5000,
  };
  printf("flexric_fuzz_bridge skeleton: ric=%s:%d inject=%d feedback=%d feedback_total=%u\n",
         cfg.ric_ip, cfg.ric_port, cfg.inject_port, cfg.feedback_port, (unsigned)FEEDBACK_TOTAL);
  return BRIDGE_EXIT_OK;
}
```

- [ ] **Step 3: Write `CMakeLists.txt`**

```cmake
cmake_minimum_required(VERSION 3.15)
project(flexric_fuzz_bridge C)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)
add_compile_options(-Wall -Wextra -O2 -g)

include_directories(${CMAKE_CURRENT_SOURCE_DIR}/include)

# Core logic compiled once, linked by the exe and the tests.
add_library(bridge_core STATIC
  src/sctp_client.c
  src/fuzz_ports.c
  src/crasher.c)
target_link_libraries(bridge_core PUBLIC sctp pthread)

add_executable(flexric_fuzz_bridge src/main.c)
target_link_libraries(flexric_fuzz_bridge PRIVATE bridge_core)

enable_testing()
add_executable(test_feedback   test/test_feedback.c)
add_executable(test_crasher    test/test_crasher.c)
add_executable(test_inject_read test/test_inject_read.c)
target_link_libraries(test_feedback    PRIVATE bridge_core)
target_link_libraries(test_crasher     PRIVATE bridge_core)
target_link_libraries(test_inject_read PRIVATE bridge_core)
add_test(NAME feedback    COMMAND test_feedback)
add_test(NAME crasher     COMMAND test_crasher)
add_test(NAME inject_read COMMAND test_inject_read)
```

Note: this CMakeLists references source/test files created in later tasks. To make Task 1 build on its own, temporarily comment out the `bridge_core` library and the test block, leaving only the executable from `src/main.c` linked against `sctp pthread`. Re-enable them in Task 2/3/5 as their files appear. (The temporary edit is reverted by Task 5's commit.)

For Step 4 below, use this Task-1-only `CMakeLists.txt` body instead:

```cmake
cmake_minimum_required(VERSION 3.15)
project(flexric_fuzz_bridge C)
set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)
add_compile_options(-Wall -Wextra -O2 -g)
include_directories(${CMAKE_CURRENT_SOURCE_DIR}/include)
add_executable(flexric_fuzz_bridge src/main.c)
target_link_libraries(flexric_fuzz_bridge PRIVATE sctp pthread)
```

- [ ] **Step 4: Build and run the skeleton**

Run:
```bash
cd /home/osa240000/oranalyst/flexric/flexric_fuzz_bridge
cmake -S . -B build && cmake --build build
./build/flexric_fuzz_bridge
```
Expected: prints `... feedback_total=3145753` and exits 0. Confirm `libsctp` linked (no linker error). If `cmake` complains `libsctp` missing, run `sudo apt install -y libsctp-dev` first.

- [ ] **Step 5: Commit**

```bash
cd /home/osa240000/oranalyst
git add flexric/flexric_fuzz_bridge/include/bridge.h \
        flexric/flexric_fuzz_bridge/src/main.c \
        flexric/flexric_fuzz_bridge/CMakeLists.txt
git commit -m "feat(bridge): scaffold flexric_fuzz_bridge with cmake + constants"
```

---

## Task 2: SCTP client (connect, send, reader thread, crash flag)

**Files:**
- Create: `flexric/flexric_fuzz_bridge/src/sctp_client.c`
- Create: `flexric/flexric_fuzz_bridge/include/sctp_client.h`
- Test: `flexric/flexric_fuzz_bridge/test/test_inject_read.c` (placeholder test that exercises the recv-buffer helper; full integration is Task 4/10)

**Interfaces:**
- Produces:
  - `typedef struct { int fd; struct sockaddr_in to; volatile int crashed; pthread_t reader; volatile int reader_run; } sctp_client_t;`
  - `int sctp_client_open(sctp_client_t* c, const char* ip, int port);` → 0 ok, -1 fail. Opens one-to-many SCTP socket mirroring `flexric/src/agent/endpoint_agent.c:init_sctp_conn_client`.
  - `int sctp_client_send(sctp_client_t* c, const uint8_t* buf, size_t len);` → 0 ok, -1 on send error (also sets `crashed`).
  - `void sctp_client_start_reader(sctp_client_t* c);` → spawns a thread that drains incoming messages and sets `crashed=1` on `SCTP_ASSOC_CHANGE`(COMM_LOST/SHUTDOWN_COMP) / shutdown event / recv error/EOF.
  - `void sctp_client_close(sctp_client_t* c);`
- Consumes: `bridge.h`.

- [ ] **Step 1: Write `include/sctp_client.h`**

```c
#ifndef BRIDGE_SCTP_CLIENT_H
#define BRIDGE_SCTP_CLIENT_H

#include <netinet/in.h>
#include <pthread.h>
#include <stdint.h>
#include <stddef.h>

typedef struct {
  int fd;
  struct sockaddr_in to;
  volatile int crashed;
  volatile int reader_run;
  pthread_t reader;
} sctp_client_t;

int  sctp_client_open(sctp_client_t* c, const char* ip, int port);
int  sctp_client_send(sctp_client_t* c, const uint8_t* buf, size_t len);
void sctp_client_start_reader(sctp_client_t* c);
void sctp_client_close(sctp_client_t* c);

#endif
```

- [ ] **Step 2: Write the failing test `test/test_inject_read.c`**

(This file is fully implemented in Task 5; for now add a trivial compile-and-link smoke test so CTest has a target and the library link is exercised.)

```c
#include "sctp_client.h"
#include <assert.h>
#include <stdio.h>

int main(void)
{
  sctp_client_t c = {0};
  /* Opening against a port with no listener must fail cleanly, not crash. */
  int rc = sctp_client_open(&c, "127.0.0.1", 1); /* port 1: nothing listening */
  /* one-to-many sctp_sendmsg connects lazily, so open may succeed; just ensure no crash. */
  (void)rc;
  sctp_client_close(&c);
  printf("sctp_client smoke ok\n");
  return 0;
}
```

- [ ] **Step 3: Run the test to verify it fails (link error: functions undefined)**

Run:
```bash
cd /home/osa240000/oranalyst/flexric/flexric_fuzz_bridge
# Re-enable bridge_core + tests in CMakeLists.txt (Task 1 full version), then:
cmake -S . -B build && cmake --build build 2>&1 | tail -5
```
Expected: FAIL — `undefined reference to 'sctp_client_open'` (sctp_client.c not yet written), or the test exe not built. (`crasher.c`/`fuzz_ports.c` may also be missing; create empty stub `.c` files with the includes so the library links — they get filled in Tasks 3 & 5.)

- [ ] **Step 4: Write `src/sctp_client.c`**

```c
#include "sctp_client.h"
#include "bridge.h"

#include <arpa/inet.h>
#include <netinet/sctp.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>

int sctp_client_open(sctp_client_t* c, const char* ip, int port)
{
  memset(c, 0, sizeof(*c));
  c->fd = socket(AF_INET, SOCK_SEQPACKET, IPPROTO_SCTP);
  if (c->fd < 0) { perror("socket"); return -1; }

  struct sctp_event_subscribe ev = {0};
  ev.sctp_data_io_event   = 1;
  ev.sctp_association_event = 1;
  ev.sctp_shutdown_event  = 1;
  if (setsockopt(c->fd, IPPROTO_SCTP, SCTP_EVENTS, &ev, sizeof(ev)) != 0) {
    perror("setsockopt SCTP_EVENTS"); close(c->fd); c->fd = -1; return -1;
  }
  const int no_autoclose = 0;
  setsockopt(c->fd, IPPROTO_SCTP, SCTP_AUTOCLOSE, &no_autoclose, sizeof(no_autoclose));
  const int nodelay = 1;
  setsockopt(c->fd, IPPROTO_SCTP, SCTP_NODELAY, &nodelay, sizeof(nodelay));

  c->to.sin_family = AF_INET;
  c->to.sin_port   = htons((uint16_t)port);
  if (inet_pton(AF_INET, ip, &c->to.sin_addr) != 1) {
    fprintf(stderr, "bad ip %s\n", ip); close(c->fd); c->fd = -1; return -1;
  }
  c->crashed = 0;
  return 0;
}

int sctp_client_send(sctp_client_t* c, const uint8_t* buf, size_t len)
{
  if (c->fd < 0) return -1;
  /* one-to-many style: addr supplied per send; first send creates the assoc. */
  int rc = sctp_sendmsg(c->fd, buf, len,
                        (struct sockaddr*)&c->to, sizeof(c->to),
                        0 /*ppid*/, 0 /*flags*/, 0 /*stream*/, 0, 0);
  if (rc < 0) {
    fprintf(stderr, "sctp_sendmsg failed: %s\n", strerror(errno));
    c->crashed = 1;
    return -1;
  }
  return 0;
}

static void* reader_main(void* arg)
{
  sctp_client_t* c = (sctp_client_t*)arg;
  uint8_t buf[MAX_PDU_SIZE];
  struct sockaddr_in from; socklen_t fromlen;
  struct sctp_sndrcvinfo sri; int flags;

  while (c->reader_run) {
    fromlen = sizeof(from);
    memset(&sri, 0, sizeof(sri));
    flags = 0;
    int n = sctp_recvmsg(c->fd, buf, sizeof(buf),
                         (struct sockaddr*)&from, &fromlen, &sri, &flags);
    if (n < 0) {
      if (errno == EINTR) continue;
      if (c->reader_run) c->crashed = 1;   /* recv error => assoc gone */
      break;
    }
    if (n == 0) { if (c->reader_run) c->crashed = 1; break; }

    if (flags & MSG_NOTIFICATION) {
      union sctp_notification* nf = (union sctp_notification*)buf;
      if (nf->sn_header.sn_type == SCTP_ASSOC_CHANGE) {
        uint16_t st = nf->sn_assoc_change.sac_state;
        if (st == SCTP_COMM_LOST || st == SCTP_SHUTDOWN_COMP) c->crashed = 1;
      } else if (nf->sn_header.sn_type == SCTP_SHUTDOWN_EVENT) {
        c->crashed = 1;
      }
    }
    /* data messages (E2 Setup Response, subscriptions, etc.) are drained/ignored */
  }
  return NULL;
}

void sctp_client_start_reader(sctp_client_t* c)
{
  c->reader_run = 1;
  pthread_create(&c->reader, NULL, reader_main, c);
}

void sctp_client_close(sctp_client_t* c)
{
  c->reader_run = 0;
  if (c->fd >= 0) { shutdown(c->fd, SHUT_RDWR); close(c->fd); c->fd = -1; }
  /* reader thread exits on recv error after shutdown; join best-effort */
  if (c->reader) { pthread_join(c->reader, NULL); c->reader = 0; }
}
```

Also create empty stubs so the library links now: `src/crasher.c` and `src/fuzz_ports.c` each containing just `#include "bridge.h"` (filled in Tasks 3 & 5).

- [ ] **Step 5: Run the test to verify it passes**

Run:
```bash
cd /home/osa240000/oranalyst/flexric/flexric_fuzz_bridge
cmake --build build && ctest --test-dir build -R inject_read --output-on-failure
```
Expected: PASS — prints `sctp_client smoke ok`, test `inject_read` passes (it will be replaced with the real framing test in Task 5).

- [ ] **Step 6: Commit**

```bash
cd /home/osa240000/oranalyst
git add flexric/flexric_fuzz_bridge/include/sctp_client.h \
        flexric/flexric_fuzz_bridge/src/sctp_client.c \
        flexric/flexric_fuzz_bridge/src/crasher.c \
        flexric/flexric_fuzz_bridge/src/fuzz_ports.c \
        flexric/flexric_fuzz_bridge/test/test_inject_read.c \
        flexric/flexric_fuzz_bridge/CMakeLists.txt
git commit -m "feat(bridge): SCTP client with reader thread and crash detection"
```

---

## Task 3: Crasher persistence

**Files:**
- Modify: `flexric/flexric_fuzz_bridge/src/crasher.c`
- Create: `flexric/flexric_fuzz_bridge/include/crasher.h`
- Test: `flexric/flexric_fuzz_bridge/test/test_crasher.c`

**Interfaces:**
- Produces: `int crasher_save(const char* dir, const uint8_t* buf, size_t len, char* out_path, size_t out_path_sz);` → writes `dir/crash-<seq>.bin` (creating `dir`), returns 0 ok / -1 fail, fills `out_path`. Sequence is a static counter so repeated calls don't overwrite.
- Consumes: `bridge.h`.

- [ ] **Step 1: Write `include/crasher.h`**

```c
#ifndef BRIDGE_CRASHER_H
#define BRIDGE_CRASHER_H
#include <stddef.h>
#include <stdint.h>
int crasher_save(const char* dir, const uint8_t* buf, size_t len,
                 char* out_path, size_t out_path_sz);
#endif
```

- [ ] **Step 2: Write the failing test `test/test_crasher.c`**

```c
#include "crasher.h"
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main(void)
{
  const char* dir = "/tmp/bridge_test_crashers";
  char cmd[256]; snprintf(cmd, sizeof(cmd), "rm -rf %s", dir); int sr = system(cmd); (void)sr;

  uint8_t data[] = {0xde, 0xad, 0xbe, 0xef};
  char path[512] = {0};
  int rc = crasher_save(dir, data, sizeof(data), path, sizeof(path));
  assert(rc == 0);
  assert(strlen(path) > 0);

  FILE* f = fopen(path, "rb");
  assert(f != NULL);
  uint8_t rd[8]; size_t n = fread(rd, 1, sizeof(rd), f); fclose(f);
  assert(n == sizeof(data));
  assert(memcmp(rd, data, sizeof(data)) == 0);

  /* second call must not overwrite the first */
  char path2[512] = {0};
  rc = crasher_save(dir, data, sizeof(data), path2, sizeof(path2));
  assert(rc == 0);
  assert(strcmp(path, path2) != 0);

  printf("crasher ok: %s , %s\n", path, path2);
  return 0;
}
```

- [ ] **Step 3: Run the test to verify it fails**

Run:
```bash
cd /home/osa240000/oranalyst/flexric/flexric_fuzz_bridge
cmake --build build && ctest --test-dir build -R crasher --output-on-failure
```
Expected: FAIL — link error `undefined reference to 'crasher_save'` (crasher.c is still the empty stub).

- [ ] **Step 4: Write `src/crasher.c`**

```c
#include "crasher.h"
#include <stdio.h>
#include <sys/stat.h>
#include <sys/types.h>

int crasher_save(const char* dir, const uint8_t* buf, size_t len,
                 char* out_path, size_t out_path_sz)
{
  static unsigned seq = 0;
  if (mkdir(dir, 0755) != 0) {
    /* EEXIST is fine; any other failure is fatal for this call */
    struct stat st;
    if (stat(dir, &st) != 0) { perror("mkdir crashers"); return -1; }
  }
  unsigned id = seq++;
  if (out_path_sz) {
    snprintf(out_path, out_path_sz, "%s/crash-%06u.bin", dir, id);
  }
  char path[1024];
  snprintf(path, sizeof(path), "%s/crash-%06u.bin", dir, id);
  FILE* f = fopen(path, "wb");
  if (!f) { perror("fopen crasher"); return -1; }
  size_t w = fwrite(buf, 1, len, f);
  fclose(f);
  if (w != len) { fprintf(stderr, "short write crasher\n"); return -1; }
  return 0;
}
```

- [ ] **Step 5: Run the test to verify it passes**

Run:
```bash
cd /home/osa240000/oranalyst/flexric/flexric_fuzz_bridge
cmake --build build && ctest --test-dir build -R crasher --output-on-failure
```
Expected: PASS — `crasher ok: /tmp/bridge_test_crashers/crash-000000.bin , .../crash-000001.bin`.

- [ ] **Step 6: Commit**

```bash
cd /home/osa240000/oranalyst
git add flexric/flexric_fuzz_bridge/include/crasher.h \
        flexric/flexric_fuzz_bridge/src/crasher.c \
        flexric/flexric_fuzz_bridge/test/test_crasher.c
git commit -m "feat(bridge): persist crasher inputs to disk"
```

---

## Task 4: Capture a real E2 Setup Request blob

**Files:**
- Create: `flexric/flexric_fuzz_bridge/setup_req.bin` (binary artifact)
- Create (temporary, reverted): a one-line dump in `flexric/src/agent/endpoint_agent.c`

This task is mechanical, not TDD — its deliverable is a captured binary verified by a successful handshake.

- [ ] **Step 1: Add a temporary dump of the first outbound agent PDU**

In `flexric/src/agent/endpoint_agent.c`, inside `e2ap_send_bytes_agent` (after the `assert`s), add:

```c
  {
    static int dumped = 0;
    if (!dumped) {
      dumped = 1;
      FILE* df = fopen("/tmp/e2_setup_req.bin", "wb");
      if (df) { fwrite(ba.buf, 1, ba.len, df); fclose(df); }
      fprintf(stderr, "[dump] wrote first agent PDU (%zu bytes) to /tmp/e2_setup_req.bin\n", ba.len);
    }
  }
```

- [ ] **Step 2: Rebuild FlexRIC and run RIC + emu agent once to capture the setup**

Run (three terminals or backgrounded):
```bash
cd /home/osa240000/oranalyst/flexric
cmake --build build -j                      # rebuild with the dump
# Terminal A: start the RIC
./build/examples/ric/nearRT-RIC -c flexric.conf &
sleep 2
# Terminal B: start the gNB emulator agent (its first PDU is the E2 Setup Request)
./build/examples/emulator/agent/emu_agent_gnb -c flexric.conf &
sleep 3
ls -l /tmp/e2_setup_req.bin       # confirm the dump exists and len > 0
```
Expected: stderr shows `[dump] wrote first agent PDU (... bytes)`, and `/tmp/e2_setup_req.bin` is non-empty. The RIC log shows the agent connecting / E2 Setup.

- [ ] **Step 3: Save the blob into the bridge and stop the processes**

Run:
```bash
cp /tmp/e2_setup_req.bin /home/osa240000/oranalyst/flexric/flexric_fuzz_bridge/setup_req.bin
pkill -f emu_agent_gnb ; pkill -f nearRT-RIC
ls -l /home/osa240000/oranalyst/flexric/flexric_fuzz_bridge/setup_req.bin
```
Expected: `setup_req.bin` present and non-empty.

- [ ] **Step 4: Revert the temporary dump and rebuild clean**

Remove the dump block added in Step 1, then:
```bash
cd /home/osa240000/oranalyst/flexric
git -C . diff --stat src/agent/endpoint_agent.c   # expect: no changes after revert
cmake --build build -j
```
Expected: `endpoint_agent.c` shows no diff; FlexRIC rebuilds clean.

- [ ] **Step 5: Commit the captured blob**

```bash
cd /home/osa240000/oranalyst
git add flexric/flexric_fuzz_bridge/setup_req.bin
git commit -m "feat(bridge): capture real E2 Setup Request for handshake replay"
```

---

## Task 5: Inject + feedback TCP servers

**Files:**
- Modify: `flexric/flexric_fuzz_bridge/src/fuzz_ports.c`
- Create: `flexric/flexric_fuzz_bridge/include/fuzz_ports.h`
- Test: replace `flexric/flexric_fuzz_bridge/test/test_inject_read.c` (real framing test) and `flexric/flexric_fuzz_bridge/test/test_feedback.c`

**Interfaces:**
- Produces:
  - `int tcp_listen(int port);` → listening socket bound to `127.0.0.1:port` with `SO_REUSEADDR`, backlog 1; -1 on error.
  - `ssize_t read_until_eof(int fd, uint8_t* buf, size_t cap);` → reads bytes until peer closes; returns total (≤cap) or -1.
  - `int send_feedback_frame(int fd);` → writes exactly `FEEDBACK_TOTAL` bytes: first byte `1`, rest zero. Returns 0 ok / -1 on write error (peer gone).
  - `const uint8_t* feedback_frame_buffer(size_t* len_out);` → returns a static, lazily-built `FEEDBACK_TOTAL`-byte buffer (byte0=1, rest 0) for testing/reuse.
- Consumes: `bridge.h`.

- [ ] **Step 1: Write `include/fuzz_ports.h`**

```c
#ifndef BRIDGE_FUZZ_PORTS_H
#define BRIDGE_FUZZ_PORTS_H
#include <stddef.h>
#include <stdint.h>
#include <sys/types.h>
int     tcp_listen(int port);
ssize_t read_until_eof(int fd, uint8_t* buf, size_t cap);
int     send_feedback_frame(int fd);
const uint8_t* feedback_frame_buffer(size_t* len_out);
#endif
```

- [ ] **Step 2: Write the failing test `test/test_feedback.c`**

```c
#include "fuzz_ports.h"
#include "bridge.h"
#include <assert.h>
#include <stdio.h>

int main(void)
{
  size_t len = 0;
  const uint8_t* b = feedback_frame_buffer(&len);
  assert(len == FEEDBACK_TOTAL);          /* 3145753 */
  assert(b[0] == 1);                       /* end-signal byte */
  /* coverage + vals region must be all zero */
  for (size_t i = 1; i < len; i++) assert(b[i] == 0);
  printf("feedback frame ok: %zu bytes\n", len);
  return 0;
}
```

- [ ] **Step 3: Write the failing test `test/test_inject_read.c` (replace the smoke test)**

```c
#include "fuzz_ports.h"
#include <assert.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

int main(void)
{
  int fds[2];
  assert(pipe(fds) == 0);
  const char* msg = "ABCDEF";
  assert(write(fds[1], msg, 6) == 6);
  close(fds[1]);                  /* EOF, like main.go closing the conn */

  uint8_t buf[64] = {0};
  ssize_t n = read_until_eof(fds[0], buf, sizeof(buf));
  close(fds[0]);
  assert(n == 6);
  assert(memcmp(buf, msg, 6) == 0);
  printf("read_until_eof ok: %zd bytes\n", n);
  return 0;
}
```

- [ ] **Step 4: Run both tests to verify they fail**

Run:
```bash
cd /home/osa240000/oranalyst/flexric/flexric_fuzz_bridge
cmake --build build && ctest --test-dir build -R "feedback|inject_read" --output-on-failure
```
Expected: FAIL — `undefined reference to 'feedback_frame_buffer' / 'read_until_eof'`.

- [ ] **Step 5: Write `src/fuzz_ports.c`**

```c
#include "fuzz_ports.h"
#include "bridge.h"

#include <arpa/inet.h>
#include <netinet/in.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <errno.h>

int tcp_listen(int port)
{
  int fd = socket(AF_INET, SOCK_STREAM, 0);
  if (fd < 0) { perror("socket"); return -1; }
  int one = 1;
  setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
  struct sockaddr_in a = {0};
  a.sin_family = AF_INET;
  a.sin_port   = htons((uint16_t)port);
  a.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
  if (bind(fd, (struct sockaddr*)&a, sizeof(a)) != 0) { perror("bind"); close(fd); return -1; }
  if (listen(fd, 1) != 0) { perror("listen"); close(fd); return -1; }
  return fd;
}

ssize_t read_until_eof(int fd, uint8_t* buf, size_t cap)
{
  size_t total = 0;
  while (total < cap) {
    ssize_t n = read(fd, buf + total, cap - total);
    if (n < 0) { if (errno == EINTR) continue; return -1; }
    if (n == 0) break;          /* EOF: peer closed */
    total += (size_t)n;
  }
  return (ssize_t)total;
}

const uint8_t* feedback_frame_buffer(size_t* len_out)
{
  static uint8_t* frame = NULL;
  if (frame == NULL) {
    frame = (uint8_t*)calloc(FEEDBACK_TOTAL, 1);
    if (frame) frame[0] = 1;    /* end-signal byte; coverage+vals stay zero */
  }
  if (len_out) *len_out = FEEDBACK_TOTAL;
  return frame;
}

int send_feedback_frame(int fd)
{
  size_t len = 0;
  const uint8_t* b = feedback_frame_buffer(&len);
  if (!b) return -1;
  size_t sent = 0;
  while (sent < len) {
    ssize_t n = write(fd, b + sent, len - sent);
    if (n < 0) { if (errno == EINTR) continue; return -1; }
    sent += (size_t)n;
  }
  return 0;
}
```

- [ ] **Step 6: Run both tests to verify they pass**

Run:
```bash
cd /home/osa240000/oranalyst/flexric/flexric_fuzz_bridge
cmake --build build && ctest --test-dir build --output-on-failure
```
Expected: PASS — all three tests (`feedback`, `crasher`, `inject_read`) green.

- [ ] **Step 7: Commit**

```bash
cd /home/osa240000/oranalyst
git add flexric/flexric_fuzz_bridge/include/fuzz_ports.h \
        flexric/flexric_fuzz_bridge/src/fuzz_ports.c \
        flexric/flexric_fuzz_bridge/test/test_feedback.c \
        flexric/flexric_fuzz_bridge/test/test_inject_read.c \
        flexric/flexric_fuzz_bridge/CMakeLists.txt
git commit -m "feat(bridge): TCP inject + feedback servers with exact go-fuzz framing"
```

---

## Task 6: Bridge orchestration (main.c — wire it all together)

**Files:**
- Modify: `flexric/flexric_fuzz_bridge/src/main.c`

**Interfaces:**
- Consumes: `sctp_client.h`, `fuzz_ports.h`, `crasher.h`, `bridge.h`.
- Produces: the runnable `flexric_fuzz_bridge` binary with CLI flags `--ric-ip`, `--ric-port`, `--inject-port`, `--feedback-port`, `--setup`, `--crashers`, `--timeout-ms`.

Behavior (single-threaded main loop + SCTP reader thread):
1. Parse args. 2. SCTP connect to RIC. 3. Read `setup_req.bin`, send it, start reader, wait briefly, abort if `crashed` (handshake failed). 4. `tcp_listen` both ports. 5. Accept the persistent feedback connection (port 19999). 6. Loop: accept an inject connection (19960) → `read_until_eof` → `sctp_client_send` → if `crashed`, save crasher + exit 42; else `send_feedback_frame`; if feedback write fails, re-accept feedback conn (handles fuzzer worker restart).

- [ ] **Step 1: Replace `src/main.c`**

```c
#include "bridge.h"
#include "sctp_client.h"
#include "fuzz_ports.h"
#include "crasher.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <getopt.h>

static int read_file(const char* path, uint8_t* buf, size_t cap, size_t* out_len)
{
  FILE* f = fopen(path, "rb");
  if (!f) { perror("fopen setup_req"); return -1; }
  size_t n = fread(buf, 1, cap, f);
  fclose(f);
  if (n == 0) { fprintf(stderr, "empty setup file %s\n", path); return -1; }
  *out_len = n;
  return 0;
}

int main(int argc, char** argv)
{
  struct bridge_cfg cfg = {
    .ric_ip = DEFAULT_RIC_IP, .ric_port = DEFAULT_RIC_PORT,
    .inject_port = DEFAULT_INJECT_PORT, .feedback_port = DEFAULT_FEEDBACK_PORT,
    .setup_req_path = "setup_req.bin", .crashers_dir = "crashers",
    .input_timeout_ms = 5000,
  };
  static struct option opts[] = {
    {"ric-ip",        required_argument, 0, 'i'},
    {"ric-port",      required_argument, 0, 'p'},
    {"inject-port",   required_argument, 0, 'j'},
    {"feedback-port", required_argument, 0, 'f'},
    {"setup",         required_argument, 0, 's'},
    {"crashers",      required_argument, 0, 'c'},
    {"timeout-ms",    required_argument, 0, 't'},
    {0,0,0,0}
  };
  int o;
  while ((o = getopt_long(argc, argv, "i:p:j:f:s:c:t:", opts, NULL)) != -1) {
    switch (o) {
      case 'i': cfg.ric_ip = optarg; break;
      case 'p': cfg.ric_port = atoi(optarg); break;
      case 'j': cfg.inject_port = atoi(optarg); break;
      case 'f': cfg.feedback_port = atoi(optarg); break;
      case 's': cfg.setup_req_path = optarg; break;
      case 'c': cfg.crashers_dir = optarg; break;
      case 't': cfg.input_timeout_ms = atoi(optarg); break;
      default: fprintf(stderr, "usage: %s [--ric-ip IP] [--ric-port N] ...\n", argv[0]);
               return BRIDGE_EXIT_USAGE;
    }
  }

  /* 1. SCTP connect */
  sctp_client_t sc;
  if (sctp_client_open(&sc, cfg.ric_ip, cfg.ric_port) != 0) {
    fprintf(stderr, "SCTP open failed\n"); return BRIDGE_EXIT_USAGE;
  }

  /* 2. handshake: replay captured E2 Setup Request */
  static uint8_t setup[MAX_PDU_SIZE];
  size_t setup_len = 0;
  if (read_file(cfg.setup_req_path, setup, sizeof(setup), &setup_len) != 0) {
    sctp_client_close(&sc); return BRIDGE_EXIT_USAGE;
  }
  if (sctp_client_send(&sc, setup, setup_len) != 0) {
    fprintf(stderr, "failed to send E2 Setup Request\n");
    sctp_client_close(&sc); return BRIDGE_EXIT_CRASH;
  }
  sctp_client_start_reader(&sc);
  usleep(500 * 1000);   /* allow E2 Setup Response */
  if (sc.crashed) {
    fprintf(stderr, "association lost during handshake\n");
    sctp_client_close(&sc); return BRIDGE_EXIT_CRASH;
  }
  fprintf(stderr, "[bridge] E2 Setup sent (%zu bytes); association up\n", setup_len);

  /* 3. listen + accept persistent feedback conn */
  int inj_lfd = tcp_listen(cfg.inject_port);
  int fb_lfd  = tcp_listen(cfg.feedback_port);
  if (inj_lfd < 0 || fb_lfd < 0) { sctp_client_close(&sc); return BRIDGE_EXIT_USAGE; }
  fprintf(stderr, "[bridge] waiting for fuzzer feedback connection on %d...\n", cfg.feedback_port);
  int fb_fd = accept(fb_lfd, NULL, NULL);
  if (fb_fd < 0) { perror("accept feedback"); sctp_client_close(&sc); return BRIDGE_EXIT_USAGE; }
  fprintf(stderr, "[bridge] fuzzer connected; entering fuzz loop\n");

  /* 4. fuzz loop */
  static uint8_t input[MAX_PDU_SIZE];
  unsigned long count = 0;
  for (;;) {
    int in_fd = accept(inj_lfd, NULL, NULL);
    if (in_fd < 0) { if (errno == EINTR) continue; perror("accept inject"); break; }

    ssize_t n = read_until_eof(in_fd, input, sizeof(input));
    close(in_fd);
    if (n <= 0) { continue; }   /* empty input: nothing to inject */

    if (sctp_client_send(&sc, input, (size_t)n) != 0 || sc.crashed) {
      char path[512] = {0};
      crasher_save(cfg.crashers_dir, input, (size_t)n, path, sizeof(path));
      fprintf(stderr, "[bridge] CRASH after %lu inputs; saved %s\n", count, path);
      sctp_client_close(&sc);
      return BRIDGE_EXIT_CRASH;
    }
    /* give the RIC a moment to process, then re-check liveness */
    usleep(2000);
    if (sc.crashed) {
      char path[512] = {0};
      crasher_save(cfg.crashers_dir, input, (size_t)n, path, sizeof(path));
      fprintf(stderr, "[bridge] CRASH (post-send) after %lu inputs; saved %s\n", count, path);
      sctp_client_close(&sc);
      return BRIDGE_EXIT_CRASH;
    }

    if (send_feedback_frame(fb_fd) != 0) {
      /* fuzzer worker restarted: re-accept a fresh feedback conn */
      close(fb_fd);
      fb_fd = accept(fb_lfd, NULL, NULL);
      if (fb_fd < 0) { perror("re-accept feedback"); break; }
    }
    count++;
    if ((count % 500) == 0) fprintf(stderr, "[bridge] %lu inputs injected\n", count);
  }

  sctp_client_close(&sc);
  return BRIDGE_EXIT_OK;
}
```

Add `#include <errno.h>` at the top if not pulled in transitively (it is needed for `EINTR`).

- [ ] **Step 2: Build**

Run:
```bash
cd /home/osa240000/oranalyst/flexric/flexric_fuzz_bridge
cmake --build build 2>&1 | tail -5
```
Expected: builds clean, no warnings-as-errors.

- [ ] **Step 3: Smoke test the handshake against a live RIC**

Run:
```bash
cd /home/osa240000/oranalyst/flexric
./build/examples/ric/nearRT-RIC -c flexric.conf >/tmp/ric.log 2>&1 &
sleep 2
cd flexric_fuzz_bridge
./build/flexric_fuzz_bridge --setup setup_req.bin &
sleep 2
grep -i "E2 Setup\|association up\|RAN\|connected" /tmp/ric.log
grep "association up" <(jobs -l) 2>/dev/null || true
# bridge stderr should have printed "E2 Setup sent ...; association up"
pkill -f flexric_fuzz_bridge ; pkill -f nearRT-RIC
```
Expected: bridge prints `[bridge] E2 Setup sent (...); association up` and the RIC log shows the E2 Setup / a node connecting. **This proves success criterion #1 (E2 Setup succeeds).**

- [ ] **Step 4: Commit**

```bash
cd /home/osa240000/oranalyst
git add flexric/flexric_fuzz_bridge/src/main.c
git commit -m "feat(bridge): orchestration loop wiring handshake, inject, feedback, crash"
```

---

## Task 7: ORANalyst Go fuzzer bring-up (Go 1.20 + build config)

**Files:**
- Modify: `ORANalyst/O-RAN-SC/oran-input-gen/main.go` (cgo paths)
- Modify: `ORANalyst/O-RAN-SC/oran-input-gen/go-fuzz/go-fuzz/asn1_mutator/shared_mem.go` (mutator select)

This task is mechanical (toolchain + config); verification is "the fuzzer builds and runs against the bridge".

- [ ] **Step 1: Install Go 1.20**

Run:
```bash
cd /tmp
wget -q https://go.dev/dl/go1.20.14.linux-amd64.tar.gz
sudo rm -rf /usr/local/go && sudo tar -C /usr/local -xzf go1.20.14.linux-amd64.tar.gz
export PATH=$PATH:/usr/local/go/bin
go version
```
Expected: `go version go1.20.14 linux/amd64`. (Add `/usr/local/go/bin` to PATH in the supervisor script too.)

- [ ] **Step 2: Fix the cgo paths in `main.go`**

Replace the two `#cgo` lines at the top of `ORANalyst/O-RAN-SC/oran-input-gen/main.go`:
```go
// #cgo CFLAGS: -I/home/tianchang/Desktop/proj/oran-sc/oran-input-gen/kpm
// #cgo LDFLAGS: -L/home/tianchang/Desktop/proj/oran-sc/oran-input-gen/kpm/build -lkpm -lm
```
with the local absolute paths (confirm the `kpm` mutator dir + its `build` exist; the README says a prebuilt lib is in `oran-input-gen/kpm/build`):
```go
// #cgo CFLAGS: -I/home/osa240000/oranalyst/ORANalyst/O-RAN-SC/oran-input-gen/kpm
// #cgo LDFLAGS: -L/home/osa240000/oranalyst/ORANalyst/O-RAN-SC/oran-input-gen/kpm/build -lkpm -lm
```

- [ ] **Step 3: Select the e2ap mutator**

In `ORANalyst/O-RAN-SC/oran-input-gen/go-fuzz/go-fuzz/asn1_mutator/shared_mem.go`, change the mutator subprocess line from the kpm mutator to the e2ap mutator (per `O-RAN-SC/docs/test_e2t.md`):
```go
// from:
cmd := exec.Command("mutator/kpm/mutator", sharedFile.Name())
// to:
cmd := exec.Command("mutator/e2ap/mutator", sharedFile.Name())
```
(If the exact string differs, grep for `mutator/kpm/mutator` in that file and switch the `kpm` segment to `e2ap`.)

- [ ] **Step 4: Select the e2ap corpus**

Run:
```bash
cd /home/osa240000/oranalyst/ORANalyst/O-RAN-SC/oran-input-gen
[ -d corpus ] && rm -rf corpus
cp -r corpus_e2ap_final corpus
ls corpus | head
```
Expected: `corpus/` populated with e2ap seed inputs. (The repo ships `corpus_e2ap_final/`; `test_e2t.md` references `corpus_dir/e2ap` — use whichever exists, preferring `corpus_e2ap_final`.)

- [ ] **Step 5: Build the fuzzer**

Run:
```bash
cd /home/osa240000/oranalyst/ORANalyst/O-RAN-SC/oran-input-gen
export PATH=$PATH:/usr/local/go/bin
make fuzzer 2>&1 | tail -20
ls -l go-fuzz-bin fuzz.zip sonar.exe
```
Expected: `make fuzzer` completes; `go-fuzz-bin`, `fuzz.zip`, and `sonar.exe` exist. Fix any build error before proceeding (most likely: missing Go deps → `go mod download` in the relevant module dirs; or the `kpm/build` lib needs a rebuild via its CMake per the README).

- [ ] **Step 6: Commit the config changes**

```bash
cd /home/osa240000/oranalyst/ORANalyst
git add O-RAN-SC/oran-input-gen/main.go \
        O-RAN-SC/oran-input-gen/go-fuzz/go-fuzz/asn1_mutator/shared_mem.go
git commit -m "chore(fuzzer): local cgo paths + select e2ap mutator for FlexRIC fuzzing"
```
(Note: `corpus/` is build state — do not commit it; add to `.gitignore` if the repo doesn't already ignore it.)

---

## Task 8: Supervisor script (start, monitor, auto-restart, resume)

**Files:**
- Create: `run_flexric_fuzz.sh` (repo root)

**Interfaces:**
- Consumes: the bridge binary (`flexric/flexric_fuzz_bridge/build/flexric_fuzz_bridge`), the RIC binary, the fuzzer (`make run-fuzzer`).
- Produces: a supervised run that restarts RIC + bridge + fuzzer on crash (`BRIDGE_EXIT_CRASH=42`) and resumes from the go-fuzz corpus.

- [ ] **Step 1: Write `run_flexric_fuzz.sh`**

```bash
#!/usr/bin/env bash
# Supervisor: run FlexRIC RIC + fuzz bridge + ORANalyst fuzzer; restart on crash.
set -u

export PATH="$PATH:/usr/local/go/bin"

ROOT="/home/osa240000/oranalyst"
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
  sleep 2

  if [ "$BRC" -eq 42 ]; then
    echo "[supervisor] CRASH detected (round $ROUND). Crasher saved under $BRIDGE/crashers/. Restarting stack..."
    continue
  else
    echo "[supervisor] bridge exited normally (code $BRC); stopping."
    cleanup
  fi
done
```

- [ ] **Step 2: Make it executable and shellcheck-clean it**

Run:
```bash
chmod +x /home/osa240000/oranalyst/run_flexric_fuzz.sh
bash -n /home/osa240000/oranalyst/run_flexric_fuzz.sh && echo "syntax ok"
```
Expected: `syntax ok`.

- [ ] **Step 3: Commit**

```bash
cd /home/osa240000/oranalyst
git add run_flexric_fuzz.sh
git commit -m "feat: supervisor to run + auto-restart RIC/bridge/fuzzer stack"
```

---

## Task 9: End-to-end verification (the four success criteria) + README

**Files:**
- Create: `flexric/flexric_fuzz_bridge/README.md`

This task runs the real stack and records evidence for each success criterion. No claim is made without observed output.

- [ ] **Step 1: Criterion 1 — E2 Setup succeeds**

Run:
```bash
cd /home/osa240000/oranalyst/flexric
./build/examples/ric/nearRT-RIC -c flexric.conf >/tmp/ric.log 2>&1 &
sleep 2
( cd flexric_fuzz_bridge && ./build/flexric_fuzz_bridge --setup setup_req.bin >/tmp/bridge.log 2>&1 & )
sleep 2
grep "association up" /tmp/bridge.log
grep -iE "E2 Setup|connected|RAN" /tmp/ric.log | head
pkill -f flexric_fuzz_bridge ; pkill -f nearRT-RIC
```
Expected: `[bridge] E2 Setup sent ...; association up` in bridge log AND an E2-Setup/connection line in the RIC log.

- [ ] **Step 2: Criterion 2 — sustained fuzz loop**

Run:
```bash
cd /home/osa240000/oranalyst
timeout 600 ./run_flexric_fuzz.sh >/tmp/supervisor.log 2>&1 &
SUP=$!
sleep 120
tail -n 20 fuzz-logs/bridge-*.log     # expect "[bridge] N inputs injected" increasing
tail -n 20 fuzz-logs/fuzzer-*.log     # expect go-fuzz stats advancing (execs, corpus)
```
Expected: the bridge log shows injected-input counts climbing (e.g. `500 inputs injected`, `1000 ...`) and the fuzzer log shows go-fuzz making progress, with no deadlock/stall over ≥2 minutes. Let it run toward the 10-minute mark to satisfy the bar, then stop with `kill $SUP; pkill -f run_flexric_fuzz`.

- [ ] **Step 3: Criterion 3 — crash detection**

Run (fault injection: kill the RIC mid-run and confirm the bridge catches it):
```bash
cd /home/osa240000/oranalyst/flexric
./build/examples/ric/nearRT-RIC -c flexric.conf >/tmp/ric.log 2>&1 &
sleep 2
( cd flexric_fuzz_bridge && ./build/flexric_fuzz_bridge --setup setup_req.bin >/tmp/bridge.log 2>&1 ; echo "BRIDGE_EXIT=$?" >>/tmp/bridge.log & )
sleep 2
# simulate a fuzzer driving one input, then kill the RIC to force assoc loss
python3 - <<'PY'
import socket,time
s=socket.create_connection(("127.0.0.1",19999))   # feedback (persistent)
def one(payload):
    c=socket.create_connection(("127.0.0.1",19960)); c.sendall(payload); c.close()
one(b"\x00\x01\x02")        # benign inject
time.sleep(0.2)
PY
pkill -9 -f nearRT-RIC      # kill target -> association lost
# drive one more input so the bridge's send/liveness check fires
python3 -c "import socket; c=socket.create_connection(('127.0.0.1',19960)); c.sendall(b'\\x03\\x04'); c.close()" || true
sleep 1
grep -E "CRASH|BRIDGE_EXIT" /tmp/bridge.log
ls flexric_fuzz_bridge/crashers/
```
Expected: bridge log shows `[bridge] CRASH ...; saved .../crash-000000.bin` and `BRIDGE_EXIT=42`; a crasher file exists. (This validates SCTP-loss → crash classification + input persistence.)

- [ ] **Step 4: Criterion 4 — auto-restart & resume**

Run:
```bash
cd /home/osa240000/oranalyst
./run_flexric_fuzz.sh >/tmp/supervisor.log 2>&1 &
SUP=$!
sleep 20
pkill -9 -f nearRT-RIC      # force a crash mid-run
sleep 8
grep -E "CRASH detected|=== round" /tmp/supervisor.log
# expect: "round 1", then "CRASH detected (round 1)", then "round 2"
ls fuzz-logs/                # expect bridge-2.log / ric-2.log from the restart
kill $SUP 2>/dev/null; pkill -f run_flexric_fuzz; pkill -f nearRT-RIC; pkill -f flexric_fuzz_bridge
```
Expected: supervisor log shows round 1 → CRASH detected → round 2 starting, and a second set of logs exists. go-fuzz in round 2 resumes from the persisted corpus (its workdir/corpus survives across rounds).

- [ ] **Step 5: Write `README.md`**

```markdown
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

## Ports
- 19960  inject   (fuzzer -> bridge, one TCP conn per input, read until EOF)
- 19999  feedback (bridge -> fuzzer, FEEDBACK_TOTAL=3145753 bytes/input, zero coverage)
- 36421  SCTP E2AP (bridge -> RIC)

## Limitations
- Black-box: coverage is stubbed (zeros). Coverage-guided fuzzing of FlexRIC
  (compiler instrumentation + real feedback) is future work; the feedback path
  is isolated in fuzz_ports.c so it can be swapped later.
- setup_req.bin is a captured real E2 Setup Request; re-capture it (see plan
  Task 4) if the FlexRIC E2AP version / service models change.

## Regenerating setup_req.bin
See the implementation plan Task 4: temporarily dump the first PDU sent by
`emu_agent_gnb`, run it once against the RIC, copy `/tmp/e2_setup_req.bin` here.
```

- [ ] **Step 6: Commit**

```bash
cd /home/osa240000/oranalyst
git add flexric/flexric_fuzz_bridge/README.md
git commit -m "docs(bridge): README with build, run, ports, limitations"
```

---

## Self-Review (completed during planning)

**Spec coverage:**
- Black-box mode → Tasks 5/6 (zero feedback). ✓
- Standalone SCTP client + captured E2 Setup → Tasks 2/4/6. ✓
- ORANalyst Go fuzzer unmodified-logic, Go 1.20, e2ap mutator/corpus → Task 7. ✓
- Inject (19960) + feedback (19999) byte-exact protocol → Tasks 1 (constants) / 5 / 6. ✓
- Crash detection → Tasks 2 (SCTP reader) / 3 (persist) / 6 (classify+exit 42). ✓
- Auto-restart & resume → Task 8 supervisor; verified Task 9 Step 4. ✓
- Four success criteria → Task 9 Steps 1–4, each with observed-evidence verification. ✓
- Environment blockers (Go absent, Ubuntu 26.04, cgo paths) → Task 7. ✓

**Placeholder scan:** No TBD/TODO; every code step shows complete code; every command has expected output.

**Type consistency:** `sctp_client_t`, `bridge_cfg`, `crasher_save`, `feedback_frame_buffer`, `read_until_eof`, `send_feedback_frame`, `tcp_listen` used consistently across `bridge.h`, the `.c` files, `main.c`, and tests. `FEEDBACK_TOTAL = 3145753` is consistent in `bridge.h` and `test_feedback.c`. Exit code `42` consistent in `bridge.h`, `main.c`, and the supervisor.

**Known risk flagged for the executor:** Task 7 Step 5 (`make fuzzer`) is the highest-uncertainty step — building ORANalyst's Go+cgo+go-fuzz toolchain on Ubuntu 26.04 with Go 1.20. If it fails, treat it as a debugging sub-task (systematic-debugging skill): the likely culprits are the `kpm/build` mutator lib needing a CMake rebuild, or Go module fetch issues; resolve before Task 8/9.
```

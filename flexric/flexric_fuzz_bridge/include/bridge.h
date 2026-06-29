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

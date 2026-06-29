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

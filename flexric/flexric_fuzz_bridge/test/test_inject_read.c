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

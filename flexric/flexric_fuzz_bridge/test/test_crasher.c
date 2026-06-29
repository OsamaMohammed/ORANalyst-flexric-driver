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

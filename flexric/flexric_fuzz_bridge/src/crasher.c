#include "crasher.h"
#include <stdio.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

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
    snprintf(out_path, out_path_sz, "%s/crash-%d-%06u.bin", dir, (int)getpid(), id);
  }
  char path[1024];
  snprintf(path, sizeof(path), "%s/crash-%d-%06u.bin", dir, (int)getpid(), id);
  FILE* f = fopen(path, "wb");
  if (!f) { perror("fopen crasher"); return -1; }
  size_t w = fwrite(buf, 1, len, f);
  fclose(f);
  if (w != len) { fprintf(stderr, "short write crasher\n"); return -1; }
  return 0;
}

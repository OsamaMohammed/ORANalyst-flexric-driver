#ifndef BRIDGE_CRASHER_H
#define BRIDGE_CRASHER_H
#include <stddef.h>
#include <stdint.h>
int crasher_save(const char* dir, const uint8_t* buf, size_t len,
                 char* out_path, size_t out_path_sz);
#endif

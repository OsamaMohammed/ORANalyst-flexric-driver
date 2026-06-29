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

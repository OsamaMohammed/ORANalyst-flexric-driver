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

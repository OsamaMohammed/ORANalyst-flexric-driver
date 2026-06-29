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

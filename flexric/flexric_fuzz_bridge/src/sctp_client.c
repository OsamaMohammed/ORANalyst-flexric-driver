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

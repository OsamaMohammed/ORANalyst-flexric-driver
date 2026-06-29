#include "bridge.h"
#include "sctp_client.h"
#include "fuzz_ports.h"
#include "crasher.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <getopt.h>
#include <errno.h>

static int read_file(const char* path, uint8_t* buf, size_t cap, size_t* out_len)
{
  FILE* f = fopen(path, "rb");
  if (!f) { perror("fopen setup_req"); return -1; }
  size_t n = fread(buf, 1, cap, f);
  fclose(f);
  if (n == 0) { fprintf(stderr, "empty setup file %s\n", path); return -1; }
  *out_len = n;
  return 0;
}

int main(int argc, char** argv)
{
  struct bridge_cfg cfg = {
    .ric_ip = DEFAULT_RIC_IP, .ric_port = DEFAULT_RIC_PORT,
    .inject_port = DEFAULT_INJECT_PORT, .feedback_port = DEFAULT_FEEDBACK_PORT,
    .setup_req_path = "setup_req.bin", .crashers_dir = "crashers",
    .input_timeout_ms = 5000,
  };
  static struct option opts[] = {
    {"ric-ip",        required_argument, 0, 'i'},
    {"ric-port",      required_argument, 0, 'p'},
    {"inject-port",   required_argument, 0, 'j'},
    {"feedback-port", required_argument, 0, 'f'},
    {"setup",         required_argument, 0, 's'},
    {"crashers",      required_argument, 0, 'c'},
    {"timeout-ms",    required_argument, 0, 't'},
    {0,0,0,0}
  };
  int o;
  while ((o = getopt_long(argc, argv, "i:p:j:f:s:c:t:", opts, NULL)) != -1) {
    switch (o) {
      case 'i': cfg.ric_ip = optarg; break;
      case 'p': cfg.ric_port = atoi(optarg); break;
      case 'j': cfg.inject_port = atoi(optarg); break;
      case 'f': cfg.feedback_port = atoi(optarg); break;
      case 's': cfg.setup_req_path = optarg; break;
      case 'c': cfg.crashers_dir = optarg; break;
      case 't': cfg.input_timeout_ms = atoi(optarg); break;
      default: fprintf(stderr, "usage: %s [--ric-ip IP] [--ric-port N] ...\n", argv[0]);
               return BRIDGE_EXIT_USAGE;
    }
  }

  /* 1. SCTP connect */
  sctp_client_t sc;
  if (sctp_client_open(&sc, cfg.ric_ip, cfg.ric_port) != 0) {
    fprintf(stderr, "SCTP open failed\n"); return BRIDGE_EXIT_USAGE;
  }

  /* 2. handshake: replay captured E2 Setup Request */
  static uint8_t setup[MAX_PDU_SIZE];
  size_t setup_len = 0;
  if (read_file(cfg.setup_req_path, setup, sizeof(setup), &setup_len) != 0) {
    sctp_client_close(&sc); return BRIDGE_EXIT_USAGE;
  }
  if (sctp_client_send(&sc, setup, setup_len) != 0) {
    fprintf(stderr, "failed to send E2 Setup Request\n");
    sctp_client_close(&sc); return BRIDGE_EXIT_CRASH;
  }
  sctp_client_start_reader(&sc);
  usleep(500 * 1000);   /* allow E2 Setup Response */
  if (sc.crashed) {
    fprintf(stderr, "association lost during handshake\n");
    sctp_client_close(&sc); return BRIDGE_EXIT_CRASH;
  }
  fprintf(stderr, "[bridge] E2 Setup sent (%zu bytes); association up\n", setup_len);

  /* 3. listen + accept persistent feedback conn */
  int inj_lfd = tcp_listen(cfg.inject_port);
  int fb_lfd  = tcp_listen(cfg.feedback_port);
  if (inj_lfd < 0 || fb_lfd < 0) { sctp_client_close(&sc); return BRIDGE_EXIT_USAGE; }
  fprintf(stderr, "[bridge] waiting for fuzzer feedback connection on %d...\n", cfg.feedback_port);
  int fb_fd;
  do { fb_fd = accept(fb_lfd, NULL, NULL); } while (fb_fd < 0 && errno == EINTR);
  if (fb_fd < 0) { perror("accept feedback"); sctp_client_close(&sc); return BRIDGE_EXIT_USAGE; }
  fprintf(stderr, "[bridge] fuzzer connected; entering fuzz loop\n");

  /* 4. fuzz loop */
  static uint8_t input[MAX_PDU_SIZE];
  unsigned long count = 0;
  for (;;) {
    int in_fd = accept(inj_lfd, NULL, NULL);
    if (in_fd < 0) { if (errno == EINTR) continue; perror("accept inject"); break; }

    ssize_t n = read_until_eof(in_fd, input, sizeof(input));
    close(in_fd);
    if (n <= 0) { continue; }   /* empty input: nothing to inject */

    if (sctp_client_send(&sc, input, (size_t)n) != 0 || sc.crashed) {
      char path[512] = {0};
      crasher_save(cfg.crashers_dir, input, (size_t)n, path, sizeof(path));
      fprintf(stderr, "[bridge] CRASH after %lu inputs; saved %s\n", count, path);
      sctp_client_close(&sc);
      return BRIDGE_EXIT_CRASH;
    }
    /* give the RIC a moment to process, then re-check liveness */
    usleep(2000);
    if (sc.crashed) {
      char path[512] = {0};
      crasher_save(cfg.crashers_dir, input, (size_t)n, path, sizeof(path));
      fprintf(stderr, "[bridge] CRASH (post-send) after %lu inputs; saved %s\n", count, path);
      sctp_client_close(&sc);
      return BRIDGE_EXIT_CRASH;
    }

    if (send_feedback_frame(fb_fd) != 0) {
      /* Feedback write failed => the go-fuzz worker died/restarted. The in-flight
         input is intentionally abandoned (not re-sent); we re-accept the new worker's
         persistent feedback connection and continue. */
      close(fb_fd);
      do { fb_fd = accept(fb_lfd, NULL, NULL); } while (fb_fd < 0 && errno == EINTR);
      if (fb_fd < 0) { perror("re-accept feedback"); break; }
      fprintf(stderr, "[bridge] feedback peer reconnected (worker restart) after %lu inputs\n", count);
    }
    count++;
    if ((count % 500) == 0) fprintf(stderr, "[bridge] %lu inputs injected\n", count);
  }

  sctp_client_close(&sc);
  return BRIDGE_EXIT_OK;
}

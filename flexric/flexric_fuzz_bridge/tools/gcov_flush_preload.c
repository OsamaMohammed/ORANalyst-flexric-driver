/* gcov_flush_preload.c — LD_PRELOAD shim to flush gcov coverage on demand and
 * on crash, so coverage survives FlexRIC's SIGABRT/SIGSEGV deaths.
 *
 * Build: gcc -shared -fPIC -O2 -o libgcovflush.so gcov_flush_preload.c -lgcov
 * Use:   LD_PRELOAD=/abs/path/libgcovflush.so <coverage-instrumented program>
 *
 * The shim is linked with -lgcov so it exports __gcov_dump / __gcov_reset.
 * LD_PRELOAD places those exports ahead of the target's statically-linked
 * gcov runtime; because LD_PRELOAD symbols win, the target's __gcov_init
 * registers its coverage data with the shim's (identical) gcov runtime.
 * Signal handlers can therefore call __gcov_dump and flush the target's data.
 */
#define _GNU_SOURCE
#include <signal.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <execinfo.h>

/* Provided by -lgcov (linked into this shim). LD_PRELOAD makes these the
 * canonical copies; the target's __gcov_init registers with us. */
extern void __gcov_dump(void);
extern void __gcov_reset(void);

static void write_str(int fd, const char* s) { (void)!write(fd, s, strlen(s)); }

/* Live snapshot: dump accumulated counters, then reset so the next dump only
 * adds the delta (prevents double-counting into the on-disk .gcda). */
static void on_usr1(int sig)
{
  (void)sig;
  __gcov_dump();
  __gcov_reset();
}

/* Fatal signal: print a backtrace (for crash signatures), dump coverage, then
 * re-raise with the default handler so the process dies and the supervisor
 * observes the crash. */
static void on_fatal(int sig)
{
  void* bt[64];
  int n = backtrace(bt, 64);
  write_str(STDERR_FILENO, "\n=== FATAL signal ");
  switch (sig) {
    case SIGABRT: write_str(STDERR_FILENO, "SIGABRT"); break;
    case SIGSEGV: write_str(STDERR_FILENO, "SIGSEGV"); break;
    case SIGFPE:  write_str(STDERR_FILENO, "SIGFPE");  break;
    case SIGILL:  write_str(STDERR_FILENO, "SIGILL");  break;
    case SIGBUS:  write_str(STDERR_FILENO, "SIGBUS");  break;
    default:      write_str(STDERR_FILENO, "SIGNAL");  break;
  }
  write_str(STDERR_FILENO, " backtrace ===\n");
  backtrace_symbols_fd(bt, n, STDERR_FILENO);
  write_str(STDERR_FILENO, "=== end backtrace ===\n");

  __gcov_dump();

  signal(sig, SIG_DFL);
  raise(sig);
}

/* SIGTERM (supervisor stop at deadline): dump then terminate. */
static void on_term(int sig)
{
  __gcov_dump();
  signal(sig, SIG_DFL);
  raise(sig);
}

__attribute__((constructor))
static void install_handlers(void)
{
  struct sigaction sa;
  memset(&sa, 0, sizeof(sa));
  sigemptyset(&sa.sa_mask);

  sa.sa_handler = on_usr1;  sigaction(SIGUSR1, &sa, NULL);

  sa.sa_handler = on_fatal;
  sigaction(SIGABRT, &sa, NULL);
  sigaction(SIGSEGV, &sa, NULL);
  sigaction(SIGFPE,  &sa, NULL);
  sigaction(SIGILL,  &sa, NULL);
  sigaction(SIGBUS,  &sa, NULL);

  sa.sa_handler = on_term;  sigaction(SIGTERM, &sa, NULL);
}

#!/usr/bin/env python3
"""Sample cumulative FlexRIC src/ coverage every interval and append to a CSV.

Flushes the live RIC via SIGUSR1 (the gcov_flush shim) before each gcovr run,
so the snapshot reflects current coverage. Coverage is cumulative across RIC
restarts because every round reuses the same build-cov binaries.
"""
import argparse, json, os, subprocess, sys, time

HEADER = "elapsed_min,covered_edges,covered_lines"

def parse_gcovr_summary(json_text):
    try:
        d = json.loads(json_text)
    except Exception:
        return (0, 0)
    edges = int(d.get("branch_covered", 0) or 0)   # branches -> edges
    lines = int(d.get("line_covered", 0) or 0)
    return (edges, lines)

def append_row(csv_path, elapsed_min, edges, lines):
    new = not os.path.exists(csv_path) or os.path.getsize(csv_path) == 0
    with open(csv_path, "a") as f:
        if new:
            f.write(HEADER + "\n")
        f.write(f"{elapsed_min},{edges},{lines}\n")
        f.flush()

def run_gcovr(flexric_root, build_cov):
    # Resolve gcovr: prefer $HOME/.local/bin, then PATH
    gcovr_bin = os.path.join(os.path.expanduser("~"), ".local", "bin", "gcovr")
    if not os.path.isfile(gcovr_bin):
        import shutil
        gcovr_bin = shutil.which("gcovr") or "gcovr"
    # --json-summary - writes the summary JSON to stdout; build_cov is search path
    cmd = [gcovr_bin, "-r", flexric_root,
           "--filter", os.path.join(flexric_root, "src") + os.sep,
           "--gcov-executable", "gcov",
           "--gcov-ignore-parse-errors", "--json-summary", "-",
           build_cov]
    try:
        out = subprocess.run(cmd, capture_output=True, text=True,
                             timeout=600)
        if out.returncode != 0 or not out.stdout.strip():
            sys.stderr.write(f"[sampler] gcovr rc={out.returncode} stderr={out.stderr.strip()[:300]}\n")
            sys.stderr.flush()
        return out.stdout
    except Exception as e:
        sys.stderr.write(f"[sampler] gcovr failed: {e}\n")
        return "{}"

def flush_live_ric(ric_pid_file):
    try:
        pid = int(open(ric_pid_file).read().strip())
        os.kill(pid, 10)  # SIGUSR1
        time.sleep(0.5)
    except Exception:
        pass  # RIC mid-restart; sample on-disk gcda anyway

def sample_once(flexric_root, build_cov, ric_pid_file, csv_path, t0, last):
    flush_live_ric(ric_pid_file)
    edges, lines = parse_gcovr_summary(run_gcovr(flexric_root, build_cov))
    if (edges, lines) == (0, 0) and last is not None:
        edges, lines = last           # transient gcovr error -> repeat last
    elapsed_min = round((time.time() - t0) / 60)
    append_row(csv_path, elapsed_min, edges, lines)
    return (edges, lines)

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--flexric-root", required=True)
    ap.add_argument("--build-cov", required=True)
    ap.add_argument("--ric-pid-file", required=True)
    ap.add_argument("--out", required=True)
    ap.add_argument("--t0", type=float, required=True)
    ap.add_argument("--interval", type=int, default=1800)
    ap.add_argument("--deadline", type=float, required=True)
    a = ap.parse_args()

    last = sample_once(a.flexric_root, a.build_cov, a.ric_pid_file, a.out, a.t0, None)  # row 0
    while time.time() < a.deadline:
        # sleep to next interval boundary but wake by deadline
        nap = min(a.interval, max(1, a.deadline - time.time()))
        time.sleep(nap)
        if time.time() >= a.deadline:
            break
        last = sample_once(a.flexric_root, a.build_cov, a.ric_pid_file, a.out, a.t0, last)
    # final sample at the deadline
    sample_once(a.flexric_root, a.build_cov, a.ric_pid_file, a.out, a.t0, last)

if __name__ == "__main__":
    main()

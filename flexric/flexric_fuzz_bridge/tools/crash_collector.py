#!/usr/bin/env python3
"""Collect unique FlexRIC crash signatures from per-round RIC logs.

Assertions are parsed from glibc assert output; non-assert fatal signals from
the gcov_flush shim's backtrace block. One CSV row per first-seen signature.
"""
import argparse, csv, glob, os, re, time

HEADER = ["elapsed_min", "timestamp", "cumulative_unique", "signature"]

_ASSERT_RE = re.compile(
    r"(?P<path>[\w./+-]+\.c):(?P<line>\d+):\s*(?P<func>\w+):\s*"
    r"Assertion\s+`(?P<expr>.*)'\s+failed\.?\s*$")

_FRAME_RE = re.compile(r"\((?P<func>[\w.$]+)\+0x[0-9a-fA-F]+\)")

def assertion_signature(line):
    m = _ASSERT_RE.search(line)
    if not m:
        return None
    base = os.path.basename(m.group("path"))
    return f"{base}:{m.group('line')}: {m.group('func')}: Assertion `{m.group('expr')}' failed"

def backtrace_signature(block_lines, signame):
    # first frame that names a function and looks like FlexRIC code
    for ln in block_lines:
        if "nearRT-RIC" in ln or "/flexric/" in ln or "libe2" in ln:
            m = _FRAME_RE.search(ln)
            if m:
                return f"{signame} in {m.group('func')}"
    # fallback: any framed function, else module+offset of the first frame
    for ln in block_lines:
        m = _FRAME_RE.search(ln)
        if m:
            return f"{signame} in {m.group('func')}"
    return f"{signame} in <unknown>"

def append_crash_row(csv_path, elapsed_min, timestamp, cumulative_unique, signature):
    new = not os.path.exists(csv_path) or os.path.getsize(csv_path) == 0
    sig_q = '"' + str(signature).replace('"', '""') + '"'
    with open(csv_path, "a") as f:
        if new:
            f.write("elapsed_min,timestamp,cumulative_unique,signature\n")
        f.write(f"{elapsed_min},{timestamp},{cumulative_unique},{sig_q}\n")
        f.flush()

class CrashDedup:
    def __init__(self, csv_path, t0):
        self.csv_path = csv_path
        self.t0 = t0
        self.seen = set()
        self.count = 0

    def observe(self, signature, now=None):
        if signature in self.seen:
            return False
        now = time.time() if now is None else now
        self.seen.add(signature)
        self.count += 1
        elapsed_min = round((now - self.t0) / 60)
        ts = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(now))
        append_crash_row(self.csv_path, elapsed_min, ts, self.count, signature)
        return True

def _iter_new_lines(paths, offsets):
    for p in paths:
        try:
            with open(p, "r", errors="replace") as f:
                f.seek(offsets.get(p, 0))
                for line in f:
                    yield p, line.rstrip("\n")
                offsets[p] = f.tell()
        except FileNotFoundError:
            continue

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--logs-glob", required=True, help="e.g. campaign/logs/ric-*.log")
    ap.add_argument("--out", required=True)
    ap.add_argument("--t0", type=float, required=True)
    ap.add_argument("--deadline", type=float, required=True)
    a = ap.parse_args()

    dd = CrashDedup(a.out, a.t0)
    offsets = {}
    bt_block = None
    bt_sig = None
    while time.time() < a.deadline + 5:   # small grace to catch final crash
        for _, line in _iter_new_lines(sorted(glob.glob(a.logs_glob)), offsets):
            sig = assertion_signature(line)
            if sig:
                dd.observe(sig)
                continue
            if "=== FATAL signal" in line:
                m = re.search(r"FATAL signal (\w+)", line)
                bt_sig = m.group(1) if m else "SIGNAL"
                bt_block = []
            elif bt_block is not None and "=== end backtrace ===" in line:
                dd.observe(backtrace_signature(bt_block, bt_sig))
                bt_block = None
            elif bt_block is not None:
                bt_block.append(line)
        time.sleep(2)

if __name__ == "__main__":
    main()

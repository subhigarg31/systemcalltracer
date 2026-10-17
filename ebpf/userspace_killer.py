#!/usr/bin/env python3
"""Baseline detector in USER SPACE: same rule (4 files in 5 s), then SIGKILL."""
import os, signal, sys

WINDOW_NS, THRESHOLD = 5_000_000_000, 4
start, count, done = {}, {}, set()

for line in sys.stdin:
    if line.startswith("ARMED"):
        print("ready", flush=True)
        continue
    parts = line.split()
    if len(parts) < 3 or not parts[0].isdigit():
        continue
    pid, ts, comm = int(parts[0]), int(parts[1]), parts[2]
    if pid in done:
        continue
    if pid not in start or ts - start[pid] > WINDOW_NS:
        start[pid], count[pid] = ts, 0
    count[pid] += 1
    if count[pid] >= THRESHOLD:
        try:
            os.kill(pid, signal.SIGKILL)
            print(f'{{"event":"killed_from_userspace","pid":{pid},"process":"{comm}"}}', flush=True)
        except ProcessLookupError:
            pass
        done.add(pid)

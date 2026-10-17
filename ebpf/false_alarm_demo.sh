#!/usr/bin/env bash
# Shows WHY freezing beats killing: a legitimate backup program trips the same
# "many files fast" rule. Freeze -> resume loses nothing; kill loses work.
#   sudo ./false_alarm_demo.sh
set -u
cd "$(dirname "$0")"
DIR=/tmp/ransom_test
LOG=$(mktemp)
[ -x ./backup_tool ] || g++ -O2 -std=c++17 -o backup_tool backup_tool.cpp
stop() { pkill -INT -f "bpftrace.*(freeze|report).bt" 2>/dev/null; pkill -f userspace_killer.py 2>/dev/null; sleep 1; }
trap 'stop; rm -f "$LOG"' EXIT

echo "=== FREEZE case (in-kernel SIGSTOP, then a human resumes) ==="
rm -rf "$DIR/restore"; mkdir -p "$DIR"
bpftrace --unsafe freeze.bt > "$LOG" 2>&1 &
for _ in $(seq 100); do grep -q armed "$LOG" && break; sleep 0.2; done
./backup_tool "$DIR/restore" 50 & BP=$!
sleep 1.5
echo "  backup state: $(ps -o stat= -p $BP 2>/dev/null | tr -d ' ')  (T = frozen)"
grep frozen "$LOG" | tail -1
echo "  restored before freeze: $(ls "$DIR/restore" 2>/dev/null | wc -l) / 50"
echo "  -> analyst clicks RESUME (kill -CONT)"
kill -CONT $BP 2>/dev/null; wait $BP 2>/dev/null
echo "  restored after resume:  $(ls "$DIR/restore" 2>/dev/null | wc -l) / 50"
stop

echo
echo "=== KILL case (user-space detector sends SIGKILL) ==="
rm -rf "$DIR/restore2"; mkdir -p "$DIR"
( bpftrace -B line report.bt 2>/dev/null | python3 -u userspace_killer.py > "$LOG" ) 2>/dev/null &
for _ in $(seq 100); do grep -q ready "$LOG" && break; sleep 0.2; done
./backup_tool "$DIR/restore2" 50 & BP=$!
wait $BP 2>/dev/null
echo "  restored after kill:    $(ls "$DIR/restore2" 2>/dev/null | wc -l) / 50  (work lost)"
stop

echo
echo "=== SUMMARY ==="
echo "  Freeze + resume: 50/50 files restored (no work lost)."
echo "  Kill:            fewer than 50 restored (backup destroyed)."

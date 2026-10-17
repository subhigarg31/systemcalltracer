#!/usr/bin/env bash
# Usage: sudo ./run_experiment.sh [num_files] [delay_ms_per_file] [runs]
set -u
cd "$(dirname "$0")"
FILES=${1:-200}; DELAY=${2:-0}; RUNS=${3:-5}
DIR=/tmp/ransom_test
LOG=$(mktemp -d)

stop_tracers() { pkill -INT -f "bpftrace.*(freeze|report).bt" 2>/dev/null; pkill -f userspace_killer.py 2>/dev/null; sleep 1; }
trap 'stop_tracers; rm -rf "$LOG"' EXIT

wait_ready() {   # wait up to 20 s for the tracer to say it is attached
  for _ in $(seq 100); do grep -qs -e armed -e ready "$LOG/k.log" "$LOG/u.log" && return 0; sleep 0.2; done
  echo "tracer did not attach" >&2; return 1
}

one_run() {
  ./fake_ransom setup "$DIR" "$FILES" >/dev/null
  rm -f "$LOG/k.log" "$LOG/u.log"
  case "$1" in
    kernel)    bpftrace --unsafe freeze.bt >"$LOG/k.log" 2>&1 & ;;
    userspace) (bpftrace -B line report.bt 2>/dev/null | python3 -u userspace_killer.py >"$LOG/u.log") 2>/dev/null & ;;
  esac
  [ "$1" != none ] && wait_ready
  ./fake_ransom run "$DIR" "$FILES" "$DELAY" >/dev/null 2>&1 &
  local rp=$!
  sleep 1.5
  ./fake_ransom count "$DIR" "$FILES"
  kill -9 "$rp" 2>/dev/null; wait "$rp" 2>/dev/null
  stop_tracers
}

avg() { awk '{s+=$1} END {printf "%.1f", s/NR}'; }
echo "Files: $FILES   Delay per file: ${DELAY} ms   Runs per mode: $RUNS"; echo
printf "%-26s %-34s %s\n" "Response" "Files damaged (each run)" "Average"
for mode in none userspace kernel; do
  results=()
  for ((r=1; r<=RUNS; r++)); do results+=("$(one_run "$mode" 2>/dev/null)"); done
  case $mode in none) name="No protection";; userspace) name="User-space kill";; kernel) name="In-kernel freeze (ours)";; esac
  printf "%-26s %-34s %s / %s\n" "$name" "${results[*]}" "$(printf '%s\n' "${results[@]}" | avg)" "$FILES"
done

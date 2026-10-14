# C++ System Call Event Simulator

This module simulates realistic system-call activity on macOS without requiring Linux `ptrace` or root kernel extensions. It produces structured, newline-delimited JSON (NDJSON) events to standard output.

> **Disclaimer**: This is a behavioral simulation designed for security monitoring and anomaly detection education. It emits structured synthetic telemetry and does not perform actual malicious actions (no real sensitive file reads, no encryption, no fork bombs, and no network attacks).

## Features
- **POSIX Compliant**: Built with standard C++17, compatible with macOS Apple Clang and Linux GCC.
- **Three Simulation Scenarios**:
  - `normal`: Routine file reads, log writes, standard web/DNS connections, standard binary execution.
  - `suspicious`: Sensitive file access (`/etc/passwd`, `/etc/shadow`), rapid sequential ransomware-like writes, suspicious C2 connections (e.g. port 4444, 1337), and abnormal process spawning bursts.
  - `mixed`: Realistic mix of ~75% normal events with ~25% suspicious spikes.
- **Dynamic Control**: Supports CLI flags as well as runtime commands via standard input (`MODE <mode>`, `INTERVAL <ms>`, `QUIT`).
- **Clean Signal Handling**: Handles `SIGINT` and `SIGTERM` gracefully for safe termination.

## Building
```bash
make clean && make
```
The binary will be compiled to `bin/syscall_tracer_sim`.

## Standalone Usage
```bash
# Run continuous normal simulation at 200ms interval
./bin/syscall_tracer_sim --mode normal --interval 200

# Run continuous suspicious simulation
./bin/syscall_tracer_sim --mode suspicious --interval 150

# Emit 10 events and exit
./bin/syscall_tracer_sim --mode mixed --interval 100 --count 10
```

## JSON Event Schema
Each event contains:
```json
{
  "timestamp": "2026-10-13T10:19:29.689Z",
  "pid": 4015,
  "process_name": "curl",
  "syscall": "write",
  "category": "file",
  "scenario": "normal",
  "ret": 917,
  "args": {
    "bytes": "473",
    "fd": "3",
    "path": "/tmp/cache_store.tmp"
  }
}
```

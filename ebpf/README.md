# In-kernel ransomware freeze (eBPF)

Freeze a process from inside the kernel the moment it writes to 4+ files in 5 seconds,
instead of killing it, so a human can resume false alarms (SIGCONT) or kill real threats.

All testing happens ONLY in `/tmp/ransom_test`. `fake_ransom` refuses any other folder.

## Files

| File | What it does |
|---|---|
| `fake_ransom.cpp` | Safe test program: creates dummy files and overwrites them with random bytes |
| `freeze.bt` | **Our method**: eBPF script that sends SIGSTOP inside the kernel at 4 files / 5 s |
| `report.bt` + `userspace_killer.py` | **Baseline**: kernel only reports, Python in user space decides and kills |
| `run_experiment.sh` | Runs no protection / user-space kill / in-kernel freeze and prints a table |

## 1. Build

```bash
g++ -O2 -std=c++17 -o fake_ransom fake_ransom.cpp
chmod +x run_experiment.sh
```

## 2. Manual demo (two terminals)

Terminal 1:
```bash
sudo bpftrace --unsafe freeze.bt
```

Terminal 2:
```bash
./fake_ransom setup /tmp/ransom_test 200
./fake_ransom run /tmp/ransom_test 200 0      # hangs = frozen
```

Terminal 1 prints a JSON line with the frozen PID. In a third terminal:
```bash
ps -o pid,stat,comm -p <pid>                  # STAT "T" = stopped
./fake_ransom count /tmp/ransom_test 200      # files damaged (expect ~3)
kill -CONT <pid>                              # resume (false alarm)
# or: kill -9 <pid>                           # kill (real threat)
```

## 3. Measured comparison

```bash
sudo ./run_experiment.sh 200 0 5    # fast: no delay between files, 5 runs each
sudo ./run_experiment.sh 200 5 5    # 5 ms between files
```

## Notes

- `--unsafe` is required for `signal()`. Everything needs `sudo`.
- bpftrace 0.21+ may want `args.filename` instead of `args->filename`. If you get a
  syntax error, run: `sed -i 's/args->/args./g' freeze.bt report.bt`
- A "couldn't set RLIMIT_MEMLOCK" warning is harmless.
- Keep the project in the Linux filesystem (`~/...`), not `/mnt/c/...`.

## Tested result (bpftrace 0.20.2, Linux 6.18)

In-kernel freeze stopped the test program after **3 of 200** files; `kill -CONT` resumed it.

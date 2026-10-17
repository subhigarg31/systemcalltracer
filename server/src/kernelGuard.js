const { spawn, execFile, execFileSync } = require('child_process');
const readline = require('readline');
const fs = require('fs');
const path = require('path');
const wsManager = require('./websocket');

const EBPF_DIR = path.resolve(__dirname, '../../ebpf');
const FREEZE_SCRIPT = path.join(EBPF_DIR, 'freeze.bt');
const FAKE_RANSOM = path.join(EBPF_DIR, 'fake_ransom');
const TEST_DIR = '/tmp/ransom_test';
const TEST_FILES = 200;

class KernelGuard {
  constructor() {
    this.process = null;
    this.readline = null;
    this.status = 'off'; // off | starting | armed
    this.startTime = null;
    this.entries = new Map(); // pid -> entry
  }

  start() {
    if (this.process && !this.process.killed) {
      console.log('[KernelGuard] bpftrace is already running.');
      return { success: true, alreadyRunning: true, status: this.status };
    }

    try {
      // -B line: flush every printf so frozen events arrive immediately over the pipe
      this.process = spawn('bpftrace', ['-B', 'line', '--unsafe', FREEZE_SCRIPT], {
        stdio: ['ignore', 'pipe', 'pipe']
      });
      this.status = 'starting';
      this.startTime = Date.now();

      this.readline = readline.createInterface({
        input: this.process.stdout,
        crlfDelay: Infinity
      });

      this.readline.on('line', (line) => {
        if (!line.trim()) return;
        let msg;
        try {
          msg = JSON.parse(line.trim());
        } catch (_) {
          // bpftrace prints non-JSON lines too (e.g. "Attaching 3 probes...")
          return;
        }
        this.handleMessage(msg);
      });

      this.process.stderr.on('data', (data) => {
        console.warn(`[bpftrace stderr] ${data.toString().trim()}`);
      });

      this.process.on('close', (code) => {
        console.log(`[KernelGuard] bpftrace exited with code ${code}`);
        this.process = null;
        this.readline = null;
        this.status = 'off';
      });

      this.process.on('error', (err) => {
        console.error('[KernelGuard] Failed to start bpftrace:', err.message);
        this.process = null;
        this.status = 'off';
      });

      return { success: true, pid: this.process.pid, status: this.status };
    } catch (err) {
      console.error('[KernelGuard] Error spawning bpftrace:', err);
      throw err;
    }
  }

  handleMessage(msg) {
    if (msg.event === 'armed') {
      this.status = 'armed';
      console.log('[KernelGuard] Armed:', JSON.stringify(msg));
    } else if (msg.event === 'frozen') {
      const entry = {
        pid: msg.pid,
        process: msg.process,
        files_in_window: msg.files_in_window,
        last_file: msg.last_file,
        status: 'frozen',
        frozenAt: new Date().toISOString()
      };
      this.entries.set(entry.pid, entry);
      console.log(`[KernelGuard] Froze PID ${entry.pid} (${entry.process})`);
      wsManager.broadcast('KERNEL_FROZEN', entry);
    }
  }

  stop() {
    if (!this.process || this.process.killed) {
      this.status = 'off';
      return { success: true, wasRunning: false };
    }

    try {
      this.process.kill('SIGINT');
      this.process = null;
      this.readline = null;
      this.status = 'off';
      return { success: true, wasRunning: true };
    } catch (err) {
      console.error('[KernelGuard] Error stopping bpftrace:', err);
      return { success: false, error: err.message };
    }
  }

  // Only signal PIDs that freeze.bt reported. The server runs as root, so an
  // arbitrary PID here could stop or kill any process on the machine.
  signalEntry(pid, signal, newStatus) {
    const entry = this.entries.get(parseInt(pid, 10));
    if (!entry) {
      return { success: false, notFound: true, error: `PID ${pid} is not a frozen process tracked by the kernel guard.` };
    }

    let error = null;
    try {
      process.kill(entry.pid, signal);
      entry.status = newStatus;
    } catch (err) {
      console.warn(`[KernelGuard] ${signal} to PID ${entry.pid} failed:`, err.message);
      error = err.message;
      if (err.code === 'ESRCH') entry.status = 'exited'; // process is already gone
    }
    entry.updatedAt = new Date().toISOString();
    wsManager.broadcast('KERNEL_UPDATE', entry);
    return error ? { success: false, error, entry } : { success: true, entry };
  }

  resume(pid) {
    return this.signalEntry(pid, 'SIGCONT', 'resumed');
  }

  terminate(pid) {
    return this.signalEntry(pid, 'SIGKILL', 'killed');
  }

  getEntries() {
    return Array.from(this.entries.values());
  }

  getStatus() {
    const isRunning = !!(this.process && !this.process.killed);
    return {
      status: this.status,
      pid: isRunning ? this.process.pid : null,
      uptimeSec: isRunning && this.startTime ? Math.floor((Date.now() - this.startTime) / 1000) : 0
    };
  }

  // ---- Demo helpers (fake_ransom only ever touches /tmp/ransom_test) ----

  ensureFakeRansom() {
    if (!fs.existsSync(FAKE_RANSOM)) {
      console.log(`[KernelGuard] ${FAKE_RANSOM} not found. Compiling...`);
      execFileSync('g++', ['-O2', '-std=c++17', '-o', FAKE_RANSOM, `${FAKE_RANSOM}.cpp`], { stdio: 'inherit' });
    }
  }

  runFakeRansom(args) {
    return new Promise((resolve, reject) => {
      execFile(FAKE_RANSOM, args, (err, stdout, stderr) => {
        if (err) return reject(new Error(stderr.trim() || err.message));
        resolve(stdout.trim());
      });
    });
  }

  async demoAttack() {
    this.ensureFakeRansom();
    const setupOutput = await this.runFakeRansom(['setup', TEST_DIR, String(TEST_FILES)]);

    const child = spawn(FAKE_RANSOM, ['run', TEST_DIR, String(TEST_FILES), '0'], {
      detached: true,
      stdio: 'ignore'
    });
    child.unref();

    return { success: true, pid: child.pid, setup: setupOutput, kernelStatus: this.status };
  }

  async damage() {
    this.ensureFakeRansom();
    const out = await this.runFakeRansom(['count', TEST_DIR, String(TEST_FILES)]);
    return { damaged: parseInt(out, 10), total: TEST_FILES };
  }
}

const kernelGuard = new KernelGuard();
module.exports = kernelGuard;

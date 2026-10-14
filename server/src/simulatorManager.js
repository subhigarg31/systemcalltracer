const { spawn, execSync } = require('child_process');
const readline = require('readline');
const fs = require('fs');
const path = require('path');
const config = require('./config');

class SimulatorManager {
  constructor() {
    this.process = null;
    this.readline = null;
    this.mode = config.defaultMode;
    this.interval = config.defaultIntervalMs;
    this.startTime = null;
    this.onEventCallback = null;
    this.onErrorCallback = null;
    this.onStatusChangeCallback = null;
  }

  setCallbacks({ onEvent, onError, onStatusChange }) {
    if (onEvent) this.onEventCallback = onEvent;
    if (onError) this.onErrorCallback = onError;
    if (onStatusChange) this.onStatusChangeCallback = onStatusChange;
  }

  ensureBinaryExists() {
    const binaryPath = config.simulatorPath;
    if (!fs.existsSync(binaryPath)) {
      console.log(`[SimulatorManager] Binary not found at ${binaryPath}. Compiling...`);
      const simDir = path.dirname(path.dirname(binaryPath));
      try {
        execSync('make -C "' + simDir + '"', { stdio: 'inherit' });
        console.log('[SimulatorManager] Simulator compiled successfully.');
      } catch (err) {
        console.error('[SimulatorManager] Compilation failed:', err.message);
        throw new Error(`Failed to compile C++ simulator: ${err.message}`);
      }
    }
  }

  start({ mode, interval, threatInterval } = {}) {
    if (this.process && !this.process.killed) {
      console.log('[SimulatorManager] Simulator is already running.');
      // If mode or interval changed, update them on the fly
      if (mode && mode !== this.mode) this.setMode(mode);
      if (interval && interval !== this.interval) this.setInterval(interval);
      return { success: true, alreadyRunning: true };
    }

    this.ensureBinaryExists();

    if (mode) this.mode = mode === 'auto' ? 'automatic' : mode;
    if (interval) this.interval = interval;
    if (threatInterval) this.threatInterval = threatInterval;

    const args = [
      '--mode', this.mode,
      '--interval', this.interval.toString()
    ];
    if (this.threatInterval) {
      args.push('--threat-interval', this.threatInterval.toString());
    }

    try {
      this.process = spawn(config.simulatorPath, args, {
        stdio: ['pipe', 'pipe', 'pipe']
      });
      this.startTime = Date.now();

      this.readline = readline.createInterface({
        input: this.process.stdout,
        crlfDelay: Infinity
      });

      this.readline.on('line', (line) => {
        if (!line.trim()) return;
        try {
          const event = JSON.parse(line.trim());
          if (this.onEventCallback) {
            this.onEventCallback(event);
          }
        } catch (parseErr) {
          console.warn('[SimulatorManager] Malformed event received:', line, parseErr.message);
          if (this.onErrorCallback) {
            this.onErrorCallback(parseErr);
          }
        }
      });

      this.process.stderr.on('data', (data) => {
        console.warn(`[Simulator stderr] ${data.toString().trim()}`);
      });

      this.process.on('close', (code) => {
        console.log(`[SimulatorManager] Simulator process exited with code ${code}`);
        this.process = null;
        this.readline = null;
        if (this.onStatusChangeCallback) {
          this.onStatusChangeCallback(this.getStatus());
        }
      });

      this.process.on('error', (err) => {
        console.error('[SimulatorManager] Failed to start simulator process:', err);
        this.process = null;
        if (this.onStatusChangeCallback) {
          this.onStatusChangeCallback(this.getStatus());
        }
      });

      if (this.onStatusChangeCallback) {
        this.onStatusChangeCallback(this.getStatus());
      }

      return { success: true, pid: this.process.pid, mode: this.mode, interval: this.interval };
    } catch (err) {
      console.error('[SimulatorManager] Error spawning process:', err);
      throw err;
    }
  }

  stop() {
    if (!this.process || this.process.killed) {
      return { success: true, wasRunning: false };
    }

    try {
      // Send STOP command via stdin first
      if (this.process.stdin && !this.process.stdin.destroyed) {
        this.process.stdin.write('STOP\n');
      }
      // Send SIGTERM to ensure clean termination
      this.process.kill('SIGTERM');
      this.process = null;
      this.readline = null;

      if (this.onStatusChangeCallback) {
        this.onStatusChangeCallback(this.getStatus());
      }

      return { success: true, wasRunning: true };
    } catch (err) {
      console.error('[SimulatorManager] Error stopping simulator:', err);
      return { success: false, error: err.message };
    }
  }

  setMode(mode) {
    const normalized = mode === 'auto' ? 'automatic' : mode;
    const validModes = ['automatic', 'normal', 'suspicious', 'mixed'];
    if (!validModes.includes(normalized)) {
      throw new Error(`Invalid mode: ${mode}. Must be one of: ${validModes.join(', ')}`);
    }
    this.mode = normalized;
    if (this.process && this.process.stdin && !this.process.stdin.destroyed) {
      this.process.stdin.write(`MODE ${normalized}\n`);
    }
    if (this.onStatusChangeCallback) {
      this.onStatusChangeCallback(this.getStatus());
    }
    return { success: true, mode: this.mode };
  }

  setInterval(ms) {
    const intervalMs = parseInt(ms, 10);
    if (isNaN(intervalMs) || intervalMs < 10 || intervalMs > 5000) {
      throw new Error('Interval must be between 10ms and 5000ms');
    }
    this.interval = intervalMs;
    if (this.process && this.process.stdin && !this.process.stdin.destroyed) {
      this.process.stdin.write(`INTERVAL ${intervalMs}\n`);
    }
    return { success: true, interval: this.interval };
  }

  setThreatInterval(interval) {
    const val = parseInt(interval, 10);
    if (isNaN(val) || val < 5 || val > 500) {
      throw new Error('Threat interval must be between 5 and 500 events');
    }
    this.threatInterval = val;
    if (this.process && this.process.stdin && !this.process.stdin.destroyed) {
      this.process.stdin.write(`THREAT_INTERVAL ${val}\n`);
    }
    return { success: true, threatInterval: this.threatInterval };
  }

  getStatus() {
    const isRunning = !!(this.process && !this.process.killed);
    const uptimeSec = isRunning && this.startTime ? Math.floor((Date.now() - this.startTime) / 1000) : 0;
    return {
      isRunning,
      pid: isRunning ? this.process.pid : null,
      mode: this.mode,
      interval: this.interval,
      threatInterval: this.threatInterval || 25,
      uptimeSec
    };
  }
}

const simulatorManager = new SimulatorManager();
module.exports = simulatorManager;

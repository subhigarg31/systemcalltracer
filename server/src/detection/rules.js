const crypto = require('crypto');

function generateAlertId(prefix) {
  const randomSuffix = crypto.randomBytes(3).toString('hex').toUpperCase();
  return `ALT-${prefix}-${randomSuffix}`;
}

/**
 * Rule A: Sensitive File Access Detection
 * Detects access attempts to critical credentials/identity files.
 */
function evaluateRuleA(event, ruleConfig, state) {
  if (!ruleConfig.enabled) return null;
  if (event.category !== 'file') return null;

  const path = event.args?.path || event.args?.target || event.args?.filename || '';
  if (!path) return null;

  const matches = ruleConfig.sensitivePaths.some(p => path.startsWith(p) || path.includes(p));
  if (!matches) return null;

  const now = Date.now();
  const dedupKey = `RULE_A:${event.pid}:${path}`;
  const lastFired = state.dedupMap.get(dedupKey) || 0;
  if (now - lastFired < ruleConfig.dedupWindowMs) {
    return null; // Suppress duplicate
  }
  state.dedupMap.set(dedupKey, now);

  // Record that this PID touched sensitive credentials (for Rule C correlation)
  if (!state.sensitiveFileAccessHistory) {
    state.sensitiveFileAccessHistory = new Map();
  }
  state.sensitiveFileAccessHistory.set(event.pid, {
    path,
    timestamp: now
  });

  return {
    alertId: generateAlertId('CRED'),
    ruleId: ruleConfig.id,
    category: ruleConfig.category,
    severity: ruleConfig.severity,
    name: ruleConfig.name,
    description: `Unauthorized access attempt to sensitive system credential store: ${path}`,
    timestamp: event.timestamp || new Date().toISOString(),
    pid: event.pid,
    process_name: event.process_name,
    status: 'active',
    evidence: {
      targetedFile: path,
      syscall: event.syscall,
      flags: event.args?.flags || 'O_RDONLY',
      fd: event.args?.fd || '3',
      rawArgs: event.args
    },
    recommendedAction: 'Audit process user privileges, isolate process tree, and inspect parent process execution origin.'
  };
}

/**
 * Rule B: Ransomware-Like Rapid File Modification
 * Detects high-frequency file modifications across multiple distinct files.
 */
function evaluateRuleB(event, ruleConfig, state) {
  if (!ruleConfig.enabled) return null;
  if (event.category !== 'file') return null;

  // Writes or creates
  const isModifying = event.syscall === 'write' ||
    (event.syscall === 'openat' && (event.args?.flags?.includes('WR') || event.args?.flags?.includes('CREAT')));

  if (!isModifying) return null;

  const targetPath = event.args?.path || event.args?.target || `fd_${event.args?.fd || 'unknown'}`;
  const now = Date.now();

  if (!state.fileWriteHistory) {
    state.fileWriteHistory = [];
  }

  // Push new write event
  state.fileWriteHistory.push({
    timestamp: now,
    pid: event.pid,
    path: targetPath,
    syscall: event.syscall
  });

  // Prune history older than windowMs
  const cutoff = now - ruleConfig.windowMs;
  state.fileWriteHistory = state.fileWriteHistory.filter(w => w.timestamp >= cutoff);

  // Count distinct files modified by THIS process within window
  const pidWrites = state.fileWriteHistory.filter(w => w.pid === event.pid);
  const distinctFiles = new Set(pidWrites.map(w => w.path));

  if (distinctFiles.size >= ruleConfig.minWrites) {
    const dedupKey = `RULE_B:${event.pid}`;
    const lastFired = state.dedupMap.get(dedupKey) || 0;
    if (now - lastFired < ruleConfig.dedupWindowMs) {
      return null;
    }
    state.dedupMap.set(dedupKey, now);

    const fileList = Array.from(distinctFiles);
    const windowSec = (ruleConfig.windowMs / 1000).toFixed(1);

    return {
      alertId: generateAlertId('RANSOM'),
      ruleId: ruleConfig.id,
      category: ruleConfig.category,
      severity: ruleConfig.severity,
      name: ruleConfig.name,
      description: `Ransomware-like activity: ${distinctFiles.size} unique files modified by PID ${event.pid} in ${windowSec}s`,
      timestamp: event.timestamp || new Date().toISOString(),
      pid: event.pid,
      process_name: event.process_name,
      status: 'active',
      evidence: {
        distinctFileCount: distinctFiles.size,
        targetFilesSample: fileList.slice(0, 5),
        windowDurationMs: ruleConfig.windowMs,
        writeRate: `${(pidWrites.length / (ruleConfig.windowMs / 1000)).toFixed(1)} ops/sec`
      },
      recommendedAction: 'Instantly terminate process PID ' + event.pid + ', take volume snapshots, and check for file encryption extensions.'
    };
  }

  return null;
}

/**
 * Rule C: Suspicious Outbound Network Connection
 * Flags connections to known C2/attacker ports or correlations with prior sensitive file access.
 */
function evaluateRuleC(event, ruleConfig, state) {
  if (!ruleConfig.enabled) return null;
  if (event.category !== 'network' || event.syscall !== 'connect') return null;

  const addr = event.args?.addr || '';
  const port = parseInt(event.args?.port, 10);
  const now = Date.now();

  const isSuspiciousPort = ruleConfig.suspiciousPorts.includes(port);

  // Check correlation: Did this process access sensitive credentials in last 15 seconds?
  let correlatedWithSensitiveAccess = false;
  let sensitiveDetail = null;
  if (state.sensitiveFileAccessHistory && state.sensitiveFileAccessHistory.has(event.pid)) {
    const prev = state.sensitiveFileAccessHistory.get(event.pid);
    if (now - prev.timestamp < 15000) {
      correlatedWithSensitiveAccess = true;
      sensitiveDetail = prev;
    }
  }

  if (isSuspiciousPort || correlatedWithSensitiveAccess) {
    const dedupKey = `RULE_C:${event.pid}:${addr}:${port}`;
    const lastFired = state.dedupMap.get(dedupKey) || 0;
    if (now - lastFired < ruleConfig.dedupWindowMs) {
      return null;
    }
    state.dedupMap.set(dedupKey, now);

    let reason = `Connection to known threat/C2 port ${port}`;
    let severity = ruleConfig.severity;
    if (correlatedWithSensitiveAccess) {
      reason = `Correlated Data Exfiltration: Process touched ${sensitiveDetail.path} and connected to external IP ${addr}:${port}`;
      severity = 'Critical';
    }

    return {
      alertId: generateAlertId('C2'),
      ruleId: ruleConfig.id,
      category: ruleConfig.category,
      severity,
      name: ruleConfig.name,
      description: reason,
      timestamp: event.timestamp || new Date().toISOString(),
      pid: event.pid,
      process_name: event.process_name,
      status: 'active',
      evidence: {
        destinationIp: addr,
        destinationPort: port,
        protocol: event.args?.protocol || 'TCP',
        correlatedSensitiveAccess: correlatedWithSensitiveAccess ? sensitiveDetail : null
      },
      recommendedAction: `Apply host/firewall block rule against ${addr}:${port} and capture active socket descriptors.`
    };
  }

  return null;
}

/**
 * Rule D: Abnormal Process Creation Burst
 * Flags bursts of fork/clone/execve calls within short sliding window.
 */
function evaluateRuleD(event, ruleConfig, state) {
  if (!ruleConfig.enabled) return null;
  if (event.category !== 'process') return null;

  const isProcessSpawn = ['fork', 'clone', 'execve'].includes(event.syscall);
  if (!isProcessSpawn) return null;

  const now = Date.now();
  if (!state.processSpawnHistory) {
    state.processSpawnHistory = [];
  }

  state.processSpawnHistory.push({
    timestamp: now,
    pid: event.pid,
    syscall: event.syscall
  });

  const cutoff = now - ruleConfig.windowMs;
  state.processSpawnHistory = state.processSpawnHistory.filter(s => s.timestamp >= cutoff);

  // Filter spawns initiated by this process
  const pidSpawns = state.processSpawnHistory.filter(s => s.pid === event.pid);

  if (pidSpawns.length >= ruleConfig.maxSpawns) {
    const dedupKey = `RULE_D:${event.pid}`;
    const lastFired = state.dedupMap.get(dedupKey) || 0;
    if (now - lastFired < ruleConfig.dedupWindowMs) {
      return null;
    }
    state.dedupMap.set(dedupKey, now);

    const windowSec = (ruleConfig.windowMs / 1000).toFixed(1);
    const spawnRate = (pidSpawns.length / (ruleConfig.windowMs / 1000)).toFixed(1);

    return {
      alertId: generateAlertId('SPAWN'),
      ruleId: ruleConfig.id,
      category: ruleConfig.category,
      severity: ruleConfig.severity,
      name: ruleConfig.name,
      description: `Rapid process creation burst: PID ${event.pid} spawned ${pidSpawns.length} children in ${windowSec}s (${spawnRate} spawns/sec)`,
      timestamp: event.timestamp || new Date().toISOString(),
      pid: event.pid,
      process_name: event.process_name,
      status: 'active',
      evidence: {
        spawnCount: pidSpawns.length,
        windowMs: ruleConfig.windowMs,
        spawnRate: `${spawnRate} spawns/sec`,
        recentSyscalls: pidSpawns.slice(-4).map(s => s.syscall)
      },
      recommendedAction: 'Inspect process tree for runaway fork-bomb or multi-threaded payload deployment.'
    };
  }

  return null;
}

module.exports = {
  evaluateRuleA,
  evaluateRuleB,
  evaluateRuleC,
  evaluateRuleD
};

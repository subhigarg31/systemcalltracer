const path = require('path');

const config = {
  port: parseInt(process.env.PORT, 10) || 3001,
  simulatorPath: path.resolve(__dirname, '../../simulator/bin/syscall_tracer_sim'),
  maxEventsInMemory: 2000,
  maxAlertsInMemory: 500,

  // Simulator defaults
  defaultMode: 'automatic',
  defaultIntervalMs: 200,

  // Threat Detection Rules Configuration
  rules: {
    ruleA: {
      id: 'RULE_A_SENSITIVE_FILE',
      enabled: true,
      name: 'Sensitive File Access',
      category: 'Credential Access',
      severity: 'Critical',
      sensitivePaths: ['/etc/passwd', '/etc/shadow', '/etc/sudoers', '/root/.ssh'],
      dedupWindowMs: 4000,
      description: 'Attempted unauthorized read/open of credential or system identity files.'
    },
    ruleB: {
      id: 'RULE_B_RANSOMWARE',
      enabled: true,
      name: 'Ransomware-Like Rapid File Modification',
      category: 'Ransomware / Data Destruction',
      severity: 'Critical',
      minWrites: 4,
      windowMs: 5000,
      dedupWindowMs: 6000,
      description: 'Rapid sequential file write/create operations across multiple files within a short time window.'
    },
    ruleC: {
      id: 'RULE_C_SUSPICIOUS_NETWORK',
      enabled: true,
      name: 'Suspicious Outbound Network Connection',
      category: 'Command & Control / Exfiltration',
      severity: 'High',
      suspiciousPorts: [4444, 1337, 6667, 31337, 8888, 9001],
      dedupWindowMs: 5000,
      description: 'Outbound connection directed to non-standard administrative or known command-and-control ports.'
    },
    ruleD: {
      id: 'RULE_D_PROCESS_BURST',
      enabled: true,
      name: 'Abnormal Process Creation Burst',
      category: 'Process Spawning / Denial of Service',
      severity: 'Medium',
      maxSpawns: 5,
      windowMs: 4000,
      dedupWindowMs: 5000,
      description: 'Abnormally high frequency of process-creation events (fork/clone/execve) in a rolling window.'
    }
  },

  // Risk Scoring Model Configuration
  risk: {
    decayIntervalMs: 1500,
    decayStep: 10,
    severityWeights: {
      Critical: 35,
      High: 20,
      Medium: 10,
      Low: 5
    },
    bands: [
      { name: 'Low', min: 0, max: 24, color: 'emerald' },
      { name: 'Guarded', min: 25, max: 49, color: 'amber' },
      { name: 'High', min: 50, max: 74, color: 'orange' },
      { name: 'Critical', min: 75, max: 100, color: 'red' }
    ]
  }
};

module.exports = config;

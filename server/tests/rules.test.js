const test = require('node:test');
const assert = require('node:assert');
const DetectionEngine = require('../src/detection/engine');

test('Threat Detection Rules & Deduplication', async (t) => {
  let engine;

  t.beforeEach(() => {
    engine = new DetectionEngine();
  });

  await t.test('Rule A: Detects sensitive file access to /etc/passwd', () => {
    const event = {
      timestamp: new Date().toISOString(),
      pid: 5001,
      process_name: 'recon_bot',
      syscall: 'openat',
      category: 'file',
      scenario: 'suspicious',
      ret: 3,
      args: { path: '/etc/passwd', flags: 'O_RDONLY' }
    };

    const res = engine.processEvent(event, []);
    assert.strictEqual(res.newAlerts.length, 1);
    const alert = res.newAlerts[0];
    assert.strictEqual(alert.ruleId, 'RULE_A_SENSITIVE_FILE');
    assert.strictEqual(alert.category, 'Credential Access');
    assert.strictEqual(alert.severity, 'Critical');
    assert.strictEqual(alert.evidence.targetedFile, '/etc/passwd');
    assert.ok(alert.recommendedAction.length > 0);
  });

  await t.test('Rule A: Deduplicates subsequent access within window', () => {
    const event = {
      timestamp: new Date().toISOString(),
      pid: 5001,
      process_name: 'recon_bot',
      syscall: 'openat',
      category: 'file',
      scenario: 'suspicious',
      ret: 3,
      args: { path: '/etc/shadow', flags: 'O_RDONLY' }
    };

    const res1 = engine.processEvent(event, []);
    assert.strictEqual(res1.newAlerts.length, 1);

    // Immediate second event should be deduplicated
    const res2 = engine.processEvent(event, []);
    assert.strictEqual(res2.newAlerts.length, 0);
  });

  await t.test('Rule B: Detects ransomware-like multi-file modification', () => {
    const files = [
      '/home/user/doc1.docx.enc',
      '/home/user/doc2.xlsx.enc',
      '/home/user/doc3.pdf.enc',
      '/home/user/doc4.sql.enc'
    ];

    let lastResult = null;
    for (const f of files) {
      const event = {
        timestamp: new Date().toISOString(),
        pid: 7770,
        process_name: 'ransom_sim',
        syscall: 'write',
        category: 'file',
        scenario: 'suspicious',
        ret: 4096,
        args: { path: f, bytes: '4096' }
      };
      lastResult = engine.processEvent(event, []);
    }

    assert.ok(lastResult.newAlerts.length >= 1);
    const ransomwareAlert = lastResult.newAlerts.find(a => a.ruleId === 'RULE_B_RANSOMWARE');
    assert.ok(ransomwareAlert);
    assert.strictEqual(ransomwareAlert.severity, 'Critical');
    assert.strictEqual(ransomwareAlert.evidence.distinctFileCount, 4);
  });

  await t.test('Rule C: Flags port 4444 and ignores port 443', () => {
    // Normal HTTPS port should NOT trigger alert
    const normalEvent = {
      timestamp: new Date().toISOString(),
      pid: 1024,
      process_name: 'nginx',
      syscall: 'connect',
      category: 'network',
      scenario: 'normal',
      ret: 0,
      args: { addr: '142.250.190.46', port: '443', protocol: 'TCP' }
    };
    const normalRes = engine.processEvent(normalEvent, []);
    assert.strictEqual(normalRes.newAlerts.length, 0);

    // Suspicious port 4444 should trigger alert
    const c2Event = {
      timestamp: new Date().toISOString(),
      pid: 8888,
      process_name: 'c2_beacon',
      syscall: 'connect',
      category: 'network',
      scenario: 'suspicious',
      ret: 0,
      args: { addr: '198.51.100.23', port: '4444', protocol: 'TCP' }
    };
    const c2Res = engine.processEvent(c2Event, []);
    assert.strictEqual(c2Res.newAlerts.length, 1);
    assert.strictEqual(c2Res.newAlerts[0].ruleId, 'RULE_C_SUSPICIOUS_NETWORK');
    assert.strictEqual(c2Res.newAlerts[0].severity, 'High');
  });

  await t.test('Rule C: Detects correlated exfiltration (credential access followed by connection)', () => {
    const credEvent = {
      timestamp: new Date().toISOString(),
      pid: 9110,
      process_name: 'exfil_agent',
      syscall: 'openat',
      category: 'file',
      scenario: 'suspicious',
      ret: 3,
      args: { path: '/etc/passwd', flags: 'O_RDONLY' }
    };
    engine.processEvent(credEvent, []);

    // Now exfil_agent connects to an external host
    const netEvent = {
      timestamp: new Date().toISOString(),
      pid: 9110,
      process_name: 'exfil_agent',
      syscall: 'connect',
      category: 'network',
      scenario: 'suspicious',
      ret: 0,
      args: { addr: '203.0.113.50', port: '8080' }
    };
    const netRes = engine.processEvent(netEvent, []);
    assert.strictEqual(netRes.newAlerts.length, 1);
    assert.strictEqual(netRes.newAlerts[0].severity, 'Critical');
    assert.match(netRes.newAlerts[0].description, /exfiltration/i);
  });

  await t.test('Rule D: Detects abnormal process creation burst', () => {
    let lastRes;
    for (let i = 0; i < 5; i++) {
      const spawnEvent = {
        timestamp: new Date().toISOString(),
        pid: 3333,
        process_name: 'fork_bomb_sim',
        syscall: i % 2 === 0 ? 'fork' : 'clone',
        category: 'process',
        scenario: 'suspicious',
        ret: 3334 + i,
        args: { parent_pid: '3333' }
      };
      lastRes = engine.processEvent(spawnEvent, []);
    }

    assert.ok(lastRes.newAlerts.length >= 1);
    const spawnAlert = lastRes.newAlerts.find(a => a.ruleId === 'RULE_D_PROCESS_BURST');
    assert.ok(spawnAlert);
    assert.strictEqual(spawnAlert.category, 'Process Spawning / Denial of Service');
  });

  await t.test('Normal activity scenario does not trigger high-severity alerts', () => {
    const normalEvents = [
      {
        timestamp: new Date().toISOString(),
        pid: 1024,
        process_name: 'nginx',
        syscall: 'openat',
        category: 'file',
        scenario: 'normal',
        ret: 3,
        args: { path: '/var/log/nginx/access.log', flags: 'O_RDONLY' }
      },
      {
        timestamp: new Date().toISOString(),
        pid: 1024,
        process_name: 'nginx',
        syscall: 'read',
        category: 'file',
        scenario: 'normal',
        ret: 1024,
        args: { fd: '3', bytes: '1024' }
      },
      {
        timestamp: new Date().toISOString(),
        pid: 2048,
        process_name: 'node_app',
        syscall: 'connect',
        category: 'network',
        scenario: 'normal',
        ret: 0,
        args: { addr: '8.8.8.8', port: '53' }
      },
      {
        timestamp: new Date().toISOString(),
        pid: 3000,
        process_name: 'bash',
        syscall: 'execve',
        category: 'process',
        scenario: 'normal',
        ret: 0,
        args: { filename: '/bin/ls' }
      }
    ];

    for (const ev of normalEvents) {
      const res = engine.processEvent(ev, []);
      assert.strictEqual(res.newAlerts.length, 0, `Normal event ${ev.syscall} should not trigger alert`);
      assert.strictEqual(res.risk.band, 'Low');
      assert.ok(res.risk.score < 25);
    }
  });
});

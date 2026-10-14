const test = require('node:test');
const assert = require('node:assert/strict');
const DetectionEngine = require('../src/detection/engine');
const config = require('../src/config');

test('Detection Engine Scenario Independence Tests', async (t) => {
  await t.test('Identical event sequence yields identical alerts and risk scores regardless of scenario label', () => {
    const modes = ['automatic', 'normal', 'suspicious', 'mixed', undefined];

    const generateSequence = (scenarioLabel) => [
      {
        timestamp: new Date(Date.now() - 5000).toISOString(),
        pid: 1024,
        process_name: 'nginx',
        syscall: 'read',
        category: 'file',
        scenario: scenarioLabel,
        args: { fd: '3', bytes: '1024' },
        ret: 1024
      },
      {
        timestamp: new Date(Date.now() - 4000).toISOString(),
        pid: 6601,
        process_name: 'recon_agent',
        syscall: 'openat',
        category: 'file',
        scenario: scenarioLabel,
        args: { dirfd: 'AT_FDCWD', path: '/etc/passwd', flags: 'O_RDONLY' },
        ret: 3
      },
      {
        timestamp: new Date(Date.now() - 3000).toISOString(),
        pid: 8820,
        process_name: 'c2_beacon',
        syscall: 'connect',
        category: 'network',
        scenario: scenarioLabel,
        args: { addr: '198.51.100.23', port: '4444', protocol: 'TCP' },
        ret: 0
      }
    ];

    const baselineResults = [];

    // Run baseline with 'automatic'
    const baselineEngine = new DetectionEngine(config);
    let baselineActiveAlerts = [];
    const seqAutomatic = generateSequence('automatic');
    for (const ev of seqAutomatic) {
      const res = baselineEngine.processEvent(ev, baselineActiveAlerts);
      baselineActiveAlerts = [...baselineActiveAlerts, ...res.newAlerts];
      baselineResults.push({
        flagged: res.event.detection.flagged,
        alertCount: res.newAlerts.length,
        ruleIds: res.newAlerts.map(a => a.ruleId),
        severities: res.newAlerts.map(a => a.severity),
        riskScore: res.risk.score,
        riskBand: res.risk.band
      });
    }

    // Now verify every other mode produces identical detection decisions and risk scores
    for (const mode of modes) {
      const engine = new DetectionEngine(config);
      let activeAlerts = [];
      const seq = generateSequence(mode);

      for (let i = 0; i < seq.length; i++) {
        const res = engine.processEvent(seq[i], activeAlerts);
        activeAlerts = [...activeAlerts, ...res.newAlerts];

        const expected = baselineResults[i];
        assert.equal(res.event.detection.flagged, expected.flagged, `Mode ${mode} flagged mismatch at step ${i}`);
        assert.equal(res.newAlerts.length, expected.alertCount, `Mode ${mode} alertCount mismatch at step ${i}`);
        assert.deepEqual(res.newAlerts.map(a => a.ruleId), expected.ruleIds, `Mode ${mode} ruleId mismatch at step ${i}`);
        assert.deepEqual(res.newAlerts.map(a => a.severity), expected.severities, `Mode ${mode} severity mismatch at step ${i}`);
        assert.equal(res.risk.score, expected.riskScore, `Mode ${mode} riskScore mismatch at step ${i}`);
        assert.equal(res.risk.band, expected.riskBand, `Mode ${mode} riskBand mismatch at step ${i}`);
      }
    }
  });

  await t.test('Rule A fires based on sensitive file path, not scenario label', () => {
    const scenarios = ['automatic', 'normal', 'suspicious', 'mixed'];
    for (const sc of scenarios) {
      const engine = new DetectionEngine(config);
      const ev = {
        timestamp: new Date().toISOString(),
        pid: 3001,
        process_name: 'test_proc',
        syscall: 'openat',
        category: 'file',
        scenario: sc,
        args: { path: '/etc/shadow', flags: 'O_RDONLY' },
        ret: 3
      };
      const res = engine.processEvent(ev, []);
      assert.equal(res.newAlerts.length, 1, `Rule A must trigger for ${sc}`);
      assert.equal(res.newAlerts[0].ruleId, 'RULE_A_SENSITIVE_FILE');
      assert.equal(res.newAlerts[0].severity, 'Critical');
      assert.equal(res.newAlerts[0].riskScore, res.risk.score);
    }
  });

  await t.test('Rule B fires based on multi-file write pattern, not scenario label', () => {
    const scenarios = ['automatic', 'normal', 'suspicious', 'mixed'];
    for (const sc of scenarios) {
      const engine = new DetectionEngine(config);
      let lastRes = null;
      for (let i = 0; i < 4; i++) {
        const ev = {
          timestamp: new Date().toISOString(),
          pid: 4001,
          process_name: 'writer',
          syscall: 'write',
          category: 'file',
          scenario: sc,
          args: { path: `/data/file_${i}.dat`, bytes: '4096' },
          ret: 4096
        };
        lastRes = engine.processEvent(ev, []);
      }
      assert.equal(lastRes.newAlerts.length, 1, `Rule B must trigger for ${sc}`);
      assert.equal(lastRes.newAlerts[0].ruleId, 'RULE_B_RANSOMWARE');
      assert.equal(lastRes.newAlerts[0].severity, 'Critical');
    }
  });

  await t.test('Rule C fires based on destination port without synthetic flags', () => {
    const engine = new DetectionEngine(config);
    // Port 4444 should fire without any suspicious_port flag
    const evThreat = {
      timestamp: new Date().toISOString(),
      pid: 5001,
      process_name: 'beacon',
      syscall: 'connect',
      category: 'network',
      scenario: 'normal', // labeled "normal" but connecting to port 4444!
      args: { addr: '198.51.100.23', port: '4444', protocol: 'TCP' },
      ret: 0
    };
    const resThreat = engine.processEvent(evThreat, []);
    assert.equal(resThreat.newAlerts.length, 1, 'Port 4444 must trigger Rule C even if scenario is labeled normal');
    assert.equal(resThreat.newAlerts[0].ruleId, 'RULE_C_SUSPICIOUS_NETWORK');

    // Port 443 should NEVER fire even if scenario is labeled "suspicious"
    const evSafe = {
      timestamp: new Date().toISOString(),
      pid: 5002,
      process_name: 'browser',
      syscall: 'connect',
      category: 'network',
      scenario: 'suspicious', // labeled "suspicious" but connecting to legitimate port 443!
      args: { addr: '142.250.190.46', port: '443', protocol: 'TCP' },
      ret: 0
    };
    const resSafe = engine.processEvent(evSafe, []);
    assert.equal(resSafe.newAlerts.length, 0, 'Legitimate port 443 must not trigger Rule C even if scenario is labeled suspicious');
  });

  await t.test('Rule D fires based on spawn burst frequency per PID, not scenario label', () => {
    const scenarios = ['automatic', 'normal', 'suspicious'];
    for (const sc of scenarios) {
      const engine = new DetectionEngine(config);
      let lastRes = null;
      for (let i = 0; i < 5; i++) {
        const ev = {
          timestamp: new Date().toISOString(),
          pid: 7001,
          process_name: 'forker',
          syscall: 'fork',
          category: 'process',
          scenario: sc,
          args: { parent_pid: '7001' },
          ret: 7001 + i + 1
        };
        lastRes = engine.processEvent(ev, []);
      }
      assert.equal(lastRes.newAlerts.length, 1, `Rule D must trigger on 5th spawn for ${sc}`);
      assert.equal(lastRes.newAlerts[0].ruleId, 'RULE_D_PROCESS_BURST');
    }
  });

  await t.test('Routine telemetry stream does not systematically trigger high-severity alerts', () => {
    const engine = new DetectionEngine(config);
    const standardFiles = ['/var/log/app.log', '/etc/hosts', '/etc/resolv.conf', '/tmp/cache.tmp'];
    const standardPorts = ['80', '443', '53', '3000'];

    let highCritAlertCount = 0;
    for (let i = 0; i < 300; i++) {
      const isFile = i % 2 === 0;
      const ev = isFile ? {
        timestamp: new Date().toISOString(),
        pid: 1000 + (i % 5),
        process_name: 'worker',
        syscall: (i % 4 === 0) ? 'write' : 'read',
        category: 'file',
        scenario: 'automatic',
        args: { path: standardFiles[i % standardFiles.length], bytes: '256' },
        ret: 256
      } : {
        timestamp: new Date().toISOString(),
        pid: 2000 + (i % 5),
        process_name: 'curl_proc',
        syscall: 'connect',
        category: 'network',
        scenario: 'automatic',
        args: { addr: '8.8.8.8', port: standardPorts[i % standardPorts.length], protocol: 'TCP' },
        ret: 0
      };

      const res = engine.processEvent(ev, []);
      for (const alert of res.newAlerts) {
        if (alert.severity === 'Critical' || alert.severity === 'High') {
          highCritAlertCount++;
        }
      }
    }

    assert.equal(highCritAlertCount, 0, 'Normal routine telemetry must not trigger high or critical severity alerts');
    assert.equal(engine.riskScorer.currentScore, 0, 'Risk score must remain at 0 during normal activity');
  });

  await t.test('Alert objects contain riskScore, riskBand, ruleId, severity, pid, and evidence', () => {
    const engine = new DetectionEngine(config);
    const ev = {
      timestamp: new Date().toISOString(),
      pid: 9911,
      process_name: 'bad_actor',
      syscall: 'openat',
      category: 'file',
      scenario: 'automatic',
      args: { path: '/etc/passwd', flags: 'O_RDONLY' },
      ret: 3
    };

    const res = engine.processEvent(ev, []);
    assert.equal(res.newAlerts.length, 1);
    const alert = res.newAlerts[0];

    assert.ok(alert.alertId);
    assert.equal(alert.ruleId, 'RULE_A_SENSITIVE_FILE');
    assert.equal(alert.severity, 'Critical');
    assert.equal(alert.pid, 9911);
    assert.ok(alert.timestamp);
    assert.ok(alert.evidence);
    assert.equal(typeof alert.riskScore, 'number');
    assert.ok(alert.riskScore > 0);
    assert.ok(alert.riskBand);
  });
});

const test = require('node:test');
const assert = require('node:assert');
const express = require('express');
const store = require('../src/store');
const apiRoutes = require('../src/routes/api');

// Lightweight request dispatcher for testing Express routes in isolation without network sockets
function dispatch(app, method, path, { body = {}, query = {} } = {}) {
  return new Promise((resolve, reject) => {
    // Build query string if any
    const queryString = new URLSearchParams(query).toString();
    const fullUrl = queryString ? `${path}?${queryString}` : path;

    const req = {
      method,
      url: fullUrl,
      originalUrl: fullUrl,
      path,
      query,
      body,
      params: {},
      headers: { 'content-type': 'application/json' },
      get: (h) => (h === 'content-type' ? 'application/json' : undefined)
    };

    let statusCode = 200;
    const resHeaders = {};
    let payload = null;

    const res = {
      status(code) {
        statusCode = code;
        return res;
      },
      setHeader(k, v) {
        resHeaders[k.toLowerCase()] = v;
        return res;
      },
      getHeader(k) {
        return resHeaders[k.toLowerCase()];
      },
      json(data) {
        payload = data;
        resolve({ status: statusCode, headers: resHeaders, body: payload });
        return res;
      },
      send(data) {
        payload = data;
        resolve({ status: statusCode, headers: resHeaders, body: payload });
        return res;
      },
      end() {
        resolve({ status: statusCode, headers: resHeaders, body: payload });
        return res;
      }
    };

    app.handle(req, res, (err) => {
      if (err) reject(err);
      else resolve({ status: statusCode, headers: resHeaders, body: payload });
    });
  });
}

test('REST API Endpoints', async (t) => {
  let app;

  t.before(() => {
    app = express();
    app.use(express.json());
    const DetectionEngine = require('../src/detection/engine');
    app.set('detectionEngine', new DetectionEngine());
    app.use('/api', apiRoutes);
  });

  await t.test('GET /api/health returns ok', async () => {
    const res = await dispatch(app, 'GET', '/api/health');
    assert.strictEqual(res.status, 200);
    assert.strictEqual(res.body.status, 'ok');
    assert.ok(typeof res.body.uptime === 'number');
  });

  await t.test('GET /api/status returns valid state', async () => {
    const res = await dispatch(app, 'GET', '/api/status');
    assert.strictEqual(res.status, 200);
    assert.ok(res.body.session);
    assert.ok(res.body.metrics);
  });

  await t.test('GET /api/events returns event list and handles filters', async () => {
    store.reset();
    store.addEvent({
      timestamp: new Date().toISOString(),
      pid: 101,
      process_name: 'test_proc',
      syscall: 'openat',
      category: 'file',
      scenario: 'normal',
      ret: 3,
      args: { path: '/tmp/test' }
    });

    const res = await dispatch(app, 'GET', '/api/events', { query: { category: 'file' } });
    assert.strictEqual(res.status, 200);
    assert.strictEqual(res.body.total, 1);
    assert.strictEqual(res.body.events[0].process_name, 'test_proc');
  });

  await t.test('Alert lifecycle and acknowledgement', async () => {
    store.addAlert({
      alertId: 'ALT-TEST-999',
      ruleId: 'RULE_A_SENSITIVE_FILE',
      category: 'Credential Access',
      severity: 'Critical',
      name: 'Test Alert',
      description: 'Test description',
      timestamp: new Date().toISOString(),
      pid: 101,
      process_name: 'test_proc',
      status: 'active',
      evidence: {},
      recommendedAction: 'Investigate'
    });

    // Check alert in list
    const resList = await dispatch(app, 'GET', '/api/alerts', { query: { status: 'active' } });
    assert.ok(resList.body.alerts.some(a => a.alertId === 'ALT-TEST-999'));

    // Acknowledge alert
    const resAck = await dispatch(app, 'POST', '/api/alerts/ALT-TEST-999/acknowledge');
    assert.strictEqual(resAck.status, 200);
    assert.strictEqual(resAck.body.alert.status, 'acknowledged');
    assert.strictEqual(resAck.body.risk.score, 0); // All active alerts cleared, score drops to 0
    assert.strictEqual(resAck.body.risk.band, 'Low');

    // Verify active alert count decreased
    const resAfter = await dispatch(app, 'GET', '/api/alerts', { query: { status: 'active' } });
    assert.strictEqual(resAfter.body.alerts.some(a => a.alertId === 'ALT-TEST-999'), false);
  });

  await t.test('GET /api/metrics returns aggregated metrics', async () => {
    const res = await dispatch(app, 'GET', '/api/metrics');
    assert.strictEqual(res.status, 200);
    assert.ok(res.body.risk);
    assert.ok(res.body.counts);
    assert.ok(res.body.categoryCounts);
  });

  await t.test('POST /api/settings updates configuration safely', async () => {
    const res = await dispatch(app, 'POST', '/api/settings', {
      body: { defaultIntervalMs: 350 }
    });
    assert.strictEqual(res.status, 200);
    assert.strictEqual(res.body.settings.defaultIntervalMs, 350);
  });

  await t.test('POST /api/reset clears session data', async () => {
    const res = await dispatch(app, 'POST', '/api/reset');
    assert.strictEqual(res.status, 200);
    assert.strictEqual(res.body.success, true);
    assert.strictEqual(store.metrics.totalEvents, 0);
  });
});

const test = require('node:test');
const assert = require('node:assert');
const express = require('express');
const store = require('../src/store');
const reportRoutes = require('../src/routes/reports');

function dispatch(app, method, path, { query = {} } = {}) {
  return new Promise((resolve, reject) => {
    const queryString = new URLSearchParams(query).toString();
    const fullUrl = queryString ? `${path}?${queryString}` : path;

    const req = {
      method,
      url: fullUrl,
      originalUrl: fullUrl,
      path,
      query,
      body: {},
      params: {},
      headers: {},
      get: (h) => undefined
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

test('Report Generation & Export', async (t) => {
  let app;

  t.before(() => {
    app = express();
    app.use('/api/reports', reportRoutes);

    // Populate test session data
    store.reset();
    store.addEvent({
      timestamp: new Date().toISOString(),
      pid: 2000,
      process_name: 'test_writer',
      syscall: 'write',
      category: 'file',
      scenario: 'suspicious',
      ret: 1024,
      args: { path: '/tmp/locked.enc' }
    });
    store.addAlert({
      alertId: 'ALT-REP-101',
      ruleId: 'RULE_B_RANSOMWARE',
      category: 'Ransomware / Data Destruction',
      severity: 'Critical',
      name: 'Ransomware Event',
      description: 'Mass file write detected',
      timestamp: new Date().toISOString(),
      pid: 2000,
      process_name: 'test_writer',
      status: 'active',
      evidence: { distinctFileCount: 5 },
      recommendedAction: 'Isolate host'
    });
  });

  await t.test('GET /api/reports/summary returns comprehensive report structure', async () => {
    const res = await dispatch(app, 'GET', '/api/reports/summary');
    assert.strictEqual(res.status, 200);
    const data = res.body;
    assert.ok(data.metadata);
    assert.ok(data.executiveSummary);
    assert.ok(data.threatAlerts);
    assert.ok(Array.isArray(data.systemLimitations));
    assert.strictEqual(data.threatAlerts.length, 1);
    assert.strictEqual(data.threatAlerts[0].alertId, 'ALT-REP-101');
  });

  await t.test('GET /api/reports/download?format=json serves valid downloadable JSON', async () => {
    const res = await dispatch(app, 'GET', '/api/reports/download', { query: { format: 'json' } });
    assert.strictEqual(res.status, 200);
    assert.match(res.headers['content-type'], /application\/json/);
    assert.match(res.headers['content-disposition'], /attachment;/);
    const data = JSON.parse(res.body);
    assert.strictEqual(data.metadata.reportTitle, 'System Call Tracer - Threat Intelligence & Anomaly Report');
  });

  await t.test('GET /api/reports/download?format=csv serves structured CSV', async () => {
    const res = await dispatch(app, 'GET', '/api/reports/download', { query: { format: 'csv' } });
    assert.strictEqual(res.status, 200);
    assert.match(res.headers['content-type'], /text\/csv/);
    assert.match(res.body, /SYSTEM CALL TRACER ANOMALY REPORT/);
    assert.match(res.body, /ALT-REP-101/);
  });

  await t.test('GET /api/reports/html returns printable HTML document', async () => {
    const res = await dispatch(app, 'GET', '/api/reports/html');
    assert.strictEqual(res.status, 200);
    assert.match(res.headers['content-type'], /text\/html/);
    assert.match(res.body, /<!DOCTYPE html>/i);
    assert.match(res.body, /window\.print\(\)/);
    assert.match(res.body, /ALT-REP-101/);
  });
});

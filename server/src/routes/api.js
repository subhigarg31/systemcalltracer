const express = require('express');
const router = express.Router();
const store = require('../store');
const simulatorManager = require('../simulatorManager');

// Health check
router.get('/health', (req, res) => {
  res.json({
    status: 'ok',
    timestamp: new Date().toISOString(),
    uptime: Math.floor(process.uptime())
  });
});

// Current session status
router.get('/status', (req, res) => {
  res.json({
    session: store.session,
    simulator: simulatorManager.getStatus(),
    metrics: {
      totalEvents: store.metrics.totalEvents,
      totalAlerts: store.metrics.totalAlerts,
      activeAlerts: store.metrics.activeAlerts,
      highCritAlerts: store.metrics.highCritAlerts,
      currentRiskScore: store.metrics.currentRiskScore,
      riskBand: store.metrics.riskBand
    }
  });
});

// Start simulator
router.post('/simulator/start', (req, res) => {
  try {
    const { mode, interval } = req.body || {};
    const result = simulatorManager.start({ mode, interval });
    store.session.isRunning = true;
    if (mode) store.session.currentMode = mode;
    res.json(result);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Stop simulator
router.post('/simulator/stop', (req, res) => {
  try {
    const result = simulatorManager.stop();
    store.session.isRunning = false;
    res.json(result);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Update mode
router.post('/simulator/mode', (req, res) => {
  try {
    const { mode } = req.body || {};
    if (!mode) return res.status(400).json({ error: 'Missing mode parameter' });
    const result = simulatorManager.setMode(mode);
    store.session.currentMode = mode;
    res.json(result);
  } catch (err) {
    res.status(400).json({ error: err.message });
  }
});

// Update interval
router.post('/simulator/interval', (req, res) => {
  try {
    const { interval } = req.body || {};
    if (!interval) return res.status(400).json({ error: 'Missing interval parameter' });
    const result = simulatorManager.setInterval(interval);
    res.json(result);
  } catch (err) {
    res.status(400).json({ error: err.message });
  }
});

// Update threat interval in automatic mode
router.post('/simulator/threat-interval', (req, res) => {
  try {
    const { threatInterval } = req.body || {};
    if (!threatInterval) return res.status(400).json({ error: 'Missing threatInterval parameter' });
    const result = simulatorManager.setThreatInterval(threatInterval);
    res.json(result);
  } catch (err) {
    res.status(400).json({ error: err.message });
  }
});

// Query events
router.get('/events', (req, res) => {
  const { limit, category, search, pid, severity } = req.query;
  const events = store.getFilteredEvents({
    limit: limit ? parseInt(limit, 10) : 100,
    category,
    search,
    pid,
    severity
  });
  res.json({
    total: store.metrics.totalEvents,
    count: events.length,
    events
  });
});

// Query alerts
router.get('/alerts', (req, res) => {
  const { status, severity, search, limit } = req.query;
  const alerts = store.getAlerts({
    status,
    severity,
    search,
    limit: limit ? parseInt(limit, 10) : 100
  });
  res.json({
    total: store.metrics.totalAlerts,
    active: store.metrics.activeAlerts,
    alerts
  });
});

// Acknowledge alert
router.post('/alerts/:id/acknowledge', (req, res) => {
  const alertId = req.params.id;
  const alert = store.acknowledgeAlert(alertId);
  if (!alert) {
    return res.status(404).json({ error: `Alert ${alertId} not found or already acknowledged.` });
  }

  // Recalculate score from remaining active alerts
  const engine = req.app.get('detectionEngine');
  let updatedRisk = null;
  if (engine) {
    const activeAlerts = store.alerts.filter(a => a.status === 'active');
    updatedRisk = engine.recalculateScore(activeAlerts);
    store.updateRiskScore(updatedRisk.score, updatedRisk.band);

    const wsManager = req.app.get('wsManager');
    if (wsManager) {
      wsManager.broadcast('ALERT_ACKNOWLEDGED', alert);
      wsManager.broadcast('METRICS', {
        totalEvents: store.metrics.totalEvents,
        totalAlerts: store.metrics.totalAlerts,
        activeAlerts: store.metrics.activeAlerts,
        highCritAlerts: store.metrics.highCritAlerts,
        currentRiskScore: store.metrics.currentRiskScore,
        riskBand: store.metrics.riskBand,
        categoryCounts: store.metrics.categoryCounts,
        timeSeries: store.metrics.timeSeries
      });
    }
  }

  res.json({ success: true, alert, risk: updatedRisk });
});

// Query dashboard metrics
router.get('/metrics', (req, res) => {
  res.json({
    risk: {
      score: store.metrics.currentRiskScore,
      band: store.metrics.riskBand
    },
    counts: {
      totalEvents: store.metrics.totalEvents,
      totalAlerts: store.metrics.totalAlerts,
      activeAlerts: store.metrics.activeAlerts,
      highCritAlerts: store.metrics.highCritAlerts,
      uniqueProcesses: store.processes.size
    },
    categoryCounts: store.metrics.categoryCounts,
    syscallCounts: store.metrics.syscallCounts,
    timeSeries: store.metrics.timeSeries
  });
});

// Query process activity
router.get('/processes', (req, res) => {
  const processes = store.getProcessesList();
  res.json({
    count: processes.length,
    processes
  });
});

// Get settings
router.get('/settings', (req, res) => {
  res.json(store.settings);
});

// Update settings
router.post('/settings', (req, res) => {
  const updates = req.body || {};
  
  if (updates.defaultIntervalMs) {
    const val = parseInt(updates.defaultIntervalMs, 10);
    if (!isNaN(val) && val >= 10 && val <= 5000) {
      store.settings.defaultIntervalMs = val;
      simulatorManager.setInterval(val);
    }
  }

  if (updates.maxEventsInMemory) {
    const val = parseInt(updates.maxEventsInMemory, 10);
    if (!isNaN(val) && val >= 50 && val <= 5000) {
      store.settings.maxEventsInMemory = val;
    }
  }

  if (updates.rules) {
    // Merge rule thresholds safely
    if (updates.rules.ruleA) Object.assign(store.settings.rules.ruleA, updates.rules.ruleA);
    if (updates.rules.ruleB) Object.assign(store.settings.rules.ruleB, updates.rules.ruleB);
    if (updates.rules.ruleC) Object.assign(store.settings.rules.ruleC, updates.rules.ruleC);
    if (updates.rules.ruleD) Object.assign(store.settings.rules.ruleD, updates.rules.ruleD);
  }

  if (updates.risk) {
    if (updates.risk.decayIntervalMs) store.settings.risk.decayIntervalMs = updates.risk.decayIntervalMs;
    if (updates.risk.decayStep) store.settings.risk.decayStep = updates.risk.decayStep;
  }

  res.json({ success: true, settings: store.settings });
});

// Reset session data
router.post('/reset', (req, res) => {
  store.reset();
  res.json({ success: true, message: 'Session data reset successfully.' });
});

module.exports = router;

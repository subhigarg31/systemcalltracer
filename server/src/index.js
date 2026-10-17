const http = require('http');
const express = require('express');
const cors = require('cors');
const config = require('./config');
const store = require('./store');
const wsManager = require('./websocket');
const DetectionEngine = require('./detection/engine');
const simulatorManager = require('./simulatorManager');
const kernelGuard = require('./kernelGuard');
const apiRoutes = require('./routes/api');
const reportRoutes = require('./routes/reports');

const path = require('path');
const fs = require('fs');

const app = express();
app.use(cors());
app.use(express.json());

// Initialize WebSocket Manager & Detection Engine
const detectionEngine = new DetectionEngine(store.settings);
app.set('detectionEngine', detectionEngine);
app.set('wsManager', wsManager);

// Routes
app.use('/api', apiRoutes);
app.use('/api/reports', reportRoutes);

// Serve built frontend if available
const clientDistPath = path.resolve(__dirname, '../../client/dist');
if (fs.existsSync(clientDistPath)) {
  app.use(express.static(clientDistPath));
  app.get('*', (req, res, next) => {
    if (req.path.startsWith('/api')) return next();
    res.sendFile(path.join(clientDistPath, 'index.html'));
  });
}

const server = http.createServer(app);

// Initialize WebSocket
wsManager.init(server, store);

// Setup Simulator Callbacks
simulatorManager.setCallbacks({
  onEvent: (rawEvent) => {
    try {
      const activeAlerts = store.alerts.filter(a => a.status === 'active');
      const { event, newAlerts, risk } = detectionEngine.processEvent(rawEvent, activeAlerts);

      // Store processed event
      store.addEvent(event);

      // Store and broadcast newly triggered alerts
      for (const alert of newAlerts) {
        store.addAlert(alert);
        wsManager.broadcast('ALERT', alert);
      }

      // Update store risk score
      store.updateRiskScore(risk.score, risk.band);

      // Broadcast processed event with detection metadata attached
      wsManager.broadcast('EVENT', event);

      // Broadcast metrics update
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
    } catch (err) {
      console.error('[Event Pipeline Error]', err.message);
    }
  },
  onError: (err) => {
    console.warn('[Simulator Error]', err.message);
  },
  onStatusChange: (status) => {
    store.session.isRunning = status.isRunning;
    store.session.currentMode = status.mode;
    wsManager.broadcast('STATUS_CHANGE', status);
  }
});

// Periodic timer for score decay and heartbeat (every 1000ms)
setInterval(() => {
  const activeAlerts = store.alerts.filter(a => a.status === 'active');
  const decayedRisk = detectionEngine.decayTick(activeAlerts);
  
  if (decayedRisk.score !== store.metrics.currentRiskScore) {
    store.updateRiskScore(decayedRisk.score, decayedRisk.band);
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
}, 1000);

// Graceful termination
function cleanup() {
  console.log('\n[Server] Shutting down gracefully...');
  simulatorManager.stop();
  kernelGuard.stop(); // don't leave bpftrace freezing processes after we exit
  server.close(() => {
    console.log('[Server] HTTP and WebSocket server closed.');
    process.exit(0);
  });
  // Force exit if hanging
  setTimeout(() => process.exit(0), 3000);
}

process.on('SIGINT', cleanup);
process.on('SIGTERM', cleanup);

const PORT = config.port;
server.listen(PORT, () => {
  console.log(`=======================================================`);
  console.log(` System Call Tracer Backend Server`);
  console.log(` REST API running on:     http://localhost:${PORT}`);
  console.log(` WebSocket running on:    ws://localhost:${PORT}`);
  console.log(` Simulator Binary:        ${config.simulatorPath}`);
  console.log(` Default Mode:            ${config.defaultMode}`);
  console.log(`=======================================================`);
});

module.exports = { app, server, detectionEngine, store };

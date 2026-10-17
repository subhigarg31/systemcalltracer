const { WebSocketServer, WebSocket } = require('ws');

// Required lazily: kernelGuard requires this module, so a top-level require would be circular.
function kernelSnapshot() {
  const kernelGuard = require('./kernelGuard');
  return { ...kernelGuard.getStatus(), entries: kernelGuard.getEntries() };
}

class WebSocketManager {
  constructor() {
    this.wss = null;
    this.clients = new Set();
  }

  init(server, store) {
    this.wss = new WebSocketServer({ server });
    this.store = store;

    this.wss.on('connection', (ws, req) => {
      this.clients.add(ws);
      console.log(`[WebSocket] Client connected from ${req.socket.remoteAddress}. Active clients: ${this.clients.size}`);

      // Send initial state snapshot on connection
      const initialPayload = {
        type: 'INITIAL_STATE',
        data: {
          session: this.store.session,
          metrics: {
            totalEvents: this.store.metrics.totalEvents,
            totalAlerts: this.store.metrics.totalAlerts,
            activeAlerts: this.store.metrics.activeAlerts,
            highCritAlerts: this.store.metrics.highCritAlerts,
            currentRiskScore: this.store.metrics.currentRiskScore,
            riskBand: this.store.metrics.riskBand,
            categoryCounts: this.store.metrics.categoryCounts,
            timeSeries: this.store.metrics.timeSeries
          },
          recentEvents: this.store.events.slice(0, 50),
          alerts: this.store.alerts.slice(0, 50),
          processes: this.store.getProcessesList().slice(0, 20),
          kernel: kernelSnapshot()
        },
        timestamp: new Date().toISOString()
      };
      
      ws.send(JSON.stringify(initialPayload));

      ws.on('message', (message) => {
        try {
          const msg = JSON.parse(message);
          if (msg.type === 'PING') {
            ws.send(JSON.stringify({ type: 'PONG', timestamp: new Date().toISOString() }));
          }
        } catch (_) {}
      });

      ws.on('close', () => {
        this.clients.delete(ws);
        console.log(`[WebSocket] Client disconnected. Active clients: ${this.clients.size}`);
      });

      ws.on('error', (err) => {
        console.warn('[WebSocket] Client error:', err.message);
        this.clients.delete(ws);
      });
    });
  }

  broadcast(type, data) {
    if (!this.wss || this.clients.size === 0) return;

    const payload = JSON.stringify({
      type,
      data,
      timestamp: new Date().toISOString()
    });

    for (const client of this.clients) {
      if (client.readyState === WebSocket.OPEN) {
        try {
          client.send(payload);
        } catch (err) {
          console.warn('[WebSocket] Broadcast error:', err.message);
        }
      }
    }
  }

  getConnectedCount() {
    return this.clients.size;
  }
}

const wsManager = new WebSocketManager();
module.exports = wsManager;

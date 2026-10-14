const config = require('./config');

class EventStore {
  constructor() {
    this.events = [];
    this.alerts = [];
    this.processes = new Map();
    this.settings = JSON.parse(JSON.stringify(config));
    this.session = {
      startTime: new Date().toISOString(),
      currentMode: this.settings.defaultMode,
      isRunning: false,
      lastEventTimestamp: null
    };
    this.metrics = {
      totalEvents: 0,
      totalAlerts: 0,
      activeAlerts: 0,
      highCritAlerts: 0,
      currentRiskScore: 0,
      riskBand: 'Low',
      categoryCounts: { file: 0, network: 0, process: 0, memory: 0 },
      syscallCounts: {},
      timeSeries: [] // Array of { time, count, alerts, riskScore }
    };
  }

  reset() {
    this.events = [];
    this.alerts = [];
    this.processes.clear();
    this.session.startTime = new Date().toISOString();
    this.session.lastEventTimestamp = null;
    this.metrics = {
      totalEvents: 0,
      totalAlerts: 0,
      activeAlerts: 0,
      highCritAlerts: 0,
      currentRiskScore: 0,
      riskBand: 'Low',
      categoryCounts: { file: 0, network: 0, process: 0, memory: 0 },
      syscallCounts: {},
      timeSeries: []
    };
  }

  addEvent(event) {
    this.session.lastEventTimestamp = event.timestamp;
    this.metrics.totalEvents++;

    // Track category counts
    const cat = event.category || 'other';
    this.metrics.categoryCounts[cat] = (this.metrics.categoryCounts[cat] || 0) + 1;

    // Track syscall counts
    const sc = event.syscall || 'unknown';
    this.metrics.syscallCounts[sc] = (this.metrics.syscallCounts[sc] || 0) + 1;

    // Track process activity
    const pid = event.pid;
    if (!this.processes.has(pid)) {
      this.processes.set(pid, {
        pid,
        process_name: event.process_name,
        syscallCount: 0,
        fileCount: 0,
        networkCount: 0,
        processCount: 0,
        alertsTriggered: 0,
        firstSeen: event.timestamp,
        lastSeen: event.timestamp
      });
    }

    const proc = this.processes.get(pid);
    proc.syscallCount++;
    proc.lastSeen = event.timestamp;
    if (cat === 'file') proc.fileCount++;
    else if (cat === 'network') proc.networkCount++;
    else if (cat === 'process') proc.processCount++;

    // Store capped list of events
    this.events.unshift(event);
    if (this.events.length > this.settings.maxEventsInMemory) {
      this.events.pop();
    }

    this._updateTimeSeries(event.timestamp);
  }

  addAlert(alert) {
    this.alerts.unshift(alert);
    if (this.alerts.length > this.settings.maxAlertsInMemory) {
      this.alerts.pop();
    }

    this.metrics.totalAlerts++;
    if (alert.status === 'active') {
      this.metrics.activeAlerts++;
    }
    if (alert.severity === 'Critical' || alert.severity === 'High') {
      this.metrics.highCritAlerts++;
    }

    // Attach to process info
    if (this.processes.has(alert.pid)) {
      this.processes.get(alert.pid).alertsTriggered++;
    }
  }

  acknowledgeAlert(alertId) {
    const alert = this.alerts.find(a => a.alertId === alertId);
    if (alert && alert.status === 'active') {
      alert.status = 'acknowledged';
      alert.acknowledgedAt = new Date().toISOString();
      this.metrics.activeAlerts = Math.max(0, this.metrics.activeAlerts - 1);
      return alert;
    }
    return null;
  }

  updateRiskScore(score, band) {
    this.metrics.currentRiskScore = score;
    this.metrics.riskBand = band;
  }

  _updateTimeSeries(timestamp) {
    const now = new Date(timestamp);
    const timeKey = now.toLocaleTimeString('en-US', { hour12: false, hour: '2-digit', minute: '2-digit', second: '2-digit' });
    
    let lastEntry = this.metrics.timeSeries[this.metrics.timeSeries.length - 1];
    if (lastEntry && lastEntry.time === timeKey) {
      lastEntry.count++;
      lastEntry.riskScore = this.metrics.currentRiskScore;
    } else {
      this.metrics.timeSeries.push({
        time: timeKey,
        count: 1,
        alerts: this.metrics.activeAlerts,
        riskScore: this.metrics.currentRiskScore
      });
      // Keep last 30 time slots
      if (this.metrics.timeSeries.length > 30) {
        this.metrics.timeSeries.shift();
      }
    }
  }

  getFilteredEvents({ limit = 100, category, search, pid, severity }) {
    let result = this.events;

    if (category && category !== 'all') {
      result = result.filter(e => e.category === category);
    }

    if (pid) {
      const pidNum = parseInt(pid, 10);
      result = result.filter(e => e.pid === pidNum);
    }

    if (severity && severity !== 'all') {
      if (severity === 'flagged') {
        result = result.filter(e => e.detection && e.detection.flagged);
      } else if (severity === 'normal') {
        result = result.filter(e => !e.detection || !e.detection.flagged);
      }
    }

    if (search) {
      const s = search.toLowerCase();
      result = result.filter(e =>
        e.process_name?.toLowerCase().includes(s) ||
        e.syscall?.toLowerCase().includes(s) ||
        e.pid?.toString().includes(s) ||
        JSON.stringify(e.args || {}).toLowerCase().includes(s)
      );
    }

    return result.slice(0, Math.min(limit, 500));
  }

  getAlerts({ status, severity, search, limit = 100 }) {
    let result = this.alerts;

    if (status && status !== 'all') {
      result = result.filter(a => a.status === status);
    }

    if (severity && severity !== 'all') {
      result = result.filter(a => a.severity.toLowerCase() === severity.toLowerCase());
    }

    if (search) {
      const s = search.toLowerCase();
      result = result.filter(a =>
        a.description?.toLowerCase().includes(s) ||
        a.category?.toLowerCase().includes(s) ||
        a.process_name?.toLowerCase().includes(s) ||
        a.pid?.toString().includes(s)
      );
    }

    return result.slice(0, limit);
  }

  getProcessesList() {
    return Array.from(this.processes.values()).sort((a, b) => b.syscallCount - a.syscallCount);
  }
}

const store = new EventStore();
module.exports = store;

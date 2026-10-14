const express = require('express');
const router = express.Router();
const store = require('../store');

function generateReportData() {
  const now = new Date();
  const sessionStart = new Date(store.session.startTime);
  const durationSec = Math.floor((now.getTime() - sessionStart.getTime()) / 1000);

  const activeAlerts = store.alerts.filter(a => a.status === 'active');
  const acknowledgedAlerts = store.alerts.filter(a => a.status === 'acknowledged');

  const severityCounts = {
    Critical: store.alerts.filter(a => a.severity === 'Critical').length,
    High: store.alerts.filter(a => a.severity === 'High').length,
    Medium: store.alerts.filter(a => a.severity === 'Medium').length,
    Low: store.alerts.filter(a => a.severity === 'Low').length
  };

  return {
    metadata: {
      reportTitle: 'System Call Tracer - Threat Intelligence & Anomaly Report',
      generatedAt: now.toISOString(),
      reportId: `REP-${now.getFullYear()}${(now.getMonth()+1).toString().padStart(2, '0')}${now.getDate().toString().padStart(2, '0')}-${now.getTime().toString().slice(-6)}`,
      sessionStartTime: store.session.startTime,
      sessionDurationSeconds: durationSec,
      sessionDurationFormatted: `${Math.floor(durationSec / 60)}m ${durationSec % 60}s`,
      simulationMode: store.session.currentMode
    },
    executiveSummary: {
      totalEventsProcessed: store.metrics.totalEvents,
      totalAlertsRaised: store.alerts.length,
      activeAlertsCount: activeAlerts.length,
      acknowledgedAlertsCount: acknowledgedAlerts.length,
      currentRiskScore: store.metrics.currentRiskScore,
      riskBand: store.metrics.riskBand,
      severityCounts,
      observedProcessesCount: store.processes.size
    },
    categoryDistribution: store.metrics.categoryCounts,
    syscallDistribution: store.metrics.syscallCounts,
    threatAlerts: store.alerts.map(a => ({
      alertId: a.alertId,
      ruleId: a.ruleId,
      category: a.category,
      severity: a.severity,
      riskScore: a.riskScore !== undefined ? a.riskScore : store.metrics.currentRiskScore,
      riskBand: a.riskBand || store.metrics.riskBand,
      timestamp: a.timestamp,
      pid: a.pid,
      processName: a.process_name,
      description: a.description,
      status: a.status,
      evidence: a.evidence,
      recommendedAction: a.recommendedAction
    })),
    processActivity: store.getProcessesList().slice(0, 50),
    systemLimitations: [
      'This report reflects data processed by the C++ synthetic syscall telemetry simulator on macOS.',
      'Events are structured behavioral simulations and do not represent kernel-level ptrace hooks.',
      'The risk scoring model is a heuristic prototype (0-100) intended for SOC workflow training and evaluation, not an accredited malware certainty index.',
      'Host integrity has remained uncompromised as all suspicious behaviors are simulated safely.'
    ]
  };
}

// GET /api/reports/summary
router.get('/summary', (req, res) => {
  res.json(generateReportData());
});

// GET /api/reports/download?format=json|csv
router.get('/download', (req, res) => {
  const format = (req.query.format || 'json').toLowerCase();
  const data = generateReportData();
  const timestampStr = new Date().toISOString().replace(/[:.]/g, '-');

  if (format === 'json') {
    res.setHeader('Content-Type', 'application/json');
    res.setHeader('Content-Disposition', `attachment; filename="systemcall_threat_report_${timestampStr}.json"`);
    return res.send(JSON.stringify(data, null, 2));
  } else if (format === 'csv') {
    res.setHeader('Content-Type', 'text/csv; charset=utf-8');
    res.setHeader('Content-Disposition', `attachment; filename="systemcall_threat_report_${timestampStr}.csv"`);
    
    let csv = '';
    csv += '--- SYSTEM CALL TRACER ANOMALY REPORT ---\n';
    csv += `Report ID,${data.metadata.reportId}\n`;
    csv += `Generated At,${data.metadata.generatedAt}\n`;
    csv += `Session Duration,${data.metadata.sessionDurationFormatted}\n`;
    csv += `Total Events Processed,${data.executiveSummary.totalEventsProcessed}\n`;
    csv += `Current Risk Score,${data.executiveSummary.currentRiskScore} (${data.executiveSummary.riskBand})\n`;
    csv += `Total Alerts,${data.executiveSummary.totalAlertsRaised}\n`;
    csv += `Critical Alerts,${data.executiveSummary.severityCounts.Critical}\n`;
    csv += `High Alerts,${data.executiveSummary.severityCounts.High}\n`;
    csv += `Medium Alerts,${data.executiveSummary.severityCounts.Medium}\n`;
    csv += `Low Alerts,${data.executiveSummary.severityCounts.Low}\n\n`;

    csv += '--- DETECTED THREAT ALERTS ---\n';
    csv += 'Alert ID,Timestamp,Rule ID,Severity,Risk Score,Category,Process,PID,Status,Description,Evidence Summary,Recommended Action\n';
    
    for (const alert of data.threatAlerts) {
      const evidenceStr = JSON.stringify(alert.evidence || {}).replace(/"/g, '""');
      const desc = (alert.description || '').replace(/"/g, '""');
      const action = (alert.recommendedAction || '').replace(/"/g, '""');
      const rule = alert.ruleId || 'N/A';
      const risk = alert.riskScore !== undefined ? `${alert.riskScore} (${alert.riskBand})` : 'N/A';
      csv += `"${alert.alertId}","${alert.timestamp}","${rule}","${alert.severity}","${risk}","${alert.category}","${alert.processName}",${alert.pid},"${alert.status}","${desc}","${evidenceStr}","${action}"\n`;
    }

    csv += '\n--- OBSERVED PROCESS SUMMARY ---\n';
    csv += 'PID,Process Name,Syscall Count,File Ops,Network Ops,Process Ops,Alerts Triggered,Last Seen\n';
    for (const p of data.processActivity) {
      csv += `${p.pid},"${p.process_name}",${p.syscallCount},${p.fileCount},${p.networkCount},${p.processCount},${p.alertsTriggered},"${p.lastSeen}"\n`;
    }

    return res.send(csv);
  } else {
    return res.status(400).json({ error: 'Unsupported format. Use format=json or format=csv.' });
  }
});

// GET /api/reports/html
router.get('/html', (req, res) => {
  const data = generateReportData();
  const html = `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <title>${data.metadata.reportTitle} - ${data.metadata.reportId}</title>
  <style>
    body {
      font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
      margin: 0;
      padding: 24px;
      color: #1e293b;
      background: #f8fafc;
      line-height: 1.5;
    }
    @media print {
      body { background: #fff; padding: 0; }
      .no-print { display: none !important; }
      .page-break { page-break-before: always; }
    }
    .container { max-width: 900px; margin: 0 auto; background: #fff; padding: 32px; border-radius: 8px; border: 1px solid #e2e8f0; }
    .header { border-bottom: 2px solid #0f172a; padding-bottom: 16px; margin-bottom: 24px; }
    .header-title { font-size: 22px; font-weight: 700; color: #0f172a; margin: 0 0 4px 0; }
    .header-sub { font-size: 13px; color: #64748b; }
    .meta-grid { display: grid; grid-template-columns: repeat(4, 1fr); gap: 12px; margin-bottom: 24px; }
    .meta-card { background: #f1f5f9; padding: 12px; border-radius: 6px; }
    .meta-card label { display: block; font-size: 11px; text-transform: uppercase; color: #64748b; font-weight: 600; }
    .meta-card span { font-size: 18px; font-weight: 700; color: #0f172a; }
    .badge { display: inline-block; padding: 2px 8px; font-size: 11px; font-weight: 700; border-radius: 4px; text-transform: uppercase; }
    .badge-Critical { background: #fee2e2; color: #991b1b; }
    .badge-High { background: #ffedd5; color: #9a3412; }
    .badge-Medium { background: #fef3c7; color: #92400e; }
    .badge-Low { background: #dcfce7; color: #166534; }
    table { width: 100%; border-collapse: collapse; margin-bottom: 24px; font-size: 13px; }
    th { text-align: left; padding: 8px; background: #f8fafc; border-bottom: 2px solid #cbd5e1; font-weight: 600; color: #334155; }
    td { padding: 8px; border-bottom: 1px solid #e2e8f0; vertical-align: top; }
    .code-box { background: #f8fafc; border: 1px solid #e2e8f0; border-radius: 4px; padding: 6px; font-family: monospace; font-size: 11px; color: #0f172a; overflow-x: auto; }
    .section-title { font-size: 16px; font-weight: 700; color: #0f172a; margin: 24px 0 12px 0; padding-bottom: 4px; border-bottom: 1px solid #e2e8f0; }
    .btn { background: #0f172a; color: #fff; border: none; padding: 8px 16px; border-radius: 4px; font-size: 13px; font-weight: 600; cursor: pointer; }
    .btn:hover { background: #334155; }
    .disclaimer { font-size: 12px; color: #64748b; background: #f8fafc; padding: 12px; border-left: 3px solid #cbd5e1; border-radius: 4px; margin-top: 32px; }
  </style>
</head>
<body>
  <div class="container">
    <div class="no-print" style="margin-bottom: 16px; text-align: right;">
      <button class="btn" onclick="window.print()">Print / Save as PDF</button>
    </div>
    <div class="header">
      <h1 class="header-title">${data.metadata.reportTitle}</h1>
      <div class="header-sub">Report ID: <strong>${data.metadata.reportId}</strong> | Generated: ${data.metadata.generatedAt} | Mode: <strong>${data.metadata.simulationMode}</strong></div>
    </div>

    <div class="meta-grid">
      <div class="meta-card">
        <label>Risk Score</label>
        <span style="color: ${data.executiveSummary.currentRiskScore > 74 ? '#dc2626' : data.executiveSummary.currentRiskScore > 49 ? '#ea580c' : '#16a34a'}">
          ${data.executiveSummary.currentRiskScore} / 100 (${data.executiveSummary.riskBand})
        </span>
      </div>
      <div class="meta-card">
        <label>Total Events</label>
        <span>${data.executiveSummary.totalEventsProcessed}</span>
      </div>
      <div class="meta-card">
        <label>Active Alerts</label>
        <span>${data.executiveSummary.activeAlertsCount} / ${data.executiveSummary.totalAlertsRaised}</span>
      </div>
      <div class="meta-card">
        <label>Monitored Processes</label>
        <span>${data.executiveSummary.observedProcessesCount}</span>
      </div>
    </div>

    <div class="section-title">Threat Breakdown by Severity</div>
    <table>
      <thead>
        <tr>
          <th>Severity</th>
          <th>Count</th>
          <th>Threat Weight</th>
          <th>Status</th>
        </tr>
      </thead>
      <tbody>
        <tr>
          <td><span class="badge badge-Critical">Critical</span></td>
          <td><strong>${data.executiveSummary.severityCounts.Critical}</strong></td>
          <td>+35 pts / event</td>
          <td>${data.executiveSummary.severityCounts.Critical > 0 ? 'Requires Immediate Action' : 'Clear'}</td>
        </tr>
        <tr>
          <td><span class="badge badge-High">High</span></td>
          <td><strong>${data.executiveSummary.severityCounts.High}</strong></td>
          <td>+20 pts / event</td>
          <td>${data.executiveSummary.severityCounts.High > 0 ? 'Elevated Threat' : 'Clear'}</td>
        </tr>
        <tr>
          <td><span class="badge badge-Medium">Medium</span></td>
          <td><strong>${data.executiveSummary.severityCounts.Medium}</strong></td>
          <td>+10 pts / event</td>
          <td>${data.executiveSummary.severityCounts.Medium > 0 ? 'Monitored' : 'Clear'}</td>
        </tr>
        <tr>
          <td><span class="badge badge-Low">Low</span></td>
          <td><strong>${data.executiveSummary.severityCounts.Low}</strong></td>
          <td>+5 pts / event</td>
          <td>Operational Info</td>
        </tr>
      </tbody>
    </table>

    <div class="section-title">Detected Threat Alerts (${data.threatAlerts.length})</div>
    ${data.threatAlerts.length === 0 ? '<p style="color: #64748b; font-size: 13px;">No anomalies or threats detected during this monitoring session.</p>' : `
    <table>
      <thead>
        <tr>
          <th>Alert ID & Time</th>
          <th>Rule & Severity</th>
          <th>Risk Score</th>
          <th>Process</th>
          <th>Description & Evidence</th>
          <th>Recommended Action</th>
        </tr>
      </thead>
      <tbody>
        ${data.threatAlerts.map(a => `
        <tr>
          <td style="white-space: nowrap;">
            <strong>${a.alertId}</strong><br>
            <span style="font-size: 11px; color: #64748b;">${new Date(a.timestamp).toLocaleTimeString()}</span>
          </td>
          <td>
            <span style="font-size: 11px; font-weight: 600; color: #475569; display: block;">${a.ruleId || 'Rule N/A'}</span>
            <span class="badge badge-${a.severity}">${a.severity}</span>
          </td>
          <td style="white-space: nowrap; font-weight: 700; color: #0f172a;">
            ${a.riskScore !== undefined ? `${a.riskScore} <span style="font-size: 11px; color: #64748b; font-weight: normal;">(${a.riskBand || ''})</span>` : 'N/A'}
          </td>
          <td><strong>${a.processName}</strong><br><span style="font-size: 11px; color: #64748b;">PID: ${a.pid}</span></td>
          <td>
            <strong>${a.description}</strong>
            <div class="code-box" style="margin-top: 4px;">${JSON.stringify(a.evidence)}</div>
          </td>
          <td style="font-size: 12px; color: #334155;">${a.recommendedAction}</td>
        </tr>
        `).join('')}
      </tbody>
    </table>
    `}

    <div class="section-title">System Scope & Limitations</div>
    <div class="disclaimer">
      <ul>
        ${data.systemLimitations.map(item => `<li>${item}</li>`).join('')}
      </ul>
    </div>
  </div>
</body>
</html>`;

  res.setHeader('Content-Type', 'text/html');
  res.send(html);
});

module.exports = router;

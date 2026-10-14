import React, { useState, useEffect } from 'react';
import { FileText, Download, Printer, ShieldAlert, CheckCircle, Info, RefreshCw } from 'lucide-react';
import { useSystem } from '../context/SystemContext';
import { SeverityBadge } from '../components/StatusBadge';

export default function Reports() {
  const { session } = useSystem();
  const [reportSummary, setReportSummary] = useState(null);
  const [loading, setLoading] = useState(true);

  const fetchSummary = async () => {
    setLoading(true);
    try {
      const res = await fetch('/api/reports/summary');
      if (res.ok) {
        const data = await res.json();
        setReportSummary(data);
      }
    } catch (err) {
      console.error('Error fetching report summary:', err);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchSummary();
  }, []);

  const handleDownload = (format) => {
    window.location.href = `/api/reports/download?format=${format}`;
  };

  const handleOpenPrintable = () => {
    window.open('/api/reports/html', '_blank');
  };

  if (loading) {
    return (
      <div className="p-12 text-center text-xs font-mono text-slate-500">
        Compiling session report data...
      </div>
    );
  }

  if (!reportSummary) {
    return (
      <div className="p-12 text-center text-xs font-mono text-red-400">
        Failed to load session report data. Ensure backend is running.
      </div>
    );
  }

  const { metadata, executiveSummary, threatAlerts, systemLimitations } = reportSummary;

  return (
    <div className="p-6 max-w-7xl mx-auto space-y-6">
      {/* Top Action Bar */}
      <div className="bg-charcoal-850 p-4 rounded-lg border border-charcoal-750 flex flex-col sm:flex-row sm:items-center justify-between gap-4">
        <div>
          <h2 className="text-sm font-bold font-mono text-slate-100 flex items-center gap-2">
            <FileText className="w-4 h-4 text-cyan-400" />
            Security Intelligence & Anomaly Report
          </h2>
          <p className="text-[11px] text-slate-400 font-mono mt-0.5">
            Report ID: <span className="text-cyan-300">{metadata.reportId}</span> &bull; Generated: {new Date(metadata.generatedAt).toLocaleString()}
          </p>
        </div>

        <div className="flex flex-wrap items-center gap-2">
          <button
            onClick={fetchSummary}
            className="px-3 py-1.5 rounded bg-charcoal-900 hover:bg-charcoal-800 text-slate-300 border border-charcoal-700 text-xs font-mono flex items-center gap-1.5 transition-colors"
            title="Refresh Report Data"
          >
            <RefreshCw className="w-3.5 h-3.5" />
            <span>Refresh</span>
          </button>
          <button
            onClick={() => handleDownload('json')}
            className="px-3 py-1.5 rounded bg-charcoal-900 hover:bg-charcoal-800 text-cyan-400 border border-charcoal-700 text-xs font-mono flex items-center gap-1.5 transition-colors"
          >
            <Download className="w-3.5 h-3.5" />
            <span>Export JSON</span>
          </button>
          <button
            onClick={() => handleDownload('csv')}
            className="px-3 py-1.5 rounded bg-charcoal-900 hover:bg-charcoal-800 text-cyan-400 border border-charcoal-700 text-xs font-mono flex items-center gap-1.5 transition-colors"
          >
            <Download className="w-3.5 h-3.5" />
            <span>Export CSV</span>
          </button>
          <button
            onClick={handleOpenPrintable}
            className="px-3.5 py-1.5 rounded bg-cyan-600 hover:bg-cyan-500 text-charcoal-950 font-bold text-xs font-mono flex items-center gap-1.5 transition-colors"
          >
            <Printer className="w-3.5 h-3.5" />
            <span>Printable PDF View</span>
          </button>
        </div>
      </div>

      {/* Executive Summary Cards */}
      <div className="grid grid-cols-2 sm:grid-cols-4 gap-4">
        <div className="p-4 bg-charcoal-850 rounded-lg border border-charcoal-750">
          <span className="text-[10px] font-mono uppercase text-slate-500 block">Current Risk Score</span>
          <span className={`text-2xl font-mono font-bold ${executiveSummary.currentRiskScore > 74 ? 'text-red-400' : executiveSummary.currentRiskScore > 49 ? 'text-orange-400' : 'text-emerald-400'}`}>
            {executiveSummary.currentRiskScore} <span className="text-xs text-slate-500">/ 100</span>
          </span>
          <span className="text-[11px] text-slate-400 block mt-1 font-mono uppercase font-semibold">
            Band: {executiveSummary.riskBand}
          </span>
        </div>

        <div className="p-4 bg-charcoal-850 rounded-lg border border-charcoal-750">
          <span className="text-[10px] font-mono uppercase text-slate-500 block">Total Events Monitored</span>
          <span className="text-2xl font-mono font-bold text-slate-100">
            {executiveSummary.totalEventsProcessed}
          </span>
          <span className="text-[11px] text-slate-500 block mt-1 font-mono">
            Duration: {metadata.sessionDurationFormatted}
          </span>
        </div>

        <div className="p-4 bg-charcoal-850 rounded-lg border border-charcoal-750">
          <span className="text-[10px] font-mono uppercase text-slate-500 block">Total Threat Alerts</span>
          <span className="text-2xl font-mono font-bold text-red-400">
            {executiveSummary.totalAlertsRaised}
          </span>
          <span className="text-[11px] text-slate-500 block mt-1 font-mono">
            Active: {executiveSummary.activeAlertsCount} &bull; Ack: {executiveSummary.acknowledgedAlertsCount}
          </span>
        </div>

        <div className="p-4 bg-charcoal-850 rounded-lg border border-charcoal-750">
          <span className="text-[10px] font-mono uppercase text-slate-500 block">Active Processes</span>
          <span className="text-2xl font-mono font-bold text-cyan-400">
            {executiveSummary.observedProcessesCount}
          </span>
          <span className="text-[11px] text-slate-500 block mt-1 font-mono">
            Mode: {metadata.simulationMode}
          </span>
        </div>
      </div>

      {/* Severity Breakdown Table */}
      <div className="bg-charcoal-850 rounded-lg border border-charcoal-750 p-5 space-y-3">
        <h3 className="text-xs font-semibold uppercase tracking-wider text-slate-300 font-mono">
          Threat Severity Breakdown
        </h3>
        <div className="grid grid-cols-2 sm:grid-cols-4 gap-3 text-xs font-mono">
          <div className="p-3 rounded bg-charcoal-900 border border-charcoal-750">
            <span className="text-slate-500 block text-[10px]">CRITICAL</span>
            <span className="text-lg font-bold text-red-400">{executiveSummary.severityCounts.Critical}</span>
            <span className="text-[10px] text-slate-500 block mt-0.5">+35 pts per occurrence</span>
          </div>
          <div className="p-3 rounded bg-charcoal-900 border border-charcoal-750">
            <span className="text-slate-500 block text-[10px]">HIGH</span>
            <span className="text-lg font-bold text-orange-400">{executiveSummary.severityCounts.High}</span>
            <span className="text-[10px] text-slate-500 block mt-0.5">+20 pts per occurrence</span>
          </div>
          <div className="p-3 rounded bg-charcoal-900 border border-charcoal-750">
            <span className="text-slate-500 block text-[10px]">MEDIUM</span>
            <span className="text-lg font-bold text-amber-400">{executiveSummary.severityCounts.Medium}</span>
            <span className="text-[10px] text-slate-500 block mt-0.5">+10 pts per occurrence</span>
          </div>
          <div className="p-3 rounded bg-charcoal-900 border border-charcoal-750">
            <span className="text-slate-500 block text-[10px]">LOW</span>
            <span className="text-lg font-bold text-emerald-400">{executiveSummary.severityCounts.Low}</span>
            <span className="text-[10px] text-slate-500 block mt-0.5">+5 pts per occurrence</span>
          </div>
        </div>
      </div>

      {/* Detected Threats Ledger */}
      <div className="bg-charcoal-850 rounded-lg border border-charcoal-750 overflow-hidden shadow-sm">
        <div className="p-4 border-b border-charcoal-700/80 flex items-center justify-between">
          <h3 className="text-xs font-semibold uppercase tracking-wider text-slate-300 font-mono">
            Detected Threat Alerts Ledger ({threatAlerts.length})
          </h3>
          <span className="text-[11px] text-slate-500 font-mono">Detailed forensic logs</span>
        </div>

        <div className="overflow-x-auto max-h-96 overflow-y-auto">
          <table className="w-full text-left text-xs font-mono">
            <thead className="bg-charcoal-900 text-slate-400 border-b border-charcoal-700/80 text-[11px] uppercase tracking-wider sticky top-0">
              <tr>
                <th className="py-2.5 px-3">Alert ID</th>
                <th className="py-2.5 px-3">Time</th>
                <th className="py-2.5 px-3">Severity</th>
                <th className="py-2.5 px-3">Category</th>
                <th className="py-2.5 px-3">Process / PID</th>
                <th className="py-2.5 px-3">Evidence Details</th>
                <th className="py-2.5 px-3">Recommended SOC Action</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-charcoal-750">
              {threatAlerts.length === 0 ? (
                <tr>
                  <td colSpan="7" className="py-10 text-center text-slate-500">
                    No anomalies recorded during this session.
                  </td>
                </tr>
              ) : (
                threatAlerts.map((a) => (
                  <tr key={a.alertId} className="hover:bg-charcoal-900/60 transition-colors">
                    <td className="py-2.5 px-3 text-cyan-400 font-semibold whitespace-nowrap">{a.alertId}</td>
                    <td className="py-2.5 px-3 text-slate-400 whitespace-nowrap text-[11px]">{new Date(a.timestamp).toLocaleTimeString()}</td>
                    <td className="py-2.5 px-3 whitespace-nowrap"><SeverityBadge severity={a.severity} /></td>
                    <td className="py-2.5 px-3 text-slate-300 whitespace-nowrap">{a.category}</td>
                    <td className="py-2.5 px-3 whitespace-nowrap text-slate-200">
                      {a.processName} <span className="text-slate-500 text-[11px]">({a.pid})</span>
                    </td>
                    <td className="py-2.5 px-3 text-slate-300 max-w-xs truncate" title={JSON.stringify(a.evidence)}>
                      {a.description}
                    </td>
                    <td className="py-2.5 px-3 text-slate-400 text-[11px] max-w-xs truncate" title={a.recommendedAction}>
                      {a.recommendedAction}
                    </td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </div>
      </div>

      {/* Limitations Statement Box */}
      <div className="bg-charcoal-850 border border-charcoal-750 p-4 rounded-lg space-y-2">
        <div className="flex items-center gap-2 text-slate-300 font-mono text-xs font-semibold uppercase">
          <Info className="w-4 h-4 text-cyan-400" />
          <span>System Scope, Methodology & Detection Limitations</span>
        </div>
        <ul className="text-xs text-slate-400 font-mono space-y-1 list-disc list-inside">
          {systemLimitations.map((lim, idx) => (
            <li key={idx}>{lim}</li>
          ))}
        </ul>
      </div>
    </div>
  );
}

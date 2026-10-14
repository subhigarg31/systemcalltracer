import React from 'react';
import {
  AreaChart, Area, XAxis, YAxis, Tooltip, ResponsiveContainer,
  BarChart, Bar, Cell
} from 'recharts';
import { ShieldAlert, Activity, Cpu, AlertTriangle, ArrowRight } from 'lucide-react';
import RiskGauge from '../components/RiskGauge';
import StatCard from '../components/StatCard';
import { SeverityBadge, CategoryBadge } from '../components/StatusBadge';
import { useSystem } from '../context/SystemContext';

export default function Overview({ onNavigateTab }) {
  const { metrics, alerts, processes, setInspectedAlert } = useSystem();

  // Prepare chart data for Category Distribution
  const categoryChartData = [
    { name: 'File', count: metrics.categoryCounts.file || 0, color: '#06b6d4' },
    { name: 'Network', count: metrics.categoryCounts.network || 0, color: '#a855f7' },
    { name: 'Process', count: metrics.categoryCounts.process || 0, color: '#10b981' },
    { name: 'Memory', count: metrics.categoryCounts.memory || 0, color: '#f59e0b' },
  ];

  const recentAlerts = alerts.slice(0, 5);
  const activeProcesses = processes.slice(0, 5);

  return (
    <div className="space-y-5 p-6 max-w-7xl mx-auto">
      {/* Telemetry & Detection Independence Callout */}
      <div className="bg-charcoal-850/90 border border-charcoal-750 px-4 py-2.5 rounded-lg flex flex-col sm:flex-row sm:items-center justify-between gap-2 text-xs font-mono">
        <div className="flex items-center gap-2">
          <span className="w-2 h-2 rounded-full bg-cyan-400 shrink-0" />
          <span className="text-slate-300">
            <strong className="text-slate-100">Telemetry Mode vs. Independent Detection:</strong> Simulator modes only govern event generation.
          </span>
        </div>
        <div className="text-slate-400 text-[11px]">
          Rules A–D evaluate every syscall strictly on behavior & payload. Zero scenario coupling.
        </div>
      </div>

      {/* Top Banner & Risk Gauge Grid */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-5">
        <div className="lg:col-span-1">
          <RiskGauge score={metrics.currentRiskScore} band={metrics.riskBand} />
        </div>

        <div className="lg:col-span-2 grid grid-cols-2 sm:grid-cols-4 gap-4">
          <StatCard
            label="Total Events"
            value={metrics.totalEvents.toLocaleString()}
            subtext="Live ingested stream"
            icon={Activity}
            valueColor="text-slate-100"
          />
          <StatCard
            label="Active Alerts"
            value={metrics.activeAlerts}
            subtext={metrics.activeAlerts > 0 ? "Requires review" : "All clear"}
            icon={ShieldAlert}
            valueColor={metrics.activeAlerts > 0 ? "text-red-400" : "text-emerald-400"}
            borderColor={metrics.activeAlerts > 0 ? "border-red-900/60" : "border-charcoal-700/60"}
          />
          <StatCard
            label="High / Critical"
            value={metrics.highCritAlerts}
            subtext="Elevated threat events"
            icon={AlertTriangle}
            valueColor={metrics.highCritAlerts > 0 ? "text-orange-400" : "text-slate-300"}
          />
          <StatCard
            label="Monitored Processes"
            value={processes.length}
            subtext="Simulated PIDs active"
            icon={Cpu}
            valueColor="text-cyan-400"
          />
        </div>
      </div>

      {/* Charts Section */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-5">
        {/* Syscall Frequency Over Time Chart */}
        <div className="lg:col-span-2 p-5 rounded-lg bg-charcoal-850 border border-charcoal-750">
          <div className="flex items-center justify-between mb-4">
            <div>
              <h3 className="text-xs font-semibold uppercase tracking-wider text-slate-300 font-mono">
                Syscall Frequency & Risk Evolution
              </h3>
              <p className="text-[11px] text-slate-500 font-mono">Real-time sliding window (last 30 samples)</p>
            </div>
            <div className="flex items-center gap-3 text-[11px] font-mono">
              <span className="flex items-center gap-1.5 text-cyan-400">
                <span className="w-2 h-2 rounded-full bg-cyan-400" /> Event Count
              </span>
              <span className="flex items-center gap-1.5 text-red-400">
                <span className="w-2 h-2 rounded-full bg-red-400" /> Risk Score
              </span>
            </div>
          </div>

          <div className="h-60 w-full">
            {metrics.timeSeries.length === 0 ? (
              <div className="h-full flex items-center justify-center text-xs text-slate-500 font-mono">
                Awaiting telemetry stream... Click 'Start' to begin simulation.
              </div>
            ) : (
              <ResponsiveContainer width="100%" height="100%">
                <AreaChart data={metrics.timeSeries}>
                  <defs>
                    <linearGradient id="eventGrad" x1="0" y1="0" x2="0" y2="1">
                      <stop offset="5%" stopColor="#06b6d4" stopOpacity={0.4} />
                      <stop offset="95%" stopColor="#06b6d4" stopOpacity={0.0} />
                    </linearGradient>
                    <linearGradient id="riskGrad" x1="0" y1="0" x2="0" y2="1">
                      <stop offset="5%" stopColor="#ef4444" stopOpacity={0.4} />
                      <stop offset="95%" stopColor="#ef4444" stopOpacity={0.0} />
                    </linearGradient>
                  </defs>
                  <XAxis dataKey="time" stroke="#475569" fontSize={10} tickLine={false} />
                  <YAxis stroke="#475569" fontSize={10} tickLine={false} />
                  <Tooltip
                    contentStyle={{ backgroundColor: '#0c1017', borderColor: '#334155', fontSize: '11px', fontFamily: 'monospace' }}
                  />
                  <Area type="monotone" dataKey="count" stroke="#06b6d4" fillOpacity={1} fill="url(#eventGrad)" name="Events" />
                  <Area type="monotone" dataKey="riskScore" stroke="#ef4444" fillOpacity={1} fill="url(#riskGrad)" name="Risk Score" />
                </AreaChart>
              </ResponsiveContainer>
            )}
          </div>
        </div>

        {/* Category Distribution Bar Chart */}
        <div className="p-5 rounded-lg bg-charcoal-850 border border-charcoal-750">
          <div className="mb-4">
            <h3 className="text-xs font-semibold uppercase tracking-wider text-slate-300 font-mono">
              Events by Category
            </h3>
            <p className="text-[11px] text-slate-500 font-mono">File, Network, Process, Memory</p>
          </div>

          <div className="h-60 w-full">
            <ResponsiveContainer width="100%" height="100%">
              <BarChart data={categoryChartData} layout="vertical">
                <XAxis type="number" stroke="#475569" fontSize={10} tickLine={false} />
                <YAxis dataKey="name" type="category" stroke="#94a3b8" fontSize={11} tickLine={false} width={60} />
                <Tooltip
                  contentStyle={{ backgroundColor: '#0c1017', borderColor: '#334155', fontSize: '11px', fontFamily: 'monospace' }}
                />
                <Bar dataKey="count" radius={[0, 4, 4, 0]}>
                  {categoryChartData.map((entry, index) => (
                    <Cell key={`cell-${index}`} fill={entry.color} />
                  ))}
                </Bar>
              </BarChart>
            </ResponsiveContainer>
          </div>
        </div>
      </div>

      {/* Lower Grids: Recent Alerts & Monitored Processes */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-5">
        {/* Recent Alerts Feed */}
        <div className="p-5 rounded-lg bg-charcoal-850 border border-charcoal-750">
          <div className="flex items-center justify-between pb-3 mb-3 border-b border-charcoal-700/60">
            <div className="flex items-center gap-2">
              <ShieldAlert className="w-4 h-4 text-red-400" />
              <h3 className="text-xs font-semibold uppercase tracking-wider text-slate-300 font-mono">
                Recent Threat Alerts
              </h3>
            </div>
            <button
              onClick={() => onNavigateTab('alerts')}
              className="text-xs text-cyan-400 hover:text-cyan-300 font-mono flex items-center gap-1 transition-colors"
            >
              <span>View All</span>
              <ArrowRight className="w-3 h-3" />
            </button>
          </div>

          <div className="space-y-2.5">
            {recentAlerts.length === 0 ? (
              <div className="py-8 text-center text-xs text-slate-500 font-mono">
                No alerts detected. Operational baseline stable.
              </div>
            ) : (
              recentAlerts.map((alert) => (
                <div
                  key={alert.alertId}
                  onClick={() => setInspectedAlert(alert)}
                  className="p-3 rounded bg-charcoal-900 border border-charcoal-750 hover:border-charcoal-600 transition-colors cursor-pointer flex items-center justify-between gap-3 text-xs"
                >
                  <div className="space-y-1">
                    <div className="flex items-center gap-2">
                      <SeverityBadge severity={alert.severity} />
                      <span className="font-mono text-slate-200 font-medium truncate max-w-xs">
                        {alert.name || alert.description}
                      </span>
                    </div>
                    <div className="text-[11px] text-slate-500 font-mono">
                      PID: {alert.pid} ({alert.process_name}) &bull; {new Date(alert.timestamp).toLocaleTimeString()}
                    </div>
                  </div>
                  <span className={`text-[10px] uppercase font-mono px-1.5 py-0.5 rounded font-bold ${
                    alert.status === 'active' ? 'text-red-400 bg-red-950/60' : 'text-slate-400 bg-slate-800'
                  }`}>
                    {alert.status}
                  </span>
                </div>
              ))
            )}
          </div>
        </div>

        {/* Process Activity Summary */}
        <div className="p-5 rounded-lg bg-charcoal-850 border border-charcoal-750">
          <div className="flex items-center justify-between pb-3 mb-3 border-b border-charcoal-700/60">
            <div className="flex items-center gap-2">
              <Cpu className="w-4 h-4 text-cyan-400" />
              <h3 className="text-xs font-semibold uppercase tracking-wider text-slate-300 font-mono">
                Active Processes
              </h3>
            </div>
            <button
              onClick={() => onNavigateTab('processes')}
              className="text-xs text-cyan-400 hover:text-cyan-300 font-mono flex items-center gap-1 transition-colors"
            >
              <span>View All</span>
              <ArrowRight className="w-3 h-3" />
            </button>
          </div>

          <div className="overflow-x-auto">
            <table className="w-full text-left text-xs font-mono">
              <thead>
                <tr className="text-slate-500 border-b border-charcoal-700/60 text-[10px] uppercase">
                  <th className="pb-2">Process</th>
                  <th className="pb-2">PID</th>
                  <th className="pb-2 text-right">Syscalls</th>
                  <th className="pb-2 text-right">Alerts</th>
                  <th className="pb-2 text-right">Last Seen</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-charcoal-750">
                {activeProcesses.length === 0 ? (
                  <tr>
                    <td colSpan="5" className="py-8 text-center text-slate-500">
                      No process telemetry received yet.
                    </td>
                  </tr>
                ) : (
                  activeProcesses.map((proc) => (
                    <tr key={proc.pid} className="hover:bg-charcoal-900/40">
                      <td className="py-2.5 text-slate-200 font-semibold">{proc.process_name}</td>
                      <td className="py-2.5 text-slate-400">{proc.pid}</td>
                      <td className="py-2.5 text-right text-cyan-400">{proc.syscallCount}</td>
                      <td className="py-2.5 text-right font-bold">
                        {proc.alertsTriggered > 0 ? (
                          <span className="text-red-400">{proc.alertsTriggered}</span>
                        ) : (
                          <span className="text-slate-600">0</span>
                        )}
                      </td>
                      <td className="py-2.5 text-right text-slate-500 text-[11px]">
                        {new Date(proc.lastSeen).toLocaleTimeString()}
                      </td>
                    </tr>
                  ))
                )}
              </tbody>
            </table>
          </div>
        </div>
      </div>
    </div>
  );
}

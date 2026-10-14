import React, { useState, useMemo } from 'react';
import { ShieldAlert, Search, Filter, CheckCircle2, AlertOctagon, ExternalLink } from 'lucide-react';
import { SeverityBadge } from '../components/StatusBadge';
import { useSystem } from '../context/SystemContext';

export default function Alerts() {
  const { alerts, acknowledgeAlert, setInspectedAlert } = useSystem();

  const [statusFilter, setStatusFilter] = useState('all');
  const [severityFilter, setSeverityFilter] = useState('all');
  const [searchTerm, setSearchTerm] = useState('');

  const filteredAlerts = useMemo(() => {
    return alerts.filter((a) => {
      if (statusFilter !== 'all' && a.status !== statusFilter) return false;
      if (severityFilter !== 'all' && a.severity.toLowerCase() !== severityFilter.toLowerCase()) return false;
      if (searchTerm.trim()) {
        const s = searchTerm.toLowerCase();
        return (
          a.description?.toLowerCase().includes(s) ||
          a.category?.toLowerCase().includes(s) ||
          a.process_name?.toLowerCase().includes(s) ||
          a.alertId?.toLowerCase().includes(s) ||
          a.pid?.toString().includes(s)
        );
      }
      return true;
    });
  }, [alerts, statusFilter, severityFilter, searchTerm]);

  const activeCount = alerts.filter(a => a.status === 'active').length;
  const ackCount = alerts.filter(a => a.status === 'acknowledged').length;
  const critCount = alerts.filter(a => a.severity === 'Critical').length;
  const highCount = alerts.filter(a => a.severity === 'High').length;

  return (
    <div className="p-6 max-w-7xl mx-auto space-y-4">
      {/* Alert Stats Strip */}
      <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
        <div className="p-3 bg-charcoal-850 border border-charcoal-750 rounded-lg">
          <span className="text-[10px] font-mono uppercase text-slate-500 block">Active Alerts</span>
          <span className={`text-xl font-mono font-bold ${activeCount > 0 ? 'text-red-400' : 'text-slate-300'}`}>
            {activeCount}
          </span>
        </div>
        <div className="p-3 bg-charcoal-850 border border-charcoal-750 rounded-lg">
          <span className="text-[10px] font-mono uppercase text-slate-500 block">Critical Threats</span>
          <span className={`text-xl font-mono font-bold ${critCount > 0 ? 'text-red-500' : 'text-slate-300'}`}>
            {critCount}
          </span>
        </div>
        <div className="p-3 bg-charcoal-850 border border-charcoal-750 rounded-lg">
          <span className="text-[10px] font-mono uppercase text-slate-500 block">High Threats</span>
          <span className={`text-xl font-mono font-bold ${highCount > 0 ? 'text-orange-400' : 'text-slate-300'}`}>
            {highCount}
          </span>
        </div>
        <div className="p-3 bg-charcoal-850 border border-charcoal-750 rounded-lg">
          <span className="text-[10px] font-mono uppercase text-slate-500 block">Acknowledged</span>
          <span className="text-xl font-mono font-bold text-slate-400">
            {ackCount}
          </span>
        </div>
      </div>

      {/* Filter and Search Bar */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 bg-charcoal-850 p-4 rounded-lg border border-charcoal-750">
        <div className="flex flex-wrap items-center gap-3">
          {/* Status Filter */}
          <div className="flex items-center gap-1.5 bg-charcoal-900 border border-charcoal-700 px-2.5 py-1 rounded text-xs font-mono">
            <Filter className="w-3.5 h-3.5 text-slate-500" />
            <select
              value={statusFilter}
              onChange={(e) => setStatusFilter(e.target.value)}
              className="bg-transparent text-slate-300 focus:outline-none cursor-pointer"
            >
              <option value="all" className="bg-charcoal-900">All Statuses ({alerts.length})</option>
              <option value="active" className="bg-charcoal-900">Active Only ({activeCount})</option>
              <option value="acknowledged" className="bg-charcoal-900">Acknowledged ({ackCount})</option>
            </select>
          </div>

          {/* Severity Filter */}
          <div className="flex items-center gap-1.5 bg-charcoal-900 border border-charcoal-700 px-2.5 py-1 rounded text-xs font-mono">
            <select
              value={severityFilter}
              onChange={(e) => setSeverityFilter(e.target.value)}
              className="bg-transparent text-slate-300 focus:outline-none cursor-pointer"
            >
              <option value="all" className="bg-charcoal-900">All Severities</option>
              <option value="critical" className="bg-charcoal-900">Critical</option>
              <option value="high" className="bg-charcoal-900">High</option>
              <option value="medium" className="bg-charcoal-900">Medium</option>
              <option value="low" className="bg-charcoal-900">Low</option>
            </select>
          </div>
        </div>

        {/* Search Input */}
        <div className="relative min-w-56">
          <Search className="w-4 h-4 text-slate-500 absolute left-2.5 top-2.5" />
          <input
            type="text"
            placeholder="Search alerts, description, PID..."
            value={searchTerm}
            onChange={(e) => setSearchTerm(e.target.value)}
            className="w-full bg-charcoal-900 border border-charcoal-700 rounded pl-8 pr-3 py-1.5 text-xs text-slate-200 placeholder-slate-500 focus:outline-none focus:border-cyan-500 font-mono"
          />
        </div>
      </div>

      {/* Alerts Table */}
      <div className="bg-charcoal-850 rounded-lg border border-charcoal-750 overflow-hidden shadow-sm">
        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs font-mono">
            <thead className="bg-charcoal-900 text-slate-400 border-b border-charcoal-700/80 text-[11px] uppercase tracking-wider">
              <tr>
                <th className="py-2.5 px-3">Alert ID</th>
                <th className="py-2.5 px-3">Timestamp</th>
                <th className="py-2.5 px-3">Rule</th>
                <th className="py-2.5 px-3">Severity</th>
                <th className="py-2.5 px-3">Risk Score</th>
                <th className="py-2.5 px-3">Category</th>
                <th className="py-2.5 px-3">Process / PID</th>
                <th className="py-2.5 px-3">Threat Description</th>
                <th className="py-2.5 px-3 text-center">Status</th>
                <th className="py-2.5 px-3 text-right">Actions</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-charcoal-750">
              {filteredAlerts.length === 0 ? (
                <tr>
                  <td colSpan="10" className="py-12 text-center text-slate-500 font-mono">
                    {alerts.length === 0
                      ? "No threat alerts recorded in this session. Monitoring baseline stream (threat patterns evaluated independently)."
                      : "No alerts match the selected filters."}
                  </td>
                </tr>
              ) : (
                filteredAlerts.map((a) => {
                  const isActive = a.status === 'active';
                  const rowBorder = isActive
                    ? a.severity === 'Critical'
                      ? 'border-l-2 border-red-500'
                      : 'border-l-2 border-orange-500'
                    : '';

                  return (
                    <tr
                      key={a.alertId}
                      onClick={() => setInspectedAlert(a)}
                      className={`cursor-pointer hover:bg-charcoal-900/60 transition-colors ${rowBorder}`}
                    >
                      <td className="py-2.5 px-3 text-cyan-400 font-semibold whitespace-nowrap">
                        {a.alertId}
                      </td>
                      <td className="py-2.5 px-3 text-slate-400 text-[11px] whitespace-nowrap">
                        {new Date(a.timestamp).toLocaleTimeString()}
                      </td>
                      <td className="py-2.5 px-3 whitespace-nowrap">
                        <span className="text-[11px] px-1.5 py-0.5 rounded bg-charcoal-900 border border-charcoal-700 text-slate-300">
                          {a.ruleId ? a.ruleId.replace('RULE_', '').replace(/_/g, ' ') : 'HEURISTIC'}
                        </span>
                      </td>
                      <td className="py-2.5 px-3 whitespace-nowrap">
                        <SeverityBadge severity={a.severity} />
                      </td>
                      <td className="py-2.5 px-3 whitespace-nowrap">
                        <span className={`font-bold text-[11px] px-1.5 py-0.5 rounded ${
                          (a.riskScore || 0) >= 75 ? 'text-red-400 bg-red-950/70 border border-red-800/60' :
                          (a.riskScore || 0) >= 50 ? 'text-orange-400 bg-orange-950/70 border border-orange-800/60' :
                          'text-amber-400 bg-amber-950/70 border border-amber-800/60'
                        }`}>
                          {a.riskScore !== undefined ? `${a.riskScore} (${a.riskBand || 'Risk'})` : '--'}
                        </span>
                      </td>
                      <td className="py-2.5 px-3 text-slate-300 whitespace-nowrap">
                        {a.category}
                      </td>
                      <td className="py-2.5 px-3 whitespace-nowrap">
                        <span className="text-slate-200 font-semibold">{a.process_name}</span>
                        <span className="text-slate-500 text-[11px] ml-1.5">({a.pid})</span>
                      </td>
                      <td className="py-2.5 px-3 text-slate-300 max-w-sm truncate" title={a.description}>
                        {a.description}
                      </td>
                      <td className="py-2.5 px-3 text-center whitespace-nowrap">
                        <span
                          className={`text-[10px] font-bold uppercase px-2 py-0.5 rounded ${
                            isActive
                              ? 'bg-red-950/80 text-red-400 border border-red-800/60'
                              : 'bg-slate-800 text-slate-400 border border-slate-700'
                          }`}
                        >
                          {a.status}
                        </span>
                      </td>
                      <td className="py-2.5 px-3 text-right whitespace-nowrap" onClick={(e) => e.stopPropagation()}>
                        <div className="flex items-center justify-end gap-2">
                          {isActive && (
                            <button
                              onClick={() => acknowledgeAlert(a.alertId)}
                              className="px-2 py-1 bg-emerald-950 text-emerald-400 hover:bg-emerald-900 border border-emerald-800/60 rounded text-[11px] font-mono flex items-center gap-1 transition-colors"
                              title="Acknowledge Alert"
                            >
                              <CheckCircle2 className="w-3 h-3" />
                              <span>Ack</span>
                            </button>
                          )}
                          <button
                            onClick={() => setInspectedAlert(a)}
                            className="p-1 text-slate-400 hover:text-cyan-400 transition-colors"
                            title="Inspect Evidence"
                          >
                            <ExternalLink className="w-3.5 h-3.5" />
                          </button>
                        </div>
                      </td>
                    </tr>
                  );
                })
              )}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
}

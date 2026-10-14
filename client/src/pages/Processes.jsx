import React, { useState, useMemo } from 'react';
import { Cpu, Search, AlertTriangle, ShieldCheck } from 'lucide-react';
import { useSystem } from '../context/SystemContext';

export default function Processes() {
  const { processes } = useSystem();
  const [searchTerm, setSearchTerm] = useState('');
  const [alertFilter, setAlertFilter] = useState('all');

  const filteredProcesses = useMemo(() => {
    return processes.filter((p) => {
      if (alertFilter === 'flagged' && p.alertsTriggered === 0) return false;
      if (alertFilter === 'clean' && p.alertsTriggered > 0) return false;

      if (searchTerm.trim()) {
        const s = searchTerm.toLowerCase();
        return p.process_name?.toLowerCase().includes(s) || p.pid?.toString().includes(s);
      }
      return true;
    });
  }, [processes, alertFilter, searchTerm]);

  return (
    <div className="p-6 max-w-7xl mx-auto space-y-4">
      {/* Banner explicitly clarifying simulated process telemetry */}
      <div className="bg-charcoal-850 border border-charcoal-700/80 p-4 rounded-lg flex items-center justify-between">
        <div className="flex items-center gap-3">
          <Cpu className="w-5 h-5 text-cyan-400" />
          <div>
            <h3 className="text-xs font-semibold uppercase tracking-wider text-slate-200 font-mono">
              Simulated Process Activity Ledger
            </h3>
            <p className="text-[11px] text-slate-400 font-mono">
              Observed execution contexts from the C++ simulator engine. (Safe synthetic telemetry)
            </p>
          </div>
        </div>
        <span className="text-xs font-mono font-medium px-2.5 py-1 rounded bg-charcoal-900 border border-charcoal-750 text-slate-300">
          Total Processes: {processes.length}
        </span>
      </div>

      {/* Filter and Search Bar */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 bg-charcoal-850 p-4 rounded-lg border border-charcoal-750">
        <div className="flex items-center gap-2">
          <span className="text-xs font-mono text-slate-400">Filter:</span>
          <select
            value={alertFilter}
            onChange={(e) => setAlertFilter(e.target.value)}
            className="bg-charcoal-900 border border-charcoal-700 text-slate-300 px-2.5 py-1 rounded text-xs font-mono focus:outline-none cursor-pointer"
          >
            <option value="all">All Processes ({processes.length})</option>
            <option value="flagged">Processes with Alerts ({processes.filter(p => p.alertsTriggered > 0).length})</option>
            <option value="clean">Nominal Baseline Processes ({processes.filter(p => p.alertsTriggered === 0).length})</option>
          </select>
        </div>

        <div className="relative min-w-56">
          <Search className="w-4 h-4 text-slate-500 absolute left-2.5 top-2.5" />
          <input
            type="text"
            placeholder="Search process name or PID..."
            value={searchTerm}
            onChange={(e) => setSearchTerm(e.target.value)}
            className="w-full bg-charcoal-900 border border-charcoal-700 rounded pl-8 pr-3 py-1.5 text-xs text-slate-200 placeholder-slate-500 focus:outline-none focus:border-cyan-500 font-mono"
          />
        </div>
      </div>

      {/* Processes Table */}
      <div className="bg-charcoal-850 rounded-lg border border-charcoal-750 overflow-hidden shadow-sm">
        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs font-mono">
            <thead className="bg-charcoal-900 text-slate-400 border-b border-charcoal-700/80 text-[11px] uppercase tracking-wider">
              <tr>
                <th className="py-2.5 px-3">Process Name</th>
                <th className="py-2.5 px-3">PID</th>
                <th className="py-2.5 px-3 text-right">Total Syscalls</th>
                <th className="py-2.5 px-3 text-right">File Ops</th>
                <th className="py-2.5 px-3 text-right">Network Ops</th>
                <th className="py-2.5 px-3 text-right">Process Ops</th>
                <th className="py-2.5 px-3 text-center">Threat Alerts</th>
                <th className="py-2.5 px-3">First Seen</th>
                <th className="py-2.5 px-3 text-right">Last Seen</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-charcoal-750">
              {filteredProcesses.length === 0 ? (
                <tr>
                  <td colSpan="9" className="py-12 text-center text-slate-500 font-mono">
                    {processes.length === 0
                      ? "No process telemetry received yet. Run simulator to capture processes."
                      : "No processes match the search criteria."}
                  </td>
                </tr>
              ) : (
                filteredProcesses.map((p) => {
                  const hasAlerts = p.alertsTriggered > 0;
                  return (
                    <tr
                      key={p.pid}
                      className={`hover:bg-charcoal-900/60 transition-colors ${
                        hasAlerts ? 'bg-red-950/20 border-l-2 border-red-500' : ''
                      }`}
                    >
                      <td className="py-2.5 px-3 text-slate-100 font-semibold whitespace-nowrap">
                        {p.process_name}
                      </td>
                      <td className="py-2.5 px-3 text-slate-400 whitespace-nowrap">
                        {p.pid}
                      </td>
                      <td className="py-2.5 px-3 text-right text-cyan-400 font-bold">
                        {p.syscallCount}
                      </td>
                      <td className="py-2.5 px-3 text-right text-slate-300">
                        {p.fileCount}
                      </td>
                      <td className="py-2.5 px-3 text-right text-slate-300">
                        {p.networkCount}
                      </td>
                      <td className="py-2.5 px-3 text-right text-slate-300">
                        {p.processCount}
                      </td>
                      <td className="py-2.5 px-3 text-center whitespace-nowrap">
                        {hasAlerts ? (
                          <span className="inline-flex items-center gap-1 text-red-400 font-bold bg-red-950/80 px-2 py-0.5 rounded border border-red-800/60">
                            <AlertTriangle className="w-3 h-3" />
                            {p.alertsTriggered} Alerts
                          </span>
                        ) : (
                          <span className="inline-flex items-center gap-1 text-emerald-400 bg-emerald-950/60 px-2 py-0.5 rounded border border-emerald-800/50">
                            <ShieldCheck className="w-3 h-3" />
                            Clean
                          </span>
                        )}
                      </td>
                      <td className="py-2.5 px-3 text-slate-500 text-[11px] whitespace-nowrap">
                        {new Date(p.firstSeen).toLocaleTimeString()}
                      </td>
                      <td className="py-2.5 px-3 text-right text-slate-400 text-[11px] whitespace-nowrap">
                        {new Date(p.lastSeen).toLocaleTimeString()}
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

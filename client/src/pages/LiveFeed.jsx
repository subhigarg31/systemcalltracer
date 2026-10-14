import React, { useState, useMemo } from 'react';
import { Search, Pause, Play, Filter, AlertTriangle, Terminal, Maximize2 } from 'lucide-react';
import { CategoryBadge, SeverityBadge } from '../components/StatusBadge';
import { useSystem } from '../context/SystemContext';

export default function LiveFeed() {
  const {
    events,
    isPaused,
    pausedBufferCount,
    togglePause,
    maxDisplayRows,
    setMaxDisplayRows,
    setInspectedEvent
  } = useSystem();

  const [searchTerm, setSearchTerm] = useState('');
  const [selectedCategory, setSelectedCategory] = useState('all');
  const [selectedSeverity, setSelectedSeverity] = useState('all');

  const filteredEvents = useMemo(() => {
    return events.filter((ev) => {
      // Category filter
      if (selectedCategory !== 'all' && ev.category !== selectedCategory) {
        return false;
      }

      // Flagged / Normal filter
      if (selectedSeverity === 'flagged' && !ev.detection?.flagged) {
        return false;
      }
      if (selectedSeverity === 'normal' && ev.detection?.flagged) {
        return false;
      }

      // Search term
      if (searchTerm.trim()) {
        const s = searchTerm.toLowerCase();
        const proc = ev.process_name?.toLowerCase() || '';
        const sc = ev.syscall?.toLowerCase() || '';
        const pid = ev.pid?.toString() || '';
        const argsStr = JSON.stringify(ev.args || {}).toLowerCase();
        return proc.includes(s) || sc.includes(s) || pid.includes(s) || argsStr.includes(s);
      }

      return true;
    });
  }, [events, selectedCategory, selectedSeverity, searchTerm]);

  const renderArgsSummary = (args) => {
    if (!args || Object.keys(args).length === 0) return '-';
    if (args.path) return args.path;
    if (args.target) return args.target;
    if (args.addr) return `${args.addr}:${args.port || ''}`;
    if (args.filename) return args.filename;
    if (args.bytes) return `${args.bytes} bytes`;
    // Fallback: key=value
    return Object.entries(args).map(([k, v]) => `${k}=${v}`).join(', ');
  };

  return (
    <div className="p-6 max-w-7xl mx-auto space-y-4">
      {/* Controls & Search Header */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-3 bg-charcoal-850 p-4 rounded-lg border border-charcoal-750">
        <div className="flex flex-wrap items-center gap-3">
          {/* Pause / Resume display toggle */}
          <button
            onClick={togglePause}
            className={`flex items-center gap-2 px-3 py-1.5 rounded text-xs font-mono font-medium transition-colors border ${
              isPaused
                ? 'bg-amber-950/80 text-amber-300 border-amber-800 hover:bg-amber-900'
                : 'bg-charcoal-900 text-slate-300 border-charcoal-700 hover:bg-charcoal-800'
            }`}
          >
            {isPaused ? (
              <>
                <Play className="w-3.5 h-3.5 fill-current" />
                <span>Resume Feed</span>
                {pausedBufferCount > 0 && (
                  <span className="bg-amber-500 text-black px-1.5 py-0.2 rounded-full text-[10px] font-bold">
                    +{pausedBufferCount} buffered
                  </span>
                )}
              </>
            ) : (
              <>
                <Pause className="w-3.5 h-3.5" />
                <span>Pause Feed</span>
              </>
            )}
          </button>

          {/* Category Filter */}
          <div className="flex items-center gap-1.5 bg-charcoal-900 border border-charcoal-700 px-2.5 py-1 rounded text-xs font-mono">
            <Filter className="w-3.5 h-3.5 text-slate-500" />
            <select
              value={selectedCategory}
              onChange={(e) => setSelectedCategory(e.target.value)}
              className="bg-transparent text-slate-300 focus:outline-none cursor-pointer"
            >
              <option value="all" className="bg-charcoal-900">All Categories</option>
              <option value="file" className="bg-charcoal-900">File</option>
              <option value="network" className="bg-charcoal-900">Network</option>
              <option value="process" className="bg-charcoal-900">Process</option>
              <option value="memory" className="bg-charcoal-900">Memory</option>
            </select>
          </div>

          {/* Severity Filter */}
          <div className="flex items-center gap-1.5 bg-charcoal-900 border border-charcoal-700 px-2.5 py-1 rounded text-xs font-mono">
            <select
              value={selectedSeverity}
              onChange={(e) => setSelectedSeverity(e.target.value)}
              className="bg-transparent text-slate-300 focus:outline-none cursor-pointer"
            >
              <option value="all" className="bg-charcoal-900">All Statuses</option>
              <option value="flagged" className="bg-charcoal-900">Flagged Anomalies Only</option>
              <option value="normal" className="bg-charcoal-900">Normal Only</option>
            </select>
          </div>

          {/* Buffer Capacity */}
          <div className="flex items-center gap-1.5 text-xs font-mono text-slate-400">
            <span>Buffer:</span>
            <select
              value={maxDisplayRows}
              onChange={(e) => setMaxDisplayRows(parseInt(e.target.value, 10))}
              className="bg-charcoal-900 border border-charcoal-700 px-2 py-1 rounded text-slate-300 focus:outline-none"
            >
              <option value="100">100 rows</option>
              <option value="250">250 rows</option>
              <option value="500">500 rows</option>
            </select>
          </div>
        </div>

        {/* Search Input */}
        <div className="relative min-w-56">
          <Search className="w-4 h-4 text-slate-500 absolute left-2.5 top-2.5" />
          <input
            type="text"
            placeholder="Search process, syscall, PID..."
            value={searchTerm}
            onChange={(e) => setSearchTerm(e.target.value)}
            className="w-full bg-charcoal-900 border border-charcoal-700 rounded pl-8 pr-3 py-1.5 text-xs text-slate-200 placeholder-slate-500 focus:outline-none focus:border-cyan-500 font-mono"
          />
        </div>
      </div>

      {/* Syscall Events Table */}
      <div className="bg-charcoal-850 rounded-lg border border-charcoal-750 overflow-hidden shadow-sm">
        <div className="overflow-x-auto max-h-[calc(100vh-250px)] overflow-y-auto">
          <table className="w-full text-left text-xs font-mono">
            <thead className="bg-charcoal-900 text-slate-400 sticky top-0 z-10 border-b border-charcoal-700/80 text-[11px] uppercase tracking-wider">
              <tr>
                <th className="py-2.5 px-3">Timestamp</th>
                <th className="py-2.5 px-3">PID</th>
                <th className="py-2.5 px-3">Process</th>
                <th className="py-2.5 px-3">Syscall</th>
                <th className="py-2.5 px-3">Arguments Summary</th>
                <th className="py-2.5 px-3 text-center">Ret</th>
                <th className="py-2.5 px-3">Category</th>
                <th className="py-2.5 px-3 text-center">Anomaly Flag</th>
                <th className="py-2.5 px-3 text-right">Inspect</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-charcoal-750">
              {filteredEvents.length === 0 ? (
                <tr>
                  <td colSpan="9" className="py-12 text-center text-slate-500 font-mono">
                    {events.length === 0
                      ? "No events captured yet. Click 'Start' in the top bar to run simulator."
                      : "No events match the selected search or filter criteria."}
                  </td>
                </tr>
              ) : (
                filteredEvents.map((ev, index) => {
                  const isFlagged = ev.detection?.flagged;
                  const rowBg = isFlagged
                    ? 'bg-red-950/20 hover:bg-red-950/40 border-l-2 border-red-500'
                    : 'hover:bg-charcoal-900/60';

                  return (
                    <tr
                      key={`${ev.timestamp}-${index}`}
                      onClick={() => setInspectedEvent(ev)}
                      className={`cursor-pointer transition-colors ${rowBg}`}
                    >
                      <td className="py-2 px-3 text-slate-400 text-[11px] whitespace-nowrap">
                        {new Date(ev.timestamp).toLocaleTimeString()}
                      </td>
                      <td className="py-2 px-3 text-slate-400 whitespace-nowrap font-mono">
                        {ev.pid}
                      </td>
                      <td className="py-2 px-3 text-slate-200 font-semibold whitespace-nowrap">
                        {ev.process_name}
                      </td>
                      <td className="py-2 px-3 font-bold text-cyan-300 whitespace-nowrap">
                        {ev.syscall}
                      </td>
                      <td className="py-2 px-3 text-slate-300 max-w-xs truncate" title={JSON.stringify(ev.args)}>
                        {renderArgsSummary(ev.args)}
                      </td>
                      <td className={`py-2 px-3 text-center ${ev.ret < 0 ? 'text-red-400 font-bold' : 'text-slate-400'}`}>
                        {ev.ret}
                      </td>
                      <td className="py-2 px-3 whitespace-nowrap">
                        <CategoryBadge category={ev.category} />
                      </td>
                      <td className="py-2 px-3 text-center whitespace-nowrap">
                        {isFlagged ? (
                          <SeverityBadge severity={ev.detection.highestSeverity || 'High'} />
                        ) : (
                          <span className="text-slate-600 text-[11px]">-</span>
                        )}
                      </td>
                      <td className="py-2 px-3 text-right">
                        <button
                          onClick={(e) => {
                            e.stopPropagation();
                            setInspectedEvent(ev);
                          }}
                          className="p-1 text-slate-500 hover:text-cyan-400 rounded transition-colors"
                          title="Inspect JSON"
                        >
                          <Maximize2 className="w-3.5 h-3.5" />
                        </button>
                      </td>
                    </tr>
                  );
                })
              )}
            </tbody>
          </table>
        </div>
        <div className="px-4 py-2 bg-charcoal-900 border-t border-charcoal-700/80 text-[11px] font-mono text-slate-500 flex justify-between items-center">
          <span>Showing {filteredEvents.length} of {events.length} buffered events</span>
          <span>Click any row to open JSON forensic drawer</span>
        </div>
      </div>
    </div>
  );
}

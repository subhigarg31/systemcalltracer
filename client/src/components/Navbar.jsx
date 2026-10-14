import React from 'react';
import { Play, Square, RefreshCw, Activity, Radio } from 'lucide-react';
import { useSystem } from '../context/SystemContext';

export default function Navbar() {
  const {
    connectionStatus,
    session,
    startSimulation,
    stopSimulation,
    setSimulationMode,
    resetSession
  } = useSystem();

  const handleModeChange = (e) => {
    const newMode = e.target.value;
    setSimulationMode(newMode);
  };

  const handleToggleRunning = () => {
    if (session.isRunning) {
      stopSimulation();
    } else {
      startSimulation(session.currentMode || 'automatic');
    }
  };

  return (
    <header className="h-14 bg-charcoal-900 border-b border-charcoal-700/80 px-4 flex items-center justify-between text-xs sticky top-0 z-40">
      {/* Brand & Connection Status */}
      <div className="flex items-center gap-3">
        <div className="flex items-center gap-2 font-mono font-bold text-slate-100 tracking-tight text-sm">
          <Activity className="w-4 h-4 text-emerald-400" />
          <span>SysCall<span className="text-cyan-400">Tracer</span></span>
          <span className="text-slate-600 font-normal hidden sm:inline">|</span>
          <span className="text-slate-400 text-xs font-normal hidden sm:inline">Anomaly Engine</span>
        </div>

        {/* Live WS Status Indicator */}
        <div className="flex items-center gap-1.5 px-2 py-0.5 rounded bg-charcoal-850 border border-charcoal-750 font-mono text-[11px]">
          <span
            className={`w-2 h-2 rounded-full ${
              connectionStatus === 'connected'
                ? 'bg-emerald-400 animate-pulse-subtle'
                : 'bg-red-500'
            }`}
          />
          <span className="text-slate-300 capitalize">{connectionStatus}</span>
        </div>
      </div>

      {/* Center / Controls */}
      <div className="flex items-center gap-2.5">
        {/* Scenario selector */}
        <div className="flex items-center gap-1.5 bg-charcoal-850 border border-charcoal-700 px-2.5 py-1 rounded" title="Telemetry generation pattern. Threat rules evaluate events independently.">
          <Radio className="w-3.5 h-3.5 text-slate-400" />
          <span className="text-slate-400 font-mono hidden md:inline">Telemetry:</span>
          <select
            value={session.currentMode || 'automatic'}
            onChange={handleModeChange}
            className="bg-transparent text-slate-200 font-mono focus:outline-none cursor-pointer"
          >
            <option value="automatic" className="bg-charcoal-900 text-slate-200">Automatic Monitoring (Default)</option>
            <option value="normal" className="bg-charcoal-900 text-slate-200">Normal Only (Baseline)</option>
            <option value="suspicious" className="bg-charcoal-900 text-slate-200">Suspicious (Test Bursts)</option>
            <option value="mixed" className="bg-charcoal-900 text-slate-200">Mixed Traffic</option>
          </select>
        </div>

        {/* Start / Stop Toggle */}
        <button
          onClick={handleToggleRunning}
          className={`flex items-center gap-1.5 px-3 py-1 rounded font-mono font-medium transition-colors ${
            session.isRunning
              ? 'bg-red-950/80 text-red-300 border border-red-800/80 hover:bg-red-900'
              : 'bg-emerald-950/80 text-emerald-300 border border-emerald-800/80 hover:bg-emerald-900'
          }`}
        >
          {session.isRunning ? (
            <>
              <Square className="w-3.5 h-3.5 fill-current" />
              <span>Stop</span>
            </>
          ) : (
            <>
              <Play className="w-3.5 h-3.5 fill-current" />
              <span>Start</span>
            </>
          )}
        </button>

        {/* Reset Button */}
        <button
          onClick={resetSession}
          className="p-1.5 text-slate-400 hover:text-slate-200 hover:bg-charcoal-800 rounded border border-charcoal-750 transition-colors hidden sm:flex"
          title="Reset telemetry and metrics"
        >
          <RefreshCw className="w-3.5 h-3.5" />
        </button>
      </div>

      {/* Right: Last Event Timestamp */}
      <div className="hidden lg:flex items-center gap-2 font-mono text-[11px] text-slate-400">
        <span>Last Event:</span>
        <span className="text-slate-200">
          {session.lastEventTimestamp
            ? new Date(session.lastEventTimestamp).toLocaleTimeString()
            : 'Idle'}
        </span>
      </div>
    </header>
  );
}

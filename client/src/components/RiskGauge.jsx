import React from 'react';
import { Shield, ShieldAlert, AlertTriangle, ShieldCheck } from 'lucide-react';

export default function RiskGauge({ score = 0, band = 'Low' }) {
  // Determine color and status description
  let colorClass = 'text-emerald-400';
  let barColor = 'bg-emerald-500';
  let borderColor = 'border-emerald-500/30';
  let statusText = 'Baseline Secure - Activity within nominal bounds';
  let Icon = ShieldCheck;

  if (score >= 75) {
    colorClass = 'text-red-400';
    barColor = 'bg-red-500';
    borderColor = 'border-red-500/40';
    statusText = 'CRITICAL ANOMALY - High-velocity threat pattern detected';
    Icon = ShieldAlert;
  } else if (score >= 50) {
    colorClass = 'text-orange-400';
    barColor = 'bg-orange-500';
    borderColor = 'border-orange-500/30';
    statusText = 'HIGH RISK - Multiple suspicious behavioral patterns observed';
    Icon = AlertTriangle;
  } else if (score >= 25) {
    colorClass = 'text-amber-400';
    barColor = 'bg-amber-500';
    borderColor = 'border-amber-500/30';
    statusText = 'GUARDED - Isolated non-standard syscall telemetry';
    Icon = Shield;
  }

  return (
    <div className={`p-5 rounded-lg bg-charcoal-850 border ${borderColor} flex flex-col justify-between shadow-sm`}>
      <div className="flex items-center justify-between pb-3 border-b border-charcoal-700/60">
        <div className="flex items-center gap-2">
          <Icon className={`w-5 h-5 ${colorClass}`} />
          <span className="text-xs font-semibold tracking-wider uppercase text-slate-300">
            Real-Time Risk Gauge
          </span>
        </div>
        <span className={`text-xs font-mono font-bold uppercase px-2.5 py-0.5 rounded border ${colorClass} bg-charcoal-900 border-charcoal-700`}>
          {band}
        </span>
      </div>

      <div className="my-4 flex items-end justify-between">
        <div>
          <div className="flex items-baseline gap-2">
            <span className={`text-4xl font-extrabold font-mono tracking-tight ${colorClass}`}>
              {score}
            </span>
            <span className="text-slate-500 text-sm font-mono">/ 100</span>
          </div>
          <div className="text-xs text-slate-400 mt-1 flex items-center gap-1.5">
            <span className={`w-2 h-2 rounded-full ${barColor} animate-pulse-subtle`}></span>
            <span>{statusText}</span>
          </div>
        </div>

        {/* Segmented Band Indicators */}
        <div className="hidden sm:flex flex-col gap-1 text-[10px] font-mono text-slate-400 text-right">
          <span className={score >= 75 ? 'text-red-400 font-bold' : 'opacity-40'}>75–100 Critical</span>
          <span className={score >= 50 && score < 75 ? 'text-orange-400 font-bold' : 'opacity-40'}>50–74 High</span>
          <span className={score >= 25 && score < 50 ? 'text-amber-400 font-bold' : 'opacity-40'}>25–49 Guarded</span>
          <span className={score < 25 ? 'text-emerald-400 font-bold' : 'opacity-40'}>0–24 Low</span>
        </div>
      </div>

      {/* Progress Bar with Segments */}
      <div className="w-full">
        <div className="h-2 w-full bg-charcoal-950 rounded-full overflow-hidden flex border border-charcoal-700/40">
          <div
            className={`h-full transition-all duration-500 ease-out ${barColor}`}
            style={{ width: `${Math.min(100, Math.max(2, score))}%` }}
          />
        </div>
        <div className="flex justify-between text-[10px] font-mono text-slate-500 mt-1 px-0.5">
          <span>0 (Nominal)</span>
          <span>25</span>
          <span>50</span>
          <span>75</span>
          <span>100 (Max)</span>
        </div>
      </div>

      <div className="text-[11px] text-slate-500 mt-3 pt-2 border-t border-charcoal-700/40 flex justify-between">
        <span>Deterministic Rule Weights + Decay Policy</span>
        <span className="italic">Prototype Model</span>
      </div>
    </div>
  );
}

import React from 'react';

export default function StatCard({ label, value, subtext, icon: Icon, valueColor = 'text-slate-100', borderColor = 'border-charcoal-700/60' }) {
  return (
    <div className={`p-4 rounded-lg bg-charcoal-850 border ${borderColor} flex flex-col justify-between shadow-sm`}>
      <div className="flex items-center justify-between text-slate-400 mb-2">
        <span className="text-xs font-medium uppercase tracking-wider">{label}</span>
        {Icon && <Icon className="w-4 h-4 text-slate-500" />}
      </div>
      <div className={`text-2xl font-bold font-mono ${valueColor}`}>
        {value}
      </div>
      {subtext && (
        <div className="text-[11px] text-slate-500 mt-1 font-mono">
          {subtext}
        </div>
      )}
    </div>
  );
}

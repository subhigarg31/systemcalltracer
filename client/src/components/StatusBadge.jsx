import React from 'react';

export function SeverityBadge({ severity }) {
  const styles = {
    Critical: 'bg-red-950/80 text-red-400 border-red-800/60',
    High: 'bg-orange-950/80 text-orange-400 border-orange-800/60',
    Medium: 'bg-amber-950/80 text-amber-400 border-amber-800/60',
    Low: 'bg-emerald-950/80 text-emerald-400 border-emerald-800/60',
    None: 'bg-slate-900 text-slate-400 border-slate-700'
  };

  const style = styles[severity] || styles.None;

  return (
    <span className={`inline-flex items-center px-2 py-0.5 text-xs font-mono font-medium rounded border ${style}`}>
      {severity}
    </span>
  );
}

export function CategoryBadge({ category }) {
  const styles = {
    file: 'bg-cyan-950/60 text-cyan-400 border-cyan-800/50',
    network: 'bg-purple-950/60 text-purple-400 border-purple-800/50',
    process: 'bg-emerald-950/60 text-emerald-400 border-emerald-800/50',
    memory: 'bg-amber-950/60 text-amber-400 border-amber-800/50'
  };

  const style = styles[category] || 'bg-slate-900 text-slate-400 border-slate-700';

  return (
    <span className={`inline-flex items-center px-1.5 py-0.5 text-[11px] font-mono rounded border uppercase tracking-wider ${style}`}>
      {category}
    </span>
  );
}

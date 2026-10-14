import React, { useState } from 'react';
import { X, Copy, Check, Terminal } from 'lucide-react';
import { CategoryBadge, SeverityBadge } from './StatusBadge';

export default function JsonDrawer({ event, onClose }) {
  const [copied, setCopied] = useState(false);

  if (!event) return null;

  const handleCopy = () => {
    navigator.clipboard.writeText(JSON.stringify(event, null, 2));
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/70 backdrop-blur-sm p-4">
      <div className="bg-charcoal-900 border border-charcoal-600 rounded-lg max-w-2xl w-full max-h-[85vh] flex flex-col shadow-2xl overflow-hidden animate-in fade-in duration-150">
        {/* Header */}
        <div className="flex items-center justify-between px-5 py-4 border-b border-charcoal-700 bg-charcoal-850">
          <div className="flex items-center gap-2.5">
            <Terminal className="w-5 h-5 text-cyan-400" />
            <div>
              <h3 className="text-sm font-semibold text-slate-100 flex items-center gap-2">
                Syscall Event Inspection
                <span className="font-mono text-xs text-slate-400">({event.syscall})</span>
              </h3>
              <p className="text-[11px] text-slate-400 font-mono">
                PID: {event.pid} &bull; Process: {event.process_name} &bull; {new Date(event.timestamp).toLocaleTimeString()}
              </p>
            </div>
          </div>
          <div className="flex items-center gap-2">
            <button
              onClick={handleCopy}
              className="p-1.5 text-slate-400 hover:text-slate-100 hover:bg-charcoal-700 rounded transition-colors text-xs flex items-center gap-1 font-mono border border-charcoal-700"
              title="Copy JSON"
            >
              {copied ? <Check className="w-3.5 h-3.5 text-emerald-400" /> : <Copy className="w-3.5 h-3.5" />}
              <span>{copied ? 'Copied' : 'Copy'}</span>
            </button>
            <button
              onClick={onClose}
              className="p-1.5 text-slate-400 hover:text-slate-100 hover:bg-charcoal-700 rounded transition-colors"
            >
              <X className="w-4 h-4" />
            </button>
          </div>
        </div>

        {/* Content */}
        <div className="p-5 overflow-y-auto space-y-4">
          {/* Quick Details Grid */}
          <div className="grid grid-cols-2 sm:grid-cols-4 gap-3 bg-charcoal-850 p-3 rounded border border-charcoal-750 text-xs font-mono">
            <div>
              <span className="text-slate-500 block text-[10px] uppercase">Category</span>
              <CategoryBadge category={event.category} />
            </div>
            <div>
              <span className="text-slate-500 block text-[10px] uppercase">Return Code</span>
              <span className={event.ret < 0 ? 'text-red-400' : 'text-slate-200'}>{event.ret}</span>
            </div>
            <div>
              <span className="text-slate-500 block text-[10px] uppercase">Scenario</span>
              <span className="text-slate-300 uppercase">{event.scenario || 'normal'}</span>
            </div>
            <div>
              <span className="text-slate-500 block text-[10px] uppercase">Anomaly Flag</span>
              {event.detection?.flagged ? (
                <SeverityBadge severity={event.detection.highestSeverity || 'High'} />
              ) : (
                <span className="text-emerald-400">Normal</span>
              )}
            </div>
          </div>

          {/* Arguments Breakdown */}
          <div>
            <h4 className="text-xs font-semibold uppercase text-slate-400 mb-1.5 font-mono">Parsed Arguments</h4>
            <div className="bg-charcoal-950 p-3 rounded border border-charcoal-800 font-mono text-xs text-slate-300">
              {Object.keys(event.args || {}).length === 0 ? (
                <span className="text-slate-600">None</span>
              ) : (
                <div className="space-y-1">
                  {Object.entries(event.args).map(([k, v]) => (
                    <div key={k} className="flex gap-2">
                      <span className="text-slate-500 min-w-16">{k}:</span>
                      <span className="text-cyan-300 break-all">{v}</span>
                    </div>
                  ))}
                </div>
              )}
            </div>
          </div>

          {/* Raw JSON viewer */}
          <div>
            <h4 className="text-xs font-semibold uppercase text-slate-400 mb-1.5 font-mono">Raw Event JSON</h4>
            <pre className="bg-charcoal-950 p-3 rounded border border-charcoal-800 font-mono text-xs text-slate-300 overflow-x-auto selection:bg-cyan-900 leading-relaxed">
              {JSON.stringify(event, null, 2)}
            </pre>
          </div>
        </div>

        {/* Footer */}
        <div className="px-5 py-3 border-t border-charcoal-700 bg-charcoal-850 flex justify-end">
          <button
            onClick={onClose}
            className="px-4 py-1.5 bg-charcoal-700 hover:bg-charcoal-600 text-slate-200 rounded text-xs font-mono transition-colors"
          >
            Close
          </button>
        </div>
      </div>
    </div>
  );
}

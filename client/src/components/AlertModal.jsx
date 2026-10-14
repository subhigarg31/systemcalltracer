import React from 'react';
import { X, ShieldAlert, CheckCircle2, AlertOctagon, Terminal } from 'lucide-react';
import { SeverityBadge } from './StatusBadge';
import { useSystem } from '../context/SystemContext';

export default function AlertModal({ alert, onClose }) {
  const { acknowledgeAlert } = useSystem();

  if (!alert) return null;

  const handleAcknowledge = async () => {
    await acknowledgeAlert(alert.alertId);
    onClose();
  };

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/70 backdrop-blur-sm p-4">
      <div className="bg-charcoal-900 border border-charcoal-600 rounded-lg max-w-2xl w-full max-h-[85vh] flex flex-col shadow-2xl overflow-hidden animate-in fade-in duration-150">
        {/* Header */}
        <div className="flex items-center justify-between px-5 py-4 border-b border-charcoal-700 bg-charcoal-850">
          <div className="flex items-center gap-2.5">
            <AlertOctagon className="w-5 h-5 text-red-400" />
            <div>
              <h3 className="text-sm font-semibold text-slate-100 flex items-center gap-2 font-mono">
                Threat Alert Investigation
                <span className="text-xs text-slate-400 font-normal">[{alert.alertId}]</span>
              </h3>
              <p className="text-[11px] text-slate-400 font-mono">
                Triggered at {new Date(alert.timestamp).toLocaleString()}
              </p>
            </div>
          </div>
          <button
            onClick={onClose}
            className="p-1.5 text-slate-400 hover:text-slate-100 hover:bg-charcoal-700 rounded transition-colors"
          >
            <X className="w-4 h-4" />
          </button>
        </div>

        {/* Content */}
        <div className="p-5 overflow-y-auto space-y-4">
          {/* Top Status Banner */}
          <div className="flex flex-wrap items-center justify-between p-3 rounded bg-charcoal-850 border border-charcoal-750 gap-2">
            <div className="flex items-center gap-2">
              <span className="text-xs text-slate-400 font-mono">Severity:</span>
              <SeverityBadge severity={alert.severity} />
            </div>
            <div className="flex items-center gap-2">
              <span className="text-xs text-slate-400 font-mono">Risk Score:</span>
              <span className={`text-xs font-mono font-bold px-2 py-0.5 rounded ${
                (alert.riskScore || 0) >= 75 ? 'bg-red-950 text-red-400 border border-red-800' :
                (alert.riskScore || 0) >= 50 ? 'bg-orange-950 text-orange-400 border border-orange-800' :
                'bg-amber-950 text-amber-400 border border-amber-800'
              }`}>
                {alert.riskScore !== undefined ? `${alert.riskScore}/100 (${alert.riskBand || 'Elevated'})` : 'Dynamic Risk'}
              </span>
            </div>
            <div className="flex items-center gap-2">
              <span className="text-xs text-slate-400 font-mono">Category:</span>
              <span className="text-xs font-mono font-medium text-slate-200 bg-charcoal-900 px-2 py-0.5 rounded border border-charcoal-700">
                {alert.category}
              </span>
            </div>
            <div className="flex items-center gap-2">
              <span className="text-xs text-slate-400 font-mono">Status:</span>
              <span className={`text-xs font-mono font-bold uppercase px-2 py-0.5 rounded ${alert.status === 'active' ? 'bg-red-950/80 text-red-400 border border-red-800/60' : 'bg-slate-800 text-slate-400 border border-slate-700'}`}>
                {alert.status}
              </span>
            </div>
          </div>

          {/* Process & Rule Info */}
          <div className="grid grid-cols-2 gap-3 bg-charcoal-850 p-3 rounded border border-charcoal-750 text-xs font-mono">
            <div>
              <span className="text-slate-500 block text-[10px] uppercase">Process Name</span>
              <span className="text-cyan-300 font-semibold">{alert.process_name}</span>
            </div>
            <div>
              <span className="text-slate-500 block text-[10px] uppercase">Process ID (PID)</span>
              <span className="text-slate-200">{alert.pid}</span>
            </div>
            <div>
              <span className="text-slate-500 block text-[10px] uppercase">Detection Rule</span>
              <span className="text-slate-200 font-semibold">{alert.ruleId || 'RULE_EVALUATION'}</span>
            </div>
            <div>
              <span className="text-slate-500 block text-[10px] uppercase">Detection Mode</span>
              <span className="text-emerald-400">Independent Heuristic Evaluation</span>
            </div>
          </div>

          {/* Human Readable Description */}
          <div>
            <h4 className="text-xs font-semibold uppercase text-slate-400 mb-1.5 font-mono">Threat Synopsis</h4>
            <div className="bg-charcoal-950 p-3 rounded border border-charcoal-800 text-sm text-slate-200 leading-relaxed font-sans">
              {alert.description}
            </div>
          </div>

          {/* Evidence Dossier */}
          <div>
            <h4 className="text-xs font-semibold uppercase text-slate-400 mb-1.5 font-mono">Forensic Evidence</h4>
            <pre className="bg-charcoal-950 p-3 rounded border border-charcoal-800 font-mono text-xs text-cyan-300 overflow-x-auto leading-relaxed">
              {JSON.stringify(alert.evidence, null, 2)}
            </pre>
          </div>

          {/* Prescriptive Recommended Action */}
          <div>
            <h4 className="text-xs font-semibold uppercase text-slate-400 mb-1.5 font-mono">Recommended SOC Action</h4>
            <div className="bg-charcoal-850 border-l-2 border-amber-500 p-3 rounded-r text-xs text-slate-300 font-mono leading-relaxed">
              {alert.recommendedAction || 'Isolate host process and inspect filesystem journal.'}
            </div>
          </div>
        </div>

        {/* Footer */}
        <div className="px-5 py-3 border-t border-charcoal-700 bg-charcoal-850 flex items-center justify-between">
          <span className="text-[11px] text-slate-500 font-mono">
            Historical evidence preserved upon acknowledgment.
          </span>
          <div className="flex gap-2">
            {alert.status === 'active' && (
              <button
                onClick={handleAcknowledge}
                className="px-3.5 py-1.5 bg-emerald-700 hover:bg-emerald-600 text-white rounded text-xs font-mono transition-colors flex items-center gap-1.5"
              >
                <CheckCircle2 className="w-3.5 h-3.5" />
                Acknowledge Alert
              </button>
            )}
            <button
              onClick={onClose}
              className="px-3.5 py-1.5 bg-charcoal-700 hover:bg-charcoal-600 text-slate-200 rounded text-xs font-mono transition-colors"
            >
              Close
            </button>
          </div>
        </div>
      </div>
    </div>
  );
}

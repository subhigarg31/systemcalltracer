import React, { useState, useEffect } from 'react';
import { Settings as SettingsIcon, Save, RefreshCw, Trash2, CheckCircle2, Shield } from 'lucide-react';
import { useSystem } from '../context/SystemContext';

export default function Settings() {
  const { session, setSimulationMode, resetSession } = useSystem();
  const [config, setConfig] = useState(null);
  const [loading, setLoading] = useState(true);
  const [savedSuccess, setSavedSuccess] = useState(false);

  useEffect(() => {
    fetchSettings();
  }, []);

  const fetchSettings = async () => {
    setLoading(true);
    try {
      const res = await fetch('/api/settings');
      if (res.ok) {
        const data = await res.json();
        setConfig(data);
      }
    } catch (err) {
      console.error('Error fetching settings:', err);
    } finally {
      setLoading(false);
    }
  };

  const handleSave = async (e) => {
    e.preventDefault();
    try {
      const res = await fetch('/api/settings', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(config)
      });
      if (res.ok) {
        setSavedSuccess(true);
        setTimeout(() => setSavedSuccess(false), 2500);
      }
    } catch (err) {
      console.error('Error saving settings:', err);
    }
  };

  if (loading || !config) {
    return (
      <div className="p-12 text-center text-xs font-mono text-slate-500">
        Loading system configuration...
      </div>
    );
  }

  return (
    <div className="p-6 max-w-5xl mx-auto space-y-6">
      <div className="bg-charcoal-850 p-4 rounded-lg border border-charcoal-750 flex items-center justify-between">
        <div>
          <h2 className="text-sm font-bold font-mono text-slate-100 flex items-center gap-2">
            <SettingsIcon className="w-4 h-4 text-cyan-400" />
            Detection Engine & Simulator Settings
          </h2>
          <p className="text-[11px] text-slate-400 font-mono mt-0.5">
            Configure telemetry intervals, threat rule thresholds, and risk decay model.
          </p>
        </div>

        {savedSuccess && (
          <span className="flex items-center gap-1.5 text-xs font-mono text-emerald-400 bg-emerald-950/80 px-2.5 py-1 rounded border border-emerald-800/60 animate-in fade-in">
            <CheckCircle2 className="w-3.5 h-3.5" />
            Settings Applied
          </span>
        )}
      </div>

      <form onSubmit={handleSave} className="space-y-6">
        {/* Simulator Parameters */}
        <div className="bg-charcoal-850 rounded-lg border border-charcoal-750 p-5 space-y-4">
          <h3 className="text-xs font-semibold uppercase tracking-wider text-slate-300 font-mono flex items-center gap-2">
            <Shield className="w-4 h-4 text-cyan-400" />
            Telemetry Simulator Controls
          </h3>

          <div className="grid grid-cols-1 sm:grid-cols-2 gap-4 text-xs font-mono">
            <div>
              <label className="text-slate-400 block mb-1">
                Event Interval ({config.defaultIntervalMs} ms)
              </label>
              <input
                type="range"
                min="50"
                max="1000"
                step="25"
                value={config.defaultIntervalMs}
                onChange={(e) => setConfig({ ...config, defaultIntervalMs: parseInt(e.target.value, 10) })}
                className="w-full accent-cyan-500"
              />
              <span className="text-[10px] text-slate-500 mt-0.5 block">
                Controls rate of generated syscall events (50ms = fast, 1000ms = slow)
              </span>
            </div>

            <div>
              <label className="text-slate-400 block mb-1">Active Scenario Mode</label>
              <select
                value={session.currentMode || 'normal'}
                onChange={(e) => setSimulationMode(e.target.value)}
                className="w-full bg-charcoal-900 border border-charcoal-700 rounded px-3 py-1.5 text-slate-200 focus:outline-none focus:border-cyan-500"
              >
                <option value="normal">Normal (Nominal operational baseline)</option>
                <option value="suspicious">Suspicious (Triggers Rules A, B, C, D)</option>
                <option value="mixed">Mixed (75% normal, 25% suspicious spikes)</option>
              </select>
            </div>
          </div>
        </div>

        {/* Rule Thresholds */}
        <div className="bg-charcoal-850 rounded-lg border border-charcoal-750 p-5 space-y-4">
          <h3 className="text-xs font-semibold uppercase tracking-wider text-slate-300 font-mono">
            Threat Detection Rules & Sensitivity Thresholds
          </h3>

          <div className="space-y-4 text-xs font-mono">
            {/* Rule A */}
            <div className="p-3 bg-charcoal-900 rounded border border-charcoal-750 space-y-2">
              <div className="flex items-center justify-between">
                <span className="font-semibold text-slate-200">Rule A: Sensitive Credential Access</span>
                <span className="text-red-400 font-bold uppercase">{config.rules.ruleA.severity}</span>
              </div>
              <p className="text-[11px] text-slate-400">{config.rules.ruleA.description}</p>
              <div>
                <label className="text-slate-500 text-[10px] uppercase block">Sensitive Paths (comma separated)</label>
                <input
                  type="text"
                  value={config.rules.ruleA.sensitivePaths.join(', ')}
                  onChange={(e) => {
                    const paths = e.target.value.split(',').map(s => s.trim()).filter(Boolean);
                    setConfig({
                      ...config,
                      rules: { ...config.rules, ruleA: { ...config.rules.ruleA, sensitivePaths: paths } }
                    });
                  }}
                  className="w-full bg-charcoal-950 border border-charcoal-800 rounded px-2.5 py-1 text-slate-200 font-mono mt-1"
                />
              </div>
            </div>

            {/* Rule B */}
            <div className="p-3 bg-charcoal-900 rounded border border-charcoal-750 space-y-2">
              <div className="flex items-center justify-between">
                <span className="font-semibold text-slate-200">Rule B: Ransomware Multi-File Modification</span>
                <span className="text-red-400 font-bold uppercase">{config.rules.ruleB.severity}</span>
              </div>
              <p className="text-[11px] text-slate-400">{config.rules.ruleB.description}</p>
              <div className="grid grid-cols-2 gap-3">
                <div>
                  <label className="text-slate-500 text-[10px] uppercase block">Min Unique Files</label>
                  <input
                    type="number"
                    min="2"
                    max="20"
                    value={config.rules.ruleB.minWrites}
                    onChange={(e) => {
                      const val = parseInt(e.target.value, 10);
                      setConfig({
                        ...config,
                        rules: { ...config.rules, ruleB: { ...config.rules.ruleB, minWrites: val } }
                      });
                    }}
                    className="w-full bg-charcoal-950 border border-charcoal-800 rounded px-2.5 py-1 text-slate-200 font-mono mt-1"
                  />
                </div>
                <div>
                  <label className="text-slate-500 text-[10px] uppercase block">Sliding Window (ms)</label>
                  <input
                    type="number"
                    min="1000"
                    max="15000"
                    step="500"
                    value={config.rules.ruleB.windowMs}
                    onChange={(e) => {
                      const val = parseInt(e.target.value, 10);
                      setConfig({
                        ...config,
                        rules: { ...config.rules, ruleB: { ...config.rules.ruleB, windowMs: val } }
                      });
                    }}
                    className="w-full bg-charcoal-950 border border-charcoal-800 rounded px-2.5 py-1 text-slate-200 font-mono mt-1"
                  />
                </div>
              </div>
            </div>

            {/* Rule C */}
            <div className="p-3 bg-charcoal-900 rounded border border-charcoal-750 space-y-2">
              <div className="flex items-center justify-between">
                <span className="font-semibold text-slate-200">Rule C: Suspicious Outbound Network Ports</span>
                <span className="text-orange-400 font-bold uppercase">{config.rules.ruleC.severity}</span>
              </div>
              <p className="text-[11px] text-slate-400">{config.rules.ruleC.description}</p>
              <div>
                <label className="text-slate-500 text-[10px] uppercase block">Flagged Ports (comma separated)</label>
                <input
                  type="text"
                  value={config.rules.ruleC.suspiciousPorts.join(', ')}
                  onChange={(e) => {
                    const ports = e.target.value.split(',').map(s => parseInt(s.trim(), 10)).filter(n => !isNaN(n));
                    setConfig({
                      ...config,
                      rules: { ...config.rules, ruleC: { ...config.rules.ruleC, suspiciousPorts: ports } }
                    });
                  }}
                  className="w-full bg-charcoal-950 border border-charcoal-800 rounded px-2.5 py-1 text-slate-200 font-mono mt-1"
                />
              </div>
            </div>

            {/* Rule D */}
            <div className="p-3 bg-charcoal-900 rounded border border-charcoal-750 space-y-2">
              <div className="flex items-center justify-between">
                <span className="font-semibold text-slate-200">Rule D: Process Spawning Burst</span>
                <span className="text-amber-400 font-bold uppercase">{config.rules.ruleD.severity}</span>
              </div>
              <p className="text-[11px] text-slate-400">{config.rules.ruleD.description}</p>
              <div className="grid grid-cols-2 gap-3">
                <div>
                  <label className="text-slate-500 text-[10px] uppercase block">Max Spawns in Window</label>
                  <input
                    type="number"
                    min="3"
                    max="20"
                    value={config.rules.ruleD.maxSpawns}
                    onChange={(e) => {
                      const val = parseInt(e.target.value, 10);
                      setConfig({
                        ...config,
                        rules: { ...config.rules, ruleD: { ...config.rules.ruleD, maxSpawns: val } }
                      });
                    }}
                    className="w-full bg-charcoal-950 border border-charcoal-800 rounded px-2.5 py-1 text-slate-200 font-mono mt-1"
                  />
                </div>
                <div>
                  <label className="text-slate-500 text-[10px] uppercase block">Window Duration (ms)</label>
                  <input
                    type="number"
                    min="1000"
                    max="10000"
                    step="500"
                    value={config.rules.ruleD.windowMs}
                    onChange={(e) => {
                      const val = parseInt(e.target.value, 10);
                      setConfig({
                        ...config,
                        rules: { ...config.rules, ruleD: { ...config.rules.ruleD, windowMs: val } }
                      });
                    }}
                    className="w-full bg-charcoal-950 border border-charcoal-800 rounded px-2.5 py-1 text-slate-200 font-mono mt-1"
                  />
                </div>
              </div>
            </div>
          </div>
        </div>

        {/* Risk Scoring & Decay Policy */}
        <div className="bg-charcoal-850 rounded-lg border border-charcoal-750 p-5 space-y-4">
          <h3 className="text-xs font-semibold uppercase tracking-wider text-slate-300 font-mono">
            Risk Score Decay Configuration
          </h3>

          <div className="grid grid-cols-1 sm:grid-cols-2 gap-4 text-xs font-mono">
            <div>
              <label className="text-slate-400 block mb-1">
                Decay Interval ({config.risk.decayIntervalMs} ms)
              </label>
              <input
                type="number"
                min="1000"
                max="10000"
                step="500"
                value={config.risk.decayIntervalMs}
                onChange={(e) => setConfig({
                  ...config,
                  risk: { ...config.risk, decayIntervalMs: parseInt(e.target.value, 10) }
                })}
                className="w-full bg-charcoal-900 border border-charcoal-700 rounded px-3 py-1.5 text-slate-200 font-mono"
              />
              <span className="text-[10px] text-slate-500 mt-0.5 block">
                Time elapsed without new anomalies before score decays toward baseline
              </span>
            </div>

            <div>
              <label className="text-slate-400 block mb-1">
                Decay Step ({config.risk.decayStep} points)
              </label>
              <input
                type="number"
                min="1"
                max="25"
                value={config.risk.decayStep}
                onChange={(e) => setConfig({
                  ...config,
                  risk: { ...config.risk, decayStep: parseInt(e.target.value, 10) }
                })}
                className="w-full bg-charcoal-900 border border-charcoal-700 rounded px-3 py-1.5 text-slate-200 font-mono"
              />
              <span className="text-[10px] text-slate-500 mt-0.5 block">
                Points deducted per decay tick
              </span>
            </div>
          </div>
        </div>

        {/* Action Buttons */}
        <div className="flex flex-wrap items-center justify-between gap-4 pt-2">
          <button
            type="button"
            onClick={resetSession}
            className="px-3.5 py-2 rounded bg-red-950/80 hover:bg-red-900 text-red-300 border border-red-800/80 text-xs font-mono flex items-center gap-2 transition-colors"
          >
            <Trash2 className="w-3.5 h-3.5" />
            <span>Purge Session Data</span>
          </button>

          <div className="flex items-center gap-2">
            <button
              type="button"
              onClick={fetchSettings}
              className="px-4 py-2 rounded bg-charcoal-800 hover:bg-charcoal-700 text-slate-300 border border-charcoal-700 text-xs font-mono transition-colors"
            >
              Cancel / Reload
            </button>
            <button
              type="submit"
              className="px-5 py-2 rounded bg-cyan-600 hover:bg-cyan-500 text-charcoal-950 font-bold text-xs font-mono flex items-center gap-2 transition-colors shadow-sm"
            >
              <Save className="w-3.5 h-3.5" />
              <span>Save & Apply Settings</span>
            </button>
          </div>
        </div>
      </form>
    </div>
  );
}

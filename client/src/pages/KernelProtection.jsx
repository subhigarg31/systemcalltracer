import React, { useEffect, useRef, useState } from 'react';
import { Shield, ShieldOff, Power, Bug, FileCheck2, Play, Skull, Snowflake, AlertOctagon, Loader2 } from 'lucide-react';
import StatCard from '../components/StatCard';
import { useSystem } from '../context/SystemContext';

const TOTAL_FILES = 200;
const RULE_LABEL = '4 files in 5 s';

const GUARD_STYLES = {
  armed: { label: 'Armed', className: 'bg-emerald-950/80 text-emerald-400 border-emerald-800/60' },
  starting: { label: 'Arming…', className: 'bg-amber-950/80 text-amber-400 border-amber-800/60' },
  off: { label: 'Off', className: 'bg-slate-800 text-slate-400 border-slate-700' }
};

const ENTRY_STYLES = {
  frozen: 'bg-orange-950/80 text-orange-400 border-orange-800/60',
  resumed: 'bg-emerald-950/80 text-emerald-400 border-emerald-800/60',
  killed: 'bg-slate-800 text-slate-400 border-slate-700',
  exited: 'bg-slate-800 text-slate-500 border-slate-700'
};

// fetch that can't hang forever: aborts after `ms` and returns null on timeout/error.
async function fetchSafe(url, options = {}, ms = 4000) {
  const ctrl = new AbortController();
  const t = setTimeout(() => ctrl.abort(), ms);
  try {
    const res = await fetch(url, { ...options, signal: ctrl.signal });
    return res;
  } catch {
    return null; // timeout or network error — caller decides what that means
  } finally {
    clearTimeout(t);
  }
}

function GuardBadge({ status }) {
  const style = GUARD_STYLES[status] || GUARD_STYLES.off;
  return (
    <span className={`inline-flex items-center gap-1.5 px-2 py-0.5 text-xs font-mono font-medium rounded border ${style.className}`}>
      <span className={`w-1.5 h-1.5 rounded-full ${status === 'armed' ? 'bg-emerald-400 animate-pulse' : status === 'starting' ? 'bg-amber-400' : 'bg-slate-500'}`} />
      {style.label}
    </span>
  );
}

function EntryBadge({ status }) {
  return (
    <span className={`text-[10px] font-bold uppercase px-2 py-0.5 rounded border ${ENTRY_STYLES[status] || ENTRY_STYLES.exited}`}>
      {status}
    </span>
  );
}

export default function KernelProtection() {
  const {
    kernelStatus,
    kernelEntries,
    fetchKernelStatus,
    armKernel,
    disarmKernel,
    resumeKernelProcess,
    killKernelProcess
  } = useSystem();

  const [damage, setDamage] = useState(null);
  const [busy, setBusy] = useState(null); // 'arm' | 'attack' | `${pid}:resume` | `${pid}:kill`
  const [error, setError] = useState(null);
  const timersRef = useRef([]);

  // The server only pushes freeze events, so poll for arm/disarm state changes.
  useEffect(() => {
    fetchKernelStatus();
    const id = setInterval(fetchKernelStatus, 2000);
    return () => {
      clearInterval(id);
      timersRef.current.forEach(clearTimeout);
    };
  }, []);

  const run = async (key, fn) => {
    setBusy(key);
    setError(null);
    try {
      await fn();
    } catch (err) {
      setError(err.message);
    } finally {
      setBusy(null);
    }
  };

  const isOn = kernelStatus === 'armed' || kernelStatus === 'starting';

  const toggleGuard = () =>
    run('arm', async () => {
      if (isOn) await disarmKernel();
      else await armKernel();
      fetchKernelStatus();
    });

  // Launch the attack as fire-and-forget: when the guard is armed the attacker
  // gets FROZEN and never exits, so the POST may never return — that's success,
  // not an error. We don't block on it; we just wait, then measure the damage.
  const runAttack = () =>
    run('attack', async () => {
      setDamage(null);
      // The backend disarms, restores a clean 200 files, re-arms, launches the
      // attacker and only responds once it is frozen. That whole cycle takes a
      // few seconds, so we wait for it (generous timeout) before measuring.
      await fetchSafe('/api/kernel/demo-attack', { method: 'POST' }, 15000);

      // Measure how many files were damaged before the attacker was stopped.
      const dRes = await fetchSafe('/api/kernel/damage', {}, 4000);
      if (dRes && dRes.ok) {
        const dData = await dRes.json().catch(() => null);
        if (dData) setDamage(dData);
        else setError('Could not read damage count');
      } else {
        setError('Could not read damage count');
      }
      fetchKernelStatus();
    });

  const protectedCount = damage ? damage.total - damage.damaged : null;
  const total = damage ? damage.total : TOTAL_FILES;
  const protectedColor =
    protectedCount === null ? 'text-slate-500' :
    protectedCount >= total * 0.95 ? 'text-emerald-400' :
    protectedCount >= total * 0.5 ? 'text-amber-400' : 'text-red-400';

  const frozenCount = kernelEntries.filter(e => e.status === 'frozen').length;
  const sortedEntries = [...kernelEntries].sort((a, b) => (b.frozenAt || '').localeCompare(a.frozenAt || ''));

  return (
    <div className="p-6 max-w-7xl mx-auto space-y-4">
      {/* Control bar */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 bg-charcoal-850 p-4 rounded-lg border border-charcoal-750">
        <div className="flex items-center gap-3">
          <Shield className="w-5 h-5 text-cyan-400" />
          <div>
            <div className="flex items-center gap-2">
              <span className="text-sm font-semibold text-slate-100">In-kernel freeze guard</span>
              <GuardBadge status={kernelStatus} />
            </div>
            <div className="text-[11px] font-mono text-slate-500 mt-0.5">
              eBPF freeze.bt · SIGSTOP any process writing {RULE_LABEL} in /tmp/ransom_test
            </div>
          </div>
        </div>

        <div className="flex items-center gap-2">
          <button
            onClick={toggleGuard}
            disabled={busy === 'arm'}
            className={`px-3 py-1.5 rounded text-xs font-mono flex items-center gap-1.5 border transition-colors disabled:opacity-50 ${
              isOn
                ? 'bg-charcoal-900 text-slate-300 hover:bg-charcoal-800 border-charcoal-700'
                : 'bg-emerald-950 text-emerald-400 hover:bg-emerald-900 border-emerald-800/60'
            }`}
          >
            {busy === 'arm' ? <Loader2 className="w-3.5 h-3.5 animate-spin" /> : isOn ? <ShieldOff className="w-3.5 h-3.5" /> : <Power className="w-3.5 h-3.5" />}
            <span>{isOn ? 'Disarm' : 'Arm'}</span>
          </button>
          <button
            onClick={runAttack}
            disabled={busy === 'attack'}
            className="px-3 py-1.5 rounded text-xs font-mono flex items-center gap-1.5 border bg-red-950 text-red-400 hover:bg-red-900 border-red-800/60 transition-colors disabled:opacity-50"
            title="Runs fake_ransom against 200 dummy files in /tmp/ransom_test"
          >
            {busy === 'attack' ? <Loader2 className="w-3.5 h-3.5 animate-spin" /> : <Bug className="w-3.5 h-3.5" />}
            <span>{busy === 'attack' ? 'Attacking…' : 'Run test attack'}</span>
          </button>
        </div>
      </div>

      {error && (
        <div className="flex items-center gap-2 px-4 py-2.5 rounded-lg bg-red-950/70 border border-red-800/60 text-red-400 text-xs font-mono">
          <AlertOctagon className="w-4 h-4 shrink-0" />
          {error}
        </div>
      )}

      {!isOn && busy !== 'attack' && (
        <div className="px-4 py-2.5 rounded-lg bg-charcoal-900 border border-charcoal-750 text-slate-500 text-[11px] font-mono">
          Guard is off: a test attack will overwrite all {TOTAL_FILES} files. Arm it first to see the freeze.
        </div>
      )}

      {/* Stats */}
      <div className="grid grid-cols-1 sm:grid-cols-3 gap-3">
        <div className="sm:col-span-2">
          <StatCard
            label="Files protected"
            icon={FileCheck2}
            value={
              <span className="text-4xl">
                {protectedCount === null ? '--' : protectedCount}
                <span className="text-slate-500 text-2xl"> / {total}</span>
              </span>
            }
            valueColor={protectedColor}
            subtext={
              damage
                ? `${damage.damaged} file${damage.damaged === 1 ? '' : 's'} overwritten before the attacker was stopped`
                : 'Run a test attack to measure damage'
            }
          />
        </div>
        <StatCard
          label="Awaiting decision"
          icon={Snowflake}
          value={frozenCount}
          valueColor={frozenCount > 0 ? 'text-orange-400' : 'text-slate-300'}
          subtext={`${kernelEntries.length} frozen this session`}
        />
      </div>

      {/* Frozen processes */}
      <div className="bg-charcoal-850 rounded-lg border border-charcoal-750 overflow-hidden shadow-sm">
        <div className="px-4 py-3 border-b border-charcoal-700/80 text-[11px] font-mono uppercase tracking-wider text-slate-400">
          Frozen processes
        </div>
        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs font-mono">
            <thead className="bg-charcoal-900 text-slate-400 border-b border-charcoal-700/80 text-[11px] uppercase tracking-wider">
              <tr>
                <th className="py-2.5 px-3">PID</th>
                <th className="py-2.5 px-3">Process</th>
                <th className="py-2.5 px-3">Rule</th>
                <th className="py-2.5 px-3">Last File</th>
                <th className="py-2.5 px-3">Frozen At</th>
                <th className="py-2.5 px-3 text-center">Status</th>
                <th className="py-2.5 px-3 text-right">Actions</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-charcoal-750">
              {sortedEntries.length === 0 ? (
                <tr>
                  <td colSpan="7" className="py-12 text-center text-slate-500 font-mono">
                    No processes frozen yet. Arm the guard and run a test attack.
                  </td>
                </tr>
              ) : (
                sortedEntries.map((e) => {
                  const isFrozen = e.status === 'frozen';
                  const resumeKey = `${e.pid}:resume`;
                  const killKey = `${e.pid}:kill`;
                  return (
                    <tr key={e.pid} className={`hover:bg-charcoal-900/60 transition-colors ${isFrozen ? 'border-l-2 border-orange-500' : ''}`}>
                      <td className="py-2.5 px-3 text-cyan-400 font-semibold whitespace-nowrap">{e.pid}</td>
                      <td className="py-2.5 px-3 text-slate-200 font-semibold whitespace-nowrap">{e.process}</td>
                      <td className="py-2.5 px-3 whitespace-nowrap">
                        <span className="text-[11px] px-1.5 py-0.5 rounded bg-charcoal-900 border border-charcoal-700 text-slate-300">
                          {RULE_LABEL}
                        </span>
                      </td>
                      <td className="py-2.5 px-3 text-slate-300 max-w-xs truncate" title={e.last_file}>{e.last_file}</td>
                      <td className="py-2.5 px-3 text-slate-400 text-[11px] whitespace-nowrap">
                        {e.frozenAt ? new Date(e.frozenAt).toLocaleTimeString() : '--'}
                      </td>
                      <td className="py-2.5 px-3 text-center whitespace-nowrap">
                        <EntryBadge status={e.status} />
                      </td>
                      <td className="py-2.5 px-3 text-right whitespace-nowrap">
                        {isFrozen && (
                          <div className="flex items-center justify-end gap-2">
                            <button
                              onClick={() => run(resumeKey, () => resumeKernelProcess(e.pid))}
                              disabled={busy === resumeKey || busy === killKey}
                              className="px-2 py-1 bg-emerald-950 text-emerald-400 hover:bg-emerald-900 border border-emerald-800/60 rounded text-[11px] font-mono flex items-center gap-1 transition-colors disabled:opacity-50"
                              title="False alarm: send SIGCONT"
                            >
                              {busy === resumeKey ? <Loader2 className="w-3 h-3 animate-spin" /> : <Play className="w-3 h-3" />}
                              <span>Resume</span>
                            </button>
                            <button
                              onClick={() => run(killKey, () => killKernelProcess(e.pid))}
                              disabled={busy === resumeKey || busy === killKey}
                              className="px-2 py-1 bg-red-950 text-red-400 hover:bg-red-900 border border-red-800/60 rounded text-[11px] font-mono flex items-center gap-1 transition-colors disabled:opacity-50"
                              title="Real threat: send SIGKILL"
                            >
                              {busy === killKey ? <Loader2 className="w-3 h-3 animate-spin" /> : <Skull className="w-3 h-3" />}
                              <span>Kill</span>
                            </button>
                          </div>
                        )}
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

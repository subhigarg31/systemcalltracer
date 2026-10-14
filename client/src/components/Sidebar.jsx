import React from 'react';
import { LayoutDashboard, Terminal, ShieldAlert, Cpu, FileText, Settings } from 'lucide-react';
import { useSystem } from '../context/SystemContext';

export default function Sidebar({ activeTab, onSelectTab }) {
  const { metrics } = useSystem();

  const navItems = [
    { id: 'overview', label: 'Overview', icon: LayoutDashboard },
    { id: 'live-feed', label: 'Live Syscall Feed', icon: Terminal },
    {
      id: 'alerts',
      label: 'Threat Alerts',
      icon: ShieldAlert,
      badge: metrics.activeAlerts > 0 ? metrics.activeAlerts : null,
      badgeColor: 'bg-red-500 text-white'
    },
    { id: 'processes', label: 'Process Activity', icon: Cpu },
    { id: 'reports', label: 'Reports', icon: FileText },
    { id: 'settings', label: 'Settings', icon: Settings },
  ];

  return (
    <aside className="w-56 bg-charcoal-950 border-r border-charcoal-800/80 flex flex-col justify-between shrink-0 select-none">
      <div className="py-4">
        <div className="px-4 mb-3 text-[10px] font-mono uppercase tracking-wider text-slate-500 font-semibold">
          Monitoring Console
        </div>
        <nav className="space-y-0.5 px-2">
          {navItems.map((item) => {
            const Icon = item.icon;
            const isActive = activeTab === item.id;

            return (
              <button
                key={item.id}
                onClick={() => onSelectTab(item.id)}
                className={`w-full flex items-center justify-between px-3 py-2 rounded text-xs font-medium transition-colors font-mono ${
                  isActive
                    ? 'bg-charcoal-800 text-slate-100 border border-charcoal-700/80'
                    : 'text-slate-400 hover:text-slate-200 hover:bg-charcoal-900 border border-transparent'
                }`}
              >
                <div className="flex items-center gap-2.5">
                  <Icon className={`w-4 h-4 ${isActive ? 'text-cyan-400' : 'text-slate-500'}`} />
                  <span>{item.label}</span>
                </div>
                {item.badge && (
                  <span className={`px-1.5 py-0.2 rounded-full text-[10px] font-bold ${item.badgeColor}`}>
                    {item.badge}
                  </span>
                )}
              </button>
            );
          })}
        </nav>
      </div>

      {/* Simulator Scope Notice in Sidebar Footer */}
      <div className="p-3 m-2 rounded bg-charcoal-900 border border-charcoal-800 text-[11px] font-mono text-slate-500">
        <div className="text-slate-400 font-semibold mb-0.5">macOS Telemetry</div>
        Synthetic C++ syscall events stream. Safe academic environment.
      </div>
    </aside>
  );
}

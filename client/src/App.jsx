import React, { useState } from 'react';
import { Snowflake, X } from 'lucide-react';
import Navbar from './components/Navbar';
import Sidebar from './components/Sidebar';
import JsonDrawer from './components/JsonDrawer';
import AlertModal from './components/AlertModal';
import Overview from './pages/Overview';
import LiveFeed from './pages/LiveFeed';
import Alerts from './pages/Alerts';
import Processes from './pages/Processes';
import Reports from './pages/Reports';
import Settings from './pages/Settings';
import KernelProtection from './pages/KernelProtection';
import { useSystem } from './context/SystemContext';

export default function App() {
  const [activeTab, setActiveTab] = useState('overview');
  const { inspectedEvent, setInspectedEvent, inspectedAlert, setInspectedAlert, kernelToast, setKernelToast } = useSystem();

  const renderActiveTab = () => {
    switch (activeTab) {
      case 'overview':
        return <Overview onNavigateTab={setActiveTab} />;
      case 'live-feed':
        return <LiveFeed />;
      case 'alerts':
        return <Alerts />;
      case 'kernel':
        return <KernelProtection />;
      case 'processes':
        return <Processes />;
      case 'reports':
        return <Reports />;
      case 'settings':
        return <Settings />;
      default:
        return <Overview onNavigateTab={setActiveTab} />;
    }
  };

  return (
    <div className="min-h-screen bg-charcoal-900 text-slate-100 flex flex-col font-sans">
      <Navbar />

      <div className="flex-1 flex overflow-hidden">
        <Sidebar activeTab={activeTab} onSelectTab={setActiveTab} />
        
        <main className="flex-1 overflow-y-auto bg-charcoal-950/40">
          {/* Kernel freeze banner: shown on any page when freeze.bt stops a process */}
          {kernelToast && (
            <div className="sticky top-0 z-30 px-6 pt-4">
              <div className="max-w-7xl mx-auto flex items-center justify-between gap-3 px-4 py-2.5 rounded-lg bg-orange-950/90 border border-orange-800/60 text-orange-300 text-xs font-mono shadow-lg">
                <button
                  onClick={() => { setActiveTab('kernel'); setKernelToast(null); }}
                  className="flex items-center gap-2 text-left hover:text-orange-200"
                >
                  <Snowflake className="w-4 h-4 shrink-0 text-orange-400" />
                  <span>
                    <span className="font-bold">Kernel froze {kernelToast.process}</span>
                    <span className="text-orange-400/80"> (PID {kernelToast.pid}) after {kernelToast.files_in_window} file writes. Review in Kernel Protection →</span>
                  </span>
                </button>
                <button onClick={() => setKernelToast(null)} className="p-1 text-orange-400 hover:text-orange-200" title="Dismiss">
                  <X className="w-3.5 h-3.5" />
                </button>
              </div>
            </div>
          )}
          {renderActiveTab()}
        </main>
      </div>

      {/* Full JSON inspection modal */}
      {inspectedEvent && (
        <JsonDrawer event={inspectedEvent} onClose={() => setInspectedEvent(null)} />
      )}

      {/* Forensic Alert inspection modal */}
      {inspectedAlert && (
        <AlertModal alert={inspectedAlert} onClose={() => setInspectedAlert(null)} />
      )}
    </div>
  );
}

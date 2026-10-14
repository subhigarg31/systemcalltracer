import React, { useState } from 'react';
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
import { useSystem } from './context/SystemContext';

export default function App() {
  const [activeTab, setActiveTab] = useState('overview');
  const { inspectedEvent, setInspectedEvent, inspectedAlert, setInspectedAlert } = useSystem();

  const renderActiveTab = () => {
    switch (activeTab) {
      case 'overview':
        return <Overview onNavigateTab={setActiveTab} />;
      case 'live-feed':
        return <LiveFeed />;
      case 'alerts':
        return <Alerts />;
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

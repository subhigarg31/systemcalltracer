import React, { createContext, useContext, useState, useEffect, useRef, useCallback } from 'react';

const SystemContext = createContext(null);

export function SystemProvider({ children }) {
  const [connectionStatus, setConnectionStatus] = useState('connecting');
  const [session, setSession] = useState({
    isRunning: false,
    currentMode: 'automatic',
    startTime: new Date().toISOString(),
    lastEventTimestamp: null
  });

  const [metrics, setMetrics] = useState({
    totalEvents: 0,
    totalAlerts: 0,
    activeAlerts: 0,
    highCritAlerts: 0,
    currentRiskScore: 0,
    riskBand: 'Low',
    categoryCounts: { file: 0, network: 0, process: 0, memory: 0 },
    timeSeries: []
  });

  const [events, setEvents] = useState([]);
  const [alerts, setAlerts] = useState([]);
  const [processes, setProcesses] = useState([]);
  const [isPaused, setIsPaused] = useState(false);
  const [pausedBufferCount, setPausedBufferCount] = useState(0);
  const [maxDisplayRows, setMaxDisplayRows] = useState(250);

  // Kernel freeze guard (eBPF)
  const [kernelStatus, setKernelStatus] = useState('off');
  const [kernelEntries, setKernelEntries] = useState([]);
  const [kernelToast, setKernelToast] = useState(null);
  const kernelToastTimeoutRef = useRef(null);
  
  // Modals / Drawers
  const [inspectedEvent, setInspectedEvent] = useState(null);
  const [inspectedAlert, setInspectedAlert] = useState(null);

  const pausedRef = useRef(isPaused);
  pausedRef.current = isPaused;

  const maxRowsRef = useRef(maxDisplayRows);
  maxRowsRef.current = maxDisplayRows;

  const wsRef = useRef(null);
  const reconnectTimeoutRef = useRef(null);

  const connectWebSocket = useCallback(() => {
    if (wsRef.current && (wsRef.current.readyState === WebSocket.OPEN || wsRef.current.readyState === WebSocket.CONNECTING)) {
      return;
    }

    const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
    // If running in Vite dev server (port 5173), connect to backend port 3001
    const wsUrl = window.location.port === '5173'
      ? `${protocol}//${window.location.hostname}:3001`
      : `${protocol}//${window.location.host}`;

    try {
      const ws = new WebSocket(wsUrl);
      wsRef.current = ws;

      ws.onopen = () => {
        setConnectionStatus('connected');
        console.log('[SystemContext] WebSocket connected.');
      };

      ws.onmessage = (event) => {
        try {
          const message = JSON.parse(event.data);
          handleWebSocketMessage(message);
        } catch (err) {
          console.warn('[SystemContext] Message parse error:', err);
        }
      };

      ws.onclose = () => {
        setConnectionStatus('disconnected');
        wsRef.current = null;
        reconnectTimeoutRef.current = setTimeout(connectWebSocket, 2000);
      };

      ws.onerror = () => {
        setConnectionStatus('disconnected');
        try { ws.close(); } catch (_) {}
      };
    } catch (err) {
      setConnectionStatus('disconnected');
      reconnectTimeoutRef.current = setTimeout(connectWebSocket, 3000);
    }
  }, []);

  const handleWebSocketMessage = (message) => {
    switch (message.type) {
      case 'INITIAL_STATE': {
        const { session: sess, metrics: met, recentEvents, alerts: alts, processes: procs, kernel } = message.data;
        if (sess) setSession(prev => ({ ...prev, ...sess }));
        if (met) setMetrics(prev => ({ ...prev, ...met }));
        if (recentEvents) setEvents(recentEvents.slice(0, maxRowsRef.current));
        if (alts) setAlerts(alts);
        if (procs) setProcesses(procs);
        if (kernel) {
          setKernelStatus(kernel.status || 'off');
          setKernelEntries(kernel.entries || []);
        }
        break;
      }
      case 'KERNEL_FROZEN': {
        const entry = message.data;
        setKernelEntries(prev => [entry, ...prev.filter(e => e.pid !== entry.pid)]);
        setKernelToast(entry);
        if (kernelToastTimeoutRef.current) clearTimeout(kernelToastTimeoutRef.current);
        kernelToastTimeoutRef.current = setTimeout(() => setKernelToast(null), 6000);
        break;
      }
      case 'KERNEL_UPDATE': {
        const entry = message.data;
        setKernelEntries(prev => prev.map(e => e.pid === entry.pid ? { ...e, ...entry } : e));
        break;
      }
      case 'EVENT': {
        const newEvent = message.data;
        setSession(prev => ({
          ...prev,
          lastEventTimestamp: newEvent.timestamp
        }));

        if (pausedRef.current) {
          setPausedBufferCount(prev => prev + 1);
        } else {
          setEvents(prev => {
            const next = [newEvent, ...prev];
            return next.slice(0, maxRowsRef.current);
          });
        }
        break;
      }
      case 'ALERT': {
        const newAlert = message.data;
        setAlerts(prev => [newAlert, ...prev.filter(a => a.alertId !== newAlert.alertId)]);
        break;
      }
      case 'ALERT_ACKNOWLEDGED': {
        const acked = message.data;
        setAlerts(prev => prev.map(a => a.alertId === acked.alertId ? { ...a, status: 'acknowledged', acknowledgedAt: acked.acknowledgedAt } : a));
        break;
      }
      case 'METRICS': {
        setMetrics(prev => ({ ...prev, ...message.data }));
        break;
      }
      case 'STATUS_CHANGE': {
        const status = message.data;
        setSession(prev => ({
          ...prev,
          isRunning: status.isRunning,
          currentMode: status.mode
        }));
        break;
      }
      default:
        break;
    }
  };

  useEffect(() => {
    connectWebSocket();
    fetchProcesses();

    const procInterval = setInterval(fetchProcesses, 4000);

    return () => {
      clearInterval(procInterval);
      if (reconnectTimeoutRef.current) clearTimeout(reconnectTimeoutRef.current);
      if (kernelToastTimeoutRef.current) clearTimeout(kernelToastTimeoutRef.current);
      if (wsRef.current) wsRef.current.close();
    };
  }, [connectWebSocket]);

  // Initial HTTP hydration & process poll
  const fetchProcesses = async () => {
    try {
      const res = await fetch('/api/processes');
      if (res.ok) {
        const data = await res.json();
        setProcesses(data.processes || []);
      }
    } catch (_) {}
  };

  const startSimulation = async (mode = 'automatic', interval = 200) => {
    try {
      const res = await fetch('/api/simulator/start', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ mode, interval })
      });
      if (res.ok) {
        setSession(prev => ({ ...prev, isRunning: true, currentMode: mode }));
      }
    } catch (err) {
      console.error('Error starting simulator:', err);
    }
  };

  const stopSimulation = async () => {
    try {
      const res = await fetch('/api/simulator/stop', { method: 'POST' });
      if (res.ok) {
        setSession(prev => ({ ...prev, isRunning: false }));
      }
    } catch (err) {
      console.error('Error stopping simulator:', err);
    }
  };

  const setSimulationMode = async (mode) => {
    try {
      const res = await fetch('/api/simulator/mode', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ mode })
      });
      if (res.ok) {
        setSession(prev => ({ ...prev, currentMode: mode }));
      }
    } catch (err) {
      console.error('Error updating mode:', err);
    }
  };

  // ---- Kernel freeze guard ----
  const fetchKernelStatus = async () => {
    try {
      const res = await fetch('/api/kernel/status');
      if (res.ok) {
        const data = await res.json();
        setKernelStatus(data.status || 'off');
        setKernelEntries(data.entries || []);
      }
    } catch (_) {}
  };

  const kernelPost = async (url) => {
    const res = await fetch(url, { method: 'POST' });
    const data = await res.json().catch(() => ({}));
    if (!res.ok) throw new Error(data.error || `Request failed (${res.status})`);
    return data;
  };

  const armKernel = async () => {
    const data = await kernelPost('/api/kernel/start');
    if (data.status) setKernelStatus(data.status);
    return data;
  };

  const disarmKernel = async () => {
    const data = await kernelPost('/api/kernel/stop');
    setKernelStatus('off');
    return data;
  };

  // The server broadcasts KERNEL_UPDATE too; updating here keeps the UI right if the socket lags.
  const updateKernelEntry = (data) => {
    if (data.entry) setKernelEntries(prev => prev.map(e => e.pid === data.entry.pid ? { ...e, ...data.entry } : e));
  };

  const resumeKernelProcess = async (pid) => {
    const data = await kernelPost(`/api/kernel/${pid}/resume`);
    updateKernelEntry(data);
    return data;
  };

  const killKernelProcess = async (pid) => {
    const data = await kernelPost(`/api/kernel/${pid}/kill`);
    updateKernelEntry(data);
    return data;
  };

  const togglePause = () => {
    setIsPaused(prev => {
      if (prev) {
        // Resuming: clear paused buffer counter
        setPausedBufferCount(0);
      }
      return !prev;
    });
  };

  const acknowledgeAlert = async (alertId) => {
    try {
      const res = await fetch(`/api/alerts/${alertId}/acknowledge`, { method: 'POST' });
      if (res.ok) {
        const data = await res.json();
        setAlerts(prev => prev.map(a => a.alertId === alertId ? data.alert : a));
        setMetrics(prev => ({
          ...prev,
          activeAlerts: Math.max(0, prev.activeAlerts - 1),
          currentRiskScore: data.risk ? data.risk.score : prev.currentRiskScore,
          riskBand: data.risk ? data.risk.band : prev.riskBand
        }));
      }
    } catch (err) {
      console.error('Error acknowledging alert:', err);
    }
  };

  const resetSession = async () => {
    try {
      const res = await fetch('/api/reset', { method: 'POST' });
      if (res.ok) {
        setEvents([]);
        setAlerts([]);
        setProcesses([]);
        setPausedBufferCount(0);
        setMetrics({
          totalEvents: 0,
          totalAlerts: 0,
          activeAlerts: 0,
          highCritAlerts: 0,
          currentRiskScore: 0,
          riskBand: 'Low',
          categoryCounts: { file: 0, network: 0, process: 0, memory: 0 },
          timeSeries: []
        });
      }
    } catch (err) {
      console.error('Error resetting session:', err);
    }
  };

  const value = {
    connectionStatus,
    session,
    metrics,
    events,
    alerts,
    processes,
    isPaused,
    pausedBufferCount,
    maxDisplayRows,
    setMaxDisplayRows,
    inspectedEvent,
    setInspectedEvent,
    inspectedAlert,
    setInspectedAlert,
    startSimulation,
    stopSimulation,
    setSimulationMode,
    togglePause,
    acknowledgeAlert,
    resetSession,
    fetchProcesses,
    kernelStatus,
    kernelEntries,
    kernelToast,
    setKernelToast,
    fetchKernelStatus,
    armKernel,
    disarmKernel,
    resumeKernelProcess,
    killKernelProcess
  };

  return (
    <SystemContext.Provider value={value}>
      {children}
    </SystemContext.Provider>
  );
}

export function useSystem() {
  const ctx = useContext(SystemContext);
  if (!ctx) throw new Error('useSystem must be used within a SystemProvider');
  return ctx;
}

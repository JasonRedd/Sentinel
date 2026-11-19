'use client';

import React, { useState, useEffect } from 'react';
import { ShieldAlert, Cpu, Activity } from 'lucide-react';

export default function SentinelDashboard() {
  const [alerts, setAlerts] = useState<any[]>([]);
  const [chains, setChains] = useState<any[]>([]);

  const fetchChains = async () => {
    try {
      const res = await fetch('http://localhost:8000/api/threats/chains');
      const data = await res.json();
      if (data.status === 'success') setChains(data.attack_chains);
    } catch (e) {
      console.error('Failed to fetch attack chains', e);
    }
  };
  const [vector, setVector] = useState('[65000.0, 950.0, 3389.0]');
  const [mlResult, setMlResult] = useState<any>(null);

  const fetchAlerts = async () => {
    try {
      const res = await fetch('http://localhost:8000/api/alerts');
      const data = await res.json();
      if (data.status === 'success') {
        setAlerts(data.alerts || data.data || []);
      } else if (Array.isArray(data)) {
        setAlerts(data);
      }
    } catch (e) {
      console.error('Failed to fetch alerts', e);
    }
  };

  useEffect(() => {
    fetchAlerts();
    fetchChains();
    const interval = setInterval(fetchAlerts, 5000);
    return () => clearInterval(interval);
  }, []);

  const handleScore = async () => {
    try {
      const parsed = JSON.parse(vector);
      const res = await fetch('http://localhost:8000/api/ml/score', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ features: parsed })
      });
      const data = await res.json();
      setMlResult(data);
    } catch (e) {
      console.error('Failed to score vector', e);
    }
  };

  return (
    <div className='p-8 max-w-7xl mx-auto text-slate-100 font-sans'>
      <div className='mb-8'>
        <h1 className='text-3xl font-bold flex items-center gap-3 font-mono'>
          <ShieldAlert className='text-red-500 w-8 h-8' /> SENTINEL // NDR Cockpit
        </h1>
        <p className='text-sm text-slate-400 font-mono mt-1'>Enterprise Network Threat Detection & Response • CachyOS Node</p>
      </div>

      <div className='grid grid-cols-4 gap-4 mb-6'>
        <div className='bg-slate-900 border border-slate-800 p-4 rounded-xl'>
          <p className='text-xs text-slate-400 font-mono'>TOTAL ALERTS</p>
          <p className='text-2xl font-bold text-slate-100 font-mono'>{alerts.length}</p>
        </div>
        <div className='bg-slate-900 border border-slate-800 p-4 rounded-xl'>
          <p className='text-xs text-slate-400 font-mono'>ML ENGINE STATUS</p>
          <p className='text-2xl font-bold text-emerald-400 font-mono'>ONLINE</p>
        </div>
        <div className='bg-slate-900 border border-slate-800 p-4 rounded-xl'>
          <p className='text-xs text-slate-400 font-mono'>MITIGATION GATEWAY</p>
          <p className='text-2xl font-bold text-cyan-400 font-mono'>ACTIVE</p>
        </div>
        <div className='bg-slate-900 border border-slate-800 p-4 rounded-xl'>
          <p className='text-xs text-slate-400 font-mono'>SECURITY NODE</p>
          <p className='text-2xl font-bold text-indigo-400 font-mono'>CachyOS</p>
        </div>
      </div>

      <div className='bg-slate-900 border border-slate-800 rounded-xl p-6 mb-8 shadow-xl'>
        <h2 className='text-lg font-semibold mb-4 flex items-center gap-2 font-mono text-red-400'>
          <Activity className='w-5 h-5' /> Live Suricata Threat Feed
        </h2>
        <div className='overflow-x-auto'>
          <table className='w-full text-left text-sm font-mono border-collapse'>
            <thead>
              <tr className='border-b border-slate-800 text-slate-400'>
                <th className='px-4 py-3'>SEVERITY</th>
                <th className='px-4 py-3'>TIMESTAMP</th>
                <th className='px-4 py-3'>SOURCE IP</th>
                <th className='px-4 py-3'>DESTINATION IP</th>
                <th className='px-4 py-3'>SIGNATURE</th>
              </tr>
            </thead>
            <tbody>
              {alerts.length === 0 ? (
                <tr>
                  <td colSpan={5} className='px-4 py-6 text-center text-slate-500'>No active threat logs detected in eve.json</td>
                </tr>
              ) : (
                alerts.map((alert, idx) => (
                  <tr key={idx} className='border-b border-slate-800/50 hover:bg-slate-800/30'>
                    <td className='px-4 py-3 text-red-400 font-bold'>{alert.severity}</td>
                    <td className='px-4 py-3 text-slate-300'>{alert.timestamp}</td>
                    <td className='px-4 py-3 text-cyan-400'>{alert.src_ip}</td>
                    <td className='px-4 py-3 text-indigo-400'>{alert.dest_ip}</td>
                    <td className='px-4 py-3 text-slate-100'>{alert.signature}</td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </div>
      </div>

      <div className='bg-slate-900 border border-slate-800 rounded-xl p-6 shadow-xl'>
        <h2 className='text-lg font-semibold mb-4 flex items-center gap-2 font-mono text-cyan-400'>
          <Cpu className='w-5 h-5' /> Isolation Forest ML Engine
        </h2>
        <div className='flex gap-4 mb-4'>
          <input 
            type='text' 
            value={vector} 
            onChange={(e) => setVector(e.target.value)}
            className='bg-slate-950 border border-slate-800 rounded-lg px-4 py-2 font-mono text-sm flex-1 focus:outline-none focus:border-cyan-500'
          />
          <button 
            onClick={handleScore}
            className='bg-cyan-600 hover:bg-cyan-500 font-mono text-sm px-6 py-2 rounded-lg font-semibold transition'
          >
            Score Traffic Vector
          </button>
        </div>
        {mlResult && (
          <div className='bg-slate-950 border border-slate-800 rounded-lg p-4 font-mono text-sm'>
            <p>
              <span className='text-slate-400'>Status:</span>{' '}
              <span className={mlResult.anomaly ? 'text-red-400 font-semibold' : 'text-emerald-400'}>
                {mlResult.anomaly ? 'Anomaly Detected' : 'Normal'}
              </span>
            </p>
            <p>
              <span className='text-slate-400'>Anomaly:</span>{' '}
              <span className={mlResult.anomaly ? 'text-red-400' : 'text-emerald-400'}>
                {String(mlResult.anomaly)}
              </span>
            </p>
          </div>
        )}
      </div>

      <div className="bg-slate-900 border border-slate-800 rounded-xl p-6 shadow-xl mt-8">
        <h2 className="text-lg font-semibold mb-4 flex items-center gap-2 font-mono text-indigo-400">
          <Activity className="w-5 h-5" /> Attack Chain Reconstruction (Kill Chain)
        </h2>
        <div className="space-y-4 font-mono text-sm">
          {chains.length === 0 ? (
            <p className="text-slate-500">No correlated attack chains detected across network telemetry.</p>
          ) : (
            chains.map((chain, idx) => (
              <div key={idx} className="bg-slate-950 border border-slate-800 rounded-lg p-4">
                <div className="flex justify-between items-center mb-2">
                  <span className="text-cyan-400 font-bold">Source IP: {chain.source_ip}</span>
                  <span className="text-xs bg-red-950 text-red-400 border border-red-800 px-2 py-0.5 rounded">
                    Events: {chain.total_events}
                  </span>
                </div>
                <p className="text-xs text-slate-400 mb-3">Tactics Observed: {chain.tactics_observed.join(', ')}</p>
                <div className="space-y-2 border-l-2 border-indigo-500/30 pl-4 ml-2">
                  {chain.timeline.map((event: any, eIdx: number) => (
                    <div key={eIdx} className="text-xs">
                      <span className="text-slate-400">{event.timestamp}</span> → <span className="text-red-300 font-semibold">{event.signature}</span> <span className="text-indigo-300">[{event.tactic}]</span>
                    </div>
                  ))}
                </div>
              </div>
            ))
          )}
        </div>
      </div>
    </div>
  );
}

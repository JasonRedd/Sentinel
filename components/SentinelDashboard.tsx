// @ts-nocheck
'use client';
import React, { useEffect, useState } from 'react';
import { ShieldAlert, Activity, Cpu, CheckCircle2 } from 'lucide-react';

export default function SentinelDashboard() {
  const [alerts, setAlerts] = useState([]);
  const [loading, setLoading] = useState(true);
  const [testSample, setTestSample] = useState('[65000.0, 950.0, 3389.0]');
  const [mlResult, setMlResult] = useState(null);

  const fetchAlerts = async () => {
    try {
      const res = await fetch('http://localhost:8000/api/alerts');
      const data = await res.json();
      if (data.status === 'success') setAlerts(data.alerts);
    } catch (e) {
      console.error(e);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchAlerts();
    const interval = setInterval(fetchAlerts, 5000);
    return () => clearInterval(interval);
  }, []);

  const runAnomalyTest = async () => {
    try {
      const res = await fetch('http://localhost:8000/api/ml/detect', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(JSON.parse(testSample)),
      });
      setMlResult(await res.json());
    } catch (e) {
      console.error(e);
    }
  };

  return (
    <div className='min-h-screen bg-slate-950 text-slate-100 p-6 font-sans'>
      <header className='flex justify-between items-center border-b border-slate-800 pb-4 mb-6'>
        <div>
          <h1 className='text-2xl font-bold tracking-wider flex items-center gap-2'>
            <ShieldAlert className='text-red-500' /> SENTINEL // NDR Cockpit
          </h1>
          <p className='text-xs text-slate-400'>Enterprise Network Threat Detection & Response • CachyOS Node</p>
        </div>
      </header>
      <div className='grid grid-cols-1 lg:grid-cols-3 gap-6'>
        <div className='lg:col-span-2 bg-slate-900 border border-slate-800 rounded-xl p-5'>
          <h2 className='text-lg font-semibold mb-4 flex items-center gap-2 text-red-400'>
            <Activity size={18} /> Live Suricata Threat Feed
          </h2>
          {loading ? <p className='text-slate-500 text-sm'>Loading...</p> : (
            <div className='overflow-x-auto max-h-[480px] overflow-y-auto'>
              <table className='w-full text-left text-xs'>
                <thead className='bg-slate-950 text-slate-400 uppercase'>
                  <tr>
                    <th className='p-3'>Severity</th>
                    <th className='p-3'>Timestamp</th>
                    <th className='p-3'>Source IP</th>
                    <th className='p-3'>Destination IP</th>
                    <th className='p-3'>Signature</th>
                  </tr>
                </thead>
                <tbody className='divide-y divide-slate-800'>
                  {alerts.map((a) => (
                    <tr key={a.id} className='hover:bg-slate-800/50'>
                      <td className='p-3'><span className='px-2 py-0.5 rounded bg-red-950 text-red-400 font-bold'>Sev {a.severity}</span></td>
                      <td className='p-3 text-slate-400'>{new Date(a.timestamp).toLocaleTimeString()}</td>
                      <td className='p-3 font-mono text-cyan-400'>{a.src_ip}</td>
                      <td className='p-3 font-mono text-slate-300'>{a.dest_ip}</td>
                      <td className='p-3 text-slate-200'>{a.signature}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </div>
        <div className='bg-slate-900 border border-slate-800 rounded-xl p-5 flex flex-col justify-between'>
          <div>
            <h2 className='text-lg font-semibold mb-4 flex items-center gap-2 text-cyan-400'>
              <Cpu size={18} /> Isolation Forest ML Engine
            </h2>
            <input 
              type='text' 
              value={testSample} 
              onChange={(e) => setTestSample(e.target.value)}
              className='w-full bg-slate-950 border border-slate-800 rounded-lg p-2 text-xs font-mono text-slate-200 mb-3'
            />
            <button 
              onClick={runAnomalyTest}
              className='w-full bg-cyan-600 hover:bg-cyan-500 text-slate-950 font-semibold py-2 rounded-lg text-xs transition'
            >
              Score Traffic Vector
            </button>
            {mlResult && (
              <div className='mt-4 p-3 rounded-lg bg-slate-950 border border-slate-800 text-xs space-y-1'>
                <p>Status: <span className={mlResult.anomaly_detected ? 'text-red-400 font-bold' : 'text-emerald-400 font-bold'}>{mlResult.score}</span></p>
                <p>Anomaly: <span className='font-mono'>{String(mlResult.anomaly_detected)}</span></p>
              </div>
            )}
          </div>
        </div>
      </div>
    </div>
  );
}

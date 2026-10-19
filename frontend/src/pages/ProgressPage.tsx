import React, { useEffect, useState } from 'react';
import { useNavigate, useParams } from 'react-router-dom';
import { fetchAnalysis } from '../api/client';

export const ProgressPage: React.FC = () => {
  const { id } = useParams<{ id: string }>();
  const [analysis, setAnalysis] = useState<any>(null);
  const [error, setError] = useState<string | null>(null);
  const navigate = useNavigate();

  useEffect(() => {
    if (!id) return;

    let timer: any;

    const poll = async () => {
      try {
        const data = await fetchAnalysis(id);
        setAnalysis(data);

        if (data.status === 'completed') {
          navigate(`/analyses/${id}`);
        } else if (data.status === 'failed') {
          setError(data.error_detail || 'Analysis failed to execute.');
        } else {
          timer = setTimeout(poll, 1000);
        }
      } catch (err: any) {
        setError(err?.error?.message || 'Failed to poll analysis progress.');
      }
    };

    poll();

    return () => {
      if (timer) clearTimeout(timer);
    };
  }, [id, navigate]);

  const stages = [
    { key: 'validating', label: 'Validating capture magic header & bounds', minProgress: 5 },
    { key: 'reading', label: 'Streaming frames & defragmenting IPv4', minProgress: 20 },
    { key: 'reconstructing', label: 'Reconstructing IKE sessions & tracking ESP flows', minProgress: 55 },
    { key: 'evaluating', label: 'Evaluating security rules & detecting cleartext', minProgress: 75 },
    { key: 'scoring', label: 'Computing risk scores, posture, & fix-first ranks', minProgress: 90 },
    { key: 'complete', label: 'Finalizing audit artifact and reports', minProgress: 100 },
  ];

  const progressPct = analysis?.progress || 10;

  return (
    <div className="max-w-3xl mx-auto px-4 py-16 space-y-8">
      <div className="text-center space-y-3">
        <div className="inline-block p-4 rounded-full bg-sky-950/80 border border-sky-500/30 text-sky-400 text-3xl animate-pulse">
          ⚡
        </div>
        <h1 className="text-2xl font-bold text-white">Analyzing Packet Capture</h1>
        <p className="text-sm text-slate-400">
          Target: <span className="font-mono text-slate-200">{analysis?.filename || 'capture.pcap'}</span> ·
          Analysis ID: <span className="font-mono text-sky-400">{id?.slice(0, 8)}...</span>
        </p>
      </div>

      {error ? (
        <div className="bg-red-950/40 border border-red-800 rounded-xl p-6 text-center space-y-4">
          <div className="text-3xl text-red-400">❌</div>
          <div className="font-bold text-white text-lg">Analysis Failed</div>
          <p className="text-sm text-red-300 font-mono bg-red-950/60 p-3 rounded">{error}</p>
          <button
            onClick={() => navigate('/new')}
            className="px-4 py-2 rounded bg-slate-800 hover:bg-slate-700 text-white text-sm"
          >
            Upload Another Capture
          </button>
        </div>
      ) : (
        <div className="bg-slate-900 border border-slate-800 rounded-2xl p-8 space-y-6 shadow-xl">
          {/* Progress Bar */}
          <div className="space-y-2">
            <div className="flex justify-between text-xs font-semibold text-slate-300">
              <span>Overall Progress</span>
              <span className="text-sky-400 font-bold">{progressPct}%</span>
            </div>
            <div className="w-full h-3 bg-slate-950 rounded-full overflow-hidden border border-slate-800">
              <div
                className="h-full bg-gradient-to-r from-sky-500 to-indigo-500 transition-all duration-500 ease-out"
                style={{ width: `${progressPct}%` }}
              />
            </div>
          </div>

          {/* Stepper Checklist */}
          <div className="space-y-3 pt-4 border-t border-slate-800">
            {stages.map((stage, idx) => {
              const isDone = progressPct >= stage.minProgress;
              const isCurrent = progressPct < stage.minProgress && (idx === 0 || progressPct >= stages[idx - 1].minProgress);

              return (
                <div
                  key={stage.key}
                  className={`flex items-center gap-3 text-sm p-2 rounded transition-colors ${
                    isCurrent ? 'bg-sky-950/40 text-sky-300 border border-sky-800/50' : 'text-slate-400'
                  }`}
                >
                  <span className="w-5 text-center">
                    {isDone ? '✅' : isCurrent ? '⏳' : '⚪'}
                  </span>
                  <span className={isDone ? 'text-slate-300 font-medium' : isCurrent ? 'font-bold text-white' : ''}>
                    {stage.label}
                  </span>
                </div>
              );
            })}
          </div>

          <div className="text-center pt-2 text-xs text-slate-500">
            Page will automatically redirect once the assessment completes.
          </div>
        </div>
      )}
    </div>
  );
};

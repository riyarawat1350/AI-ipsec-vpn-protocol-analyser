import React, { useEffect, useState } from 'react';
import { useSearchParams } from 'react-router-dom';
import { compareAnalyses, fetchAnalyses } from '../api/client';
import { SeverityBadge } from '../components/SeverityBadge';
import { CheckCircle2, AlertTriangle, ArrowUpDown, RefreshCw } from 'lucide-react';

export const ComparePage: React.FC = () => {
  const [searchParams] = useSearchParams();
  const [analyses, setAnalyses] = useState<any[]>([]);
  const [baselineId, setBaselineId] = useState<string>(searchParams.get('baseline') || '');
  const [candidateId, setCandidateId] = useState<string>(searchParams.get('candidate') || '');
  const [comparison, setComparison] = useState<any>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  // Load completed analyses for dropdown selectors
  useEffect(() => {
    const loadList = async () => {
      try {
        const res = await fetchAnalyses(1, 20, 'completed');
        setAnalyses(res.items || []);
        if (!baselineId && res.items?.length > 1) {
          setBaselineId(res.items[1].id);
        }
        if (!candidateId && res.items?.length > 0) {
          setCandidateId(res.items[0].id);
        }
      } catch (e) {
        // Non-fatal if list fails
      }
    };
    loadList();
  }, []);

  const handleCompare = async () => {
    if (!baselineId || !candidateId) {
      setError('Please select both a baseline and a candidate capture.');
      return;
    }
    try {
      setLoading(true);
      setError(null);
      const res = await compareAnalyses(baselineId, candidateId);
      setComparison(res);
    } catch (err: any) {
      setError(err?.error?.message || 'Failed to compare captures');
    } finally {
      setLoading(false);
    }
  };

  const delta = comparison?.score_delta ?? 0;
  const isPositive = delta > 0;
  const isNegative = delta < 0;

  return (
    <div className="max-w-7xl mx-auto px-4 py-8 space-y-8">
      {/* Header */}
      <div className="border-b border-slate-800 pb-5">
        <h1 className="text-2xl font-bold text-white flex items-center gap-2.5">
          <ArrowUpDown className="w-6 h-6 text-sky-400" /> Capture Comparison & Security Delta
        </h1>
        <p className="text-xs text-slate-400 mt-1">
          Differential analysis comparing a baseline capture against a candidate capture to verify remediations and catch regressions.
        </p>
      </div>

      {/* Selectors Bar */}
      <div className="bg-slate-900 border border-slate-800 p-6 rounded-2xl shadow-xl space-y-4">
        <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
          {/* Baseline Picker */}
          <div className="space-y-1.5">
            <label className="text-xs font-mono text-slate-400 uppercase">
              Baseline Capture (Before):
            </label>
            <select
              value={baselineId}
              onChange={(e) => setBaselineId(e.target.value)}
              className="w-full bg-slate-950 border border-slate-800 text-white rounded-lg px-3 py-2 text-xs focus:outline-none focus:border-sky-500 font-mono"
            >
              <option value="">-- Select Baseline Capture --</option>
              {analyses.map((a) => (
                <option key={a.id} value={a.id}>
                  {a.filename || a.id.slice(0, 10)} (Score: {a.posture_score?.toFixed(0) ?? 'N/A'})
                </option>
              ))}
            </select>
          </div>

          {/* Candidate Picker */}
          <div className="space-y-1.5">
            <label className="text-xs font-mono text-slate-400 uppercase">
              Candidate Capture (After Remediation):
            </label>
            <select
              value={candidateId}
              onChange={(e) => setCandidateId(e.target.value)}
              className="w-full bg-slate-950 border border-slate-800 text-white rounded-lg px-3 py-2 text-xs focus:outline-none focus:border-sky-500 font-mono"
            >
              <option value="">-- Select Candidate Capture --</option>
              {analyses.map((a) => (
                <option key={a.id} value={a.id}>
                  {a.filename || a.id.slice(0, 10)} (Score: {a.posture_score?.toFixed(0) ?? 'N/A'})
                </option>
              ))}
            </select>
          </div>
        </div>

        <div className="flex justify-end pt-2">
          <button
            onClick={handleCompare}
            disabled={loading}
            className="px-6 py-2.5 rounded-xl bg-sky-500 hover:bg-sky-400 disabled:opacity-50 text-slate-950 font-bold text-xs shadow-lg transition-all flex items-center gap-2"
          >
            {loading ? <RefreshCw className="w-4 h-4 animate-spin" /> : <ArrowUpDown className="w-4 h-4" />}
            <span>Compare Captures</span>
          </button>
        </div>
      </div>

      {error && (
        <div className="p-4 rounded-xl bg-red-950/40 border border-red-800 text-red-300 text-xs">
          {error}
        </div>
      )}

      {/* Comparison Results */}
      {comparison && (
        <div className="space-y-6">
          {/* Delta Hero Card */}
          <div className="grid grid-cols-1 sm:grid-cols-3 gap-4">
            <div className="p-5 rounded-2xl bg-slate-900 border border-slate-800 text-center shadow-md">
              <div className="text-xs text-slate-400">Baseline Score</div>
              <div className="text-3xl font-black text-white font-mono mt-1">
                {Number(comparison.baseline_score || 0).toFixed(1)}
              </div>
            </div>

            <div className={`p-5 rounded-2xl border text-center shadow-md ${
              isPositive
                ? 'bg-emerald-950/20 border-emerald-800/60'
                : isNegative
                ? 'bg-red-950/20 border-red-800/60'
                : 'bg-slate-900 border-slate-800'
            }`}>
              <div className="text-xs text-slate-400">Posture Score Delta (ΔP)</div>
              <div className={`text-3xl font-black font-mono mt-1 ${
                isPositive ? 'text-emerald-400' : isNegative ? 'text-red-400' : 'text-slate-300'
              }`}>
                {delta > 0 ? `+${delta.toFixed(1)}` : delta.toFixed(1)}
              </div>
              <div className="text-[10px] text-slate-400 mt-1">
                {isPositive ? 'Remediation Verified' : isNegative ? 'Security Regression' : 'No Change'}
              </div>
            </div>

            <div className="p-5 rounded-2xl bg-slate-900 border border-slate-800 text-center shadow-md">
              <div className="text-xs text-slate-400">Candidate Score</div>
              <div className="text-3xl font-black text-white font-mono mt-1">
                {Number(comparison.candidate_score || 0).toFixed(1)}
              </div>
            </div>
          </div>

          {/* Finding Comparison Columns */}
          <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
            {/* Resolved Findings */}
            <div className="bg-slate-900 border border-slate-800 rounded-2xl p-5 shadow-lg space-y-3">
              <div className="flex items-center justify-between border-b border-slate-800 pb-2">
                <h3 className="text-sm font-bold text-emerald-400 flex items-center gap-2">
                  <CheckCircle2 className="w-4 h-4" /> Resolved Vulnerabilities
                </h3>
                <span className="text-xs font-mono text-emerald-400 font-bold">
                  {comparison.resolved_findings?.length || 0}
                </span>
              </div>
              {(!comparison.resolved_findings || comparison.resolved_findings.length === 0) ? (
                <p className="text-xs text-slate-500 italic p-3">No resolved findings detected.</p>
              ) : (
                <div className="space-y-2">
                  {comparison.resolved_findings.map((f: any, idx: number) => (
                    <div key={idx} className="p-3 rounded-lg bg-slate-950/70 border border-emerald-950 space-y-1">
                      <div className="flex items-center gap-2">
                        <SeverityBadge severity={f.severity} size="sm" />
                        <span className="text-xs font-bold text-white">{f.title || f.rule_id}</span>
                      </div>
                      <div className="text-[11px] text-slate-400 line-clamp-1">{f.rule_id}</div>
                    </div>
                  ))}
                </div>
              )}
            </div>

            {/* New / Regressed Findings */}
            <div className="bg-slate-900 border border-slate-800 rounded-2xl p-5 shadow-lg space-y-3">
              <div className="flex items-center justify-between border-b border-slate-800 pb-2">
                <h3 className="text-sm font-bold text-red-400 flex items-center gap-2">
                  <AlertTriangle className="w-4 h-4" /> New Regressions
                </h3>
                <span className="text-xs font-mono text-red-400 font-bold">
                  {comparison.new_findings?.length || 0}
                </span>
              </div>
              {(!comparison.new_findings || comparison.new_findings.length === 0) ? (
                <p className="text-xs text-slate-500 italic p-3">Zero regressions flagged!</p>
              ) : (
                <div className="space-y-2">
                  {comparison.new_findings.map((f: any, idx: number) => (
                    <div key={idx} className="p-3 rounded-lg bg-slate-950/70 border border-red-950 space-y-1">
                      <div className="flex items-center gap-2">
                        <SeverityBadge severity={f.severity} size="sm" />
                        <span className="text-xs font-bold text-white">{f.title || f.rule_id}</span>
                      </div>
                      <div className="text-[11px] text-slate-400 line-clamp-1">{f.rule_id}</div>
                    </div>
                  ))}
                </div>
              )}
            </div>

            {/* Persistent Findings */}
            <div className="bg-slate-900 border border-slate-800 rounded-2xl p-5 shadow-lg space-y-3">
              <div className="flex items-center justify-between border-b border-slate-800 pb-2">
                <h3 className="text-sm font-bold text-slate-300 flex items-center gap-2">
                  <span>📌</span> Persistent Findings
                </h3>
                <span className="text-xs font-mono text-slate-400 font-bold">
                  {comparison.persistent_findings?.length || 0}
                </span>
              </div>
              {(!comparison.persistent_findings || comparison.persistent_findings.length === 0) ? (
                <p className="text-xs text-slate-500 italic p-3">No persistent findings.</p>
              ) : (
                <div className="space-y-2">
                  {comparison.persistent_findings.map((f: any, idx: number) => (
                    <div key={idx} className="p-3 rounded-lg bg-slate-950/70 border border-slate-800 space-y-1">
                      <div className="flex items-center gap-2">
                        <SeverityBadge severity={f.severity} size="sm" />
                        <span className="text-xs font-bold text-white">{f.title || f.rule_id}</span>
                      </div>
                      <div className="text-[11px] text-slate-400 line-clamp-1">{f.rule_id}</div>
                    </div>
                  ))}
                </div>
              )}
            </div>
          </div>
        </div>
      )}
    </div>
  );
};

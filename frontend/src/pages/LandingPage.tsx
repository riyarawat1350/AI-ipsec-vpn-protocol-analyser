import React, { useEffect, useState } from 'react';
import { Link, useNavigate } from 'react-router-dom';
import { deleteAnalysis, fetchAnalyses } from '../api/client';

export const LandingPage: React.FC = () => {
  const [analyses, setAnalyses] = useState<any[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const navigate = useNavigate();

  const loadData = async () => {
    try {
      setLoading(true);
      const res = await fetchAnalyses(1, 20);
      setAnalyses(res.items || []);
      setError(null);
    } catch (err: any) {
      setError(err?.error?.message || 'Failed to load analyses');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    loadData();
  }, []);

  const handleDelete = async (e: React.MouseEvent, id: string) => {
    e.stopPropagation();
    if (confirm('Are you sure you want to delete this analysis?')) {
      try {
        await deleteAnalysis(id);
        setAnalyses((prev) => prev.filter((a) => a.id !== id));
      } catch (err: any) {
        alert(err?.error?.message || 'Delete failed');
      }
    }
  };

  const getGradeBadge = (grade: string | null) => {
    const g = (grade || 'F').toUpperCase();
    const colors: Record<string, string> = {
      A: 'bg-emerald-950 text-emerald-400 border-emerald-600/40',
      B: 'bg-blue-950 text-blue-400 border-blue-600/40',
      C: 'bg-amber-950 text-amber-400 border-amber-600/40',
      D: 'bg-orange-950 text-orange-400 border-orange-600/40',
      F: 'bg-red-950 text-red-400 border-red-600/40',
    };
    return (
      <span className={`px-2.5 py-0.5 rounded-full text-xs font-black border ${colors[g] || colors.F}`}>
        GRADE {g}
      </span>
    );
  };

  return (
    <div className="max-w-7xl mx-auto px-4 py-8 space-y-8">
      {/* Hero Banner */}
      <div className="relative overflow-hidden rounded-2xl bg-gradient-to-r from-slate-900 via-sky-950 to-slate-900 border border-slate-800 p-8 shadow-2xl">
        <div className="relative z-10 max-w-3xl space-y-4">
          <div className="inline-flex items-center gap-2 px-3 py-1 rounded-full text-xs font-semibold bg-sky-500/10 text-sky-400 border border-sky-500/20">
            <span>🛡️</span> AI-Powered IPsec VPN Security Assessment Framework
          </div>
          <h1 className="text-4xl font-extrabold tracking-tight text-white sm:text-5xl">
            Audit IPsec VPN Traffic with Deterministic Cryptographic Evidence
          </h1>
          <p className="text-base text-slate-300">
            Passive, offline analysis of IKEv1, IKEv2, ESP, and AH packet captures. Reconstruct negotiations,
            benchmark cryptographic proposals against NIST SP 800-77, detect ESP-NULL cleartext, and produce prioritized
            remediations without requiring private keys.
          </p>
          <div className="flex flex-wrap gap-4 pt-2">
            <Link
              to="/new"
              className="inline-flex items-center gap-2 px-6 py-3 rounded-lg font-semibold bg-sky-500 hover:bg-sky-400 text-slate-950 shadow-lg shadow-sky-500/20 transition-all"
            >
              <span>📤</span> Upload Capture File
            </Link>
            <Link
              to="/compare"
              className="inline-flex items-center gap-2 px-6 py-3 rounded-lg font-semibold bg-slate-800 hover:bg-slate-700 text-slate-200 border border-slate-700 transition-all"
            >
              <span>⚖️</span> Compare Analyses
            </Link>
            <Link
              to="/about"
              className="inline-flex items-center gap-2 px-6 py-3 rounded-lg font-semibold bg-slate-800/60 hover:bg-slate-800 text-slate-400 hover:text-slate-200 transition-all"
            >
              <span>ℹ️</span> Capabilities & Standards
            </Link>
          </div>
        </div>
      </div>

      {/* Recent Analyses Header */}
      <div className="flex items-center justify-between">
        <div>
          <h2 className="text-xl font-bold text-white flex items-center gap-2">
            <span>📊</span> Recent Capture Analyses
          </h2>
          <p className="text-xs text-slate-400">
            Historical captures processed and indexed with posture ratings
          </p>
        </div>
        <button
          onClick={loadData}
          className="text-xs px-3 py-1.5 rounded bg-slate-800 hover:bg-slate-700 text-slate-300 border border-slate-700"
        >
          🔄 Refresh
        </button>
      </div>

      {/* Table / Content */}
      {loading ? (
        <div className="p-12 text-center text-slate-400">Loading capture history...</div>
      ) : error ? (
        <div className="p-6 rounded-lg bg-red-950/40 border border-red-800 text-red-300 text-sm">
          {error}
        </div>
      ) : analyses.length === 0 ? (
        <div className="text-center py-16 px-4 bg-slate-900 border border-slate-800 rounded-xl space-y-4">
          <div className="text-5xl">📁</div>
          <h3 className="text-lg font-semibold text-slate-200">No Captures Analyzed Yet</h3>
          <p className="text-sm text-slate-400 max-w-md mx-auto">
            Upload your first PCAP or PCAPNG capture file to begin evaluating IPsec security postures and discovering vulnerabilities.
          </p>
          <Link
            to="/new"
            className="inline-flex items-center gap-2 px-4 py-2 rounded-lg font-medium bg-sky-500 hover:bg-sky-400 text-slate-950 text-sm"
          >
            Start First Analysis
          </Link>
        </div>
      ) : (
        <div className="bg-slate-900 border border-slate-800 rounded-xl overflow-hidden shadow-lg">
          <table className="w-full text-left text-sm text-slate-300">
            <thead className="bg-slate-950 text-xs uppercase text-slate-400 border-b border-slate-800">
              <tr>
                <th className="py-3 px-4">Capture File</th>
                <th className="py-3 px-4">Status</th>
                <th className="py-3 px-4">Policy</th>
                <th className="py-3 px-4 text-center">Grade</th>
                <th className="py-3 px-4 text-center">Posture Score</th>
                <th className="py-3 px-4">Findings</th>
                <th className="py-3 px-4">Created</th>
                <th className="py-3 px-4 text-right">Actions</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800">
              {analyses.map((a) => {
                const totalFindings = Object.values(a.finding_counts || {}).reduce(
                  (sum: number, count: any) => sum + Number(count),
                  0
                );
                return (
                  <tr
                    key={a.id}
                    onClick={() => navigate(a.status === 'completed' ? `/analyses/${a.id}` : `/analyses/${a.id}/progress`)}
                    className="hover:bg-slate-800/40 cursor-pointer transition-colors"
                  >
                    <td className="py-3 px-4">
                      <div className="font-semibold text-white flex items-center gap-2">
                        <span>📦</span> {a.filename}
                      </div>
                      <div className="text-[11px] text-slate-500 font-mono">
                        ID: {a.id.slice(0, 8)}... · {(a.size_bytes / 1024).toFixed(1)} KB
                      </div>
                    </td>
                    <td className="py-3 px-4">
                      <span
                        className={`inline-block px-2 py-0.5 rounded text-xs font-semibold ${
                          a.status === 'completed'
                            ? 'bg-emerald-950 text-emerald-400 border border-emerald-800/50'
                            : a.status === 'running'
                            ? 'bg-sky-950 text-sky-400 border border-sky-800/50 animate-pulse'
                            : a.status === 'failed'
                            ? 'bg-red-950 text-red-400 border border-red-800/50'
                            : 'bg-slate-800 text-slate-400'
                        }`}
                      >
                        {a.status.toUpperCase()}
                      </span>
                    </td>
                    <td className="py-3 px-4 text-xs text-slate-400 font-mono">{a.policy}</td>
                    <td className="py-3 px-4 text-center">{getGradeBadge(a.grade)}</td>
                    <td className="py-3 px-4 text-center font-bold text-sky-400">
                      {a.posture_score !== null && a.posture_score !== undefined
                        ? a.posture_score.toFixed(1)
                        : '—'}
                    </td>
                    <td className="py-3 px-4">
                      {totalFindings > 0 ? (
                        <div className="flex gap-1 text-xs">
                          {a.finding_counts?.Critical > 0 && (
                            <span className="px-1.5 py-0.5 rounded bg-red-950 text-red-400 font-bold">
                              {a.finding_counts.Critical}C
                            </span>
                          )}
                          {a.finding_counts?.High > 0 && (
                            <span className="px-1.5 py-0.5 rounded bg-orange-950 text-orange-400 font-bold">
                              {a.finding_counts.High}H
                            </span>
                          )}
                          {a.finding_counts?.Medium > 0 && (
                            <span className="px-1.5 py-0.5 rounded bg-amber-950 text-amber-400">
                              {a.finding_counts.Medium}M
                            </span>
                          )}
                          {a.finding_counts?.Low > 0 && (
                            <span className="px-1.5 py-0.5 rounded bg-blue-950 text-blue-400">
                              {a.finding_counts.Low}L
                            </span>
                          )}
                        </div>
                      ) : (
                        <span className="text-xs text-slate-500">0 findings</span>
                      )}
                    </td>
                    <td className="py-3 px-4 text-xs text-slate-400">
                      {a.created_at ? new Date(a.created_at).toLocaleString() : '—'}
                    </td>
                    <td className="py-3 px-4 text-right space-x-2">
                      <Link
                        to={a.status === 'completed' ? `/analyses/${a.id}` : `/analyses/${a.id}/progress`}
                        className="px-2.5 py-1 rounded bg-slate-800 hover:bg-sky-600 text-xs font-medium text-slate-200 transition-colors"
                        onClick={(e) => e.stopPropagation()}
                      >
                        Open
                      </Link>
                      <button
                        onClick={(e) => handleDelete(e, a.id)}
                        className="px-2 py-1 rounded bg-red-950/40 hover:bg-red-900/60 text-red-400 text-xs transition-colors"
                      >
                        Delete
                      </button>
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
};

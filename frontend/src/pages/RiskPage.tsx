import React, { useEffect, useState } from 'react';
import { useParams } from 'react-router-dom';
import { fetchOverview, fetchFindings } from '../api/client';
import { AnalysisNav } from '../components/AnalysisNav';
import { PostureGauge } from '../components/PostureGauge';
import { SeverityBadge } from '../components/SeverityBadge';
import { Flame, Calculator, Award, Layers } from 'lucide-react';

export const RiskPage: React.FC = () => {
  const { id } = useParams<{ id: string }>();
  const [overview, setOverview] = useState<any>(null);
  const [findings, setFindings] = useState<any[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    if (!id) return;
    const load = async () => {
      try {
        setLoading(true);
        const [ovRes, finRes] = await Promise.all([
          fetchOverview(id),
          fetchFindings(id, { page: 1, page_size: 100 }),
        ]);
        setOverview(ovRes);
        setFindings(finRes.items || []);
        setError(null);
      } catch (err: any) {
        setError(err?.error?.message || 'Failed to load risk data');
      } finally {
        setLoading(false);
      }
    };
    load();
  }, [id]);

  if (loading) {
    return <div className="p-16 text-center text-slate-400">Loading risk assessment...</div>;
  }

  if (error || !overview) {
    return (
      <div className="max-w-7xl mx-auto px-4 py-8">
        <AnalysisNav />
        <div className="p-6 rounded-xl bg-red-950/40 border border-red-800 text-red-300 text-sm">{error}</div>
      </div>
    );
  }

  const posture = overview.posture || {};
  const score = posture.score !== undefined ? posture.score : 100.0;
  const grade = overview.grade || posture.grade || 'A';
  const rawScore = posture.raw_score ?? score;
  const caps = posture.applied_caps || [];


  return (
    <div className="max-w-7xl mx-auto px-4 py-8 space-y-6">
      <AnalysisNav />

      {/* Header */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 border-b border-slate-800 pb-5">
        <div>
          <h1 className="text-2xl font-bold text-white flex items-center gap-2.5">
            <Flame className="w-6 h-6 text-amber-500" /> Security Posture & Risk Mathematical Formulation
          </h1>
          <p className="text-xs text-slate-400 mt-1">
            Mathematical breakdown of compound vulnerability penalties and hard security caps.
          </p>
        </div>
      </div>

      {/* Score and Formula Overview Grid */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
        {/* Posture Gauge Card */}
        <div className="lg:col-span-4 bg-slate-900 border border-slate-800 rounded-2xl p-6 shadow-xl flex flex-col items-center justify-center">
          <h2 className="text-xs font-bold uppercase tracking-wider text-slate-400 mb-2">
            Final Posture Score
          </h2>
          <PostureGauge score={score} grade={grade} size={200} />

          <div className="mt-4 w-full space-y-2 text-xs font-mono border-t border-slate-800 pt-3">
            <div className="flex justify-between text-slate-300">
              <span>Raw Product Score:</span>
              <span className="font-bold text-white">{Number(rawScore).toFixed(1)} / 100</span>
            </div>
            <div className="flex justify-between text-slate-300">
              <span>Final Capped Score:</span>
              <span className="font-bold text-amber-400">{Number(score).toFixed(1)} / 100</span>
            </div>
            {caps.length > 0 && (
              <div className="text-[11px] text-red-400 bg-red-950/40 p-2 rounded border border-red-900">
                ⚠ Hard Cap Enforced: {caps.join(', ')}
              </div>
            )}
          </div>
        </div>

        {/* Formula Explanation Card */}
        <div className="lg:col-span-8 bg-slate-900 border border-slate-800 rounded-2xl p-6 shadow-xl space-y-4">
          <div className="flex items-center gap-2 border-b border-slate-800 pb-3">
            <Calculator className="w-5 h-5 text-sky-400" />
            <h2 className="text-base font-bold text-white">Posture Score Formula (NIST SP 800-77 Benchmark)</h2>
          </div>

          <div className="p-4 rounded-xl bg-slate-950 font-mono text-center text-sm text-sky-300 border border-slate-800 shadow-inner">
            P = 100 × ∏ [ 1 - 0.6 × min(R_i, 95) / 100 ]
          </div>

          <div className="space-y-2 text-xs text-slate-300 leading-relaxed">
            <p>
              Where <strong className="text-white font-mono">R_i ∈ [0, 100]</strong> represents the risk severity weight of each independent finding.
              A multiplier factor of 0.6 prevents single sub-95 vulnerabilities from annihilating the entire score, while compounding multiple failures aggressively.
            </p>
            <div className="grid grid-cols-1 sm:grid-cols-2 gap-3 pt-2">
              <div className="p-3 rounded-lg bg-slate-950/70 border border-slate-800">
                <div className="text-red-400 font-bold mb-1">Critical Severity Ceiling: ≤ 39 (Grade F)</div>
                <div className="text-[11px] text-slate-400">
                  Any finding marked Critical (e.g., ESP-NULL, Cleartext DES, Null Auth) enforces a hard posture score ceiling of 39 regardless of other parameters.
                </div>
              </div>
              <div className="p-3 rounded-lg bg-slate-950/70 border border-slate-800">
                <div className="text-orange-400 font-bold mb-1">High Severity Ceiling: ≤ 59 (Grade F/D)</div>
                <div className="text-[11px] text-slate-400">
                  Any High severity finding (e.g., DH Group 1/2, MD5, SHA-1 PRF) enforces a hard posture ceiling of 59.
                </div>
              </div>
            </div>
          </div>
        </div>
      </div>

      {/* Grade Scale Reference */}
      <div className="bg-slate-900 border border-slate-800 rounded-2xl p-6 shadow-md space-y-4">
        <h3 className="text-sm font-bold text-white flex items-center gap-2">
          <Award className="w-4 h-4 text-emerald-400" /> Letter Grade Mapping Standards
        </h3>
        <div className="grid grid-cols-2 sm:grid-cols-5 gap-3 font-mono text-center">
          <div className="p-3 rounded-xl bg-emerald-950/30 border border-emerald-800 text-emerald-400">
            <div className="text-2xl font-black">A</div>
            <div className="text-[11px] mt-1 text-slate-300">90 - 100</div>
            <div className="text-[10px] text-slate-400">Robust</div>
          </div>
          <div className="p-3 rounded-xl bg-blue-950/30 border border-blue-800 text-blue-400">
            <div className="text-2xl font-black">B</div>
            <div className="text-[11px] mt-1 text-slate-300">80 - 89.9</div>
            <div className="text-[10px] text-slate-400">Good</div>
          </div>
          <div className="p-3 rounded-xl bg-amber-950/30 border border-amber-800 text-amber-400">
            <div className="text-2xl font-black">C</div>
            <div className="text-[11px] mt-1 text-slate-300">70 - 79.9</div>
            <div className="text-[10px] text-slate-400">Adequate</div>
          </div>
          <div className="p-3 rounded-xl bg-orange-950/30 border border-orange-800 text-orange-400">
            <div className="text-2xl font-black">D</div>
            <div className="text-[11px] mt-1 text-slate-300">60 - 69.9</div>
            <div className="text-[10px] text-slate-400">Marginal</div>
          </div>
          <div className="p-3 rounded-xl bg-red-950/30 border border-red-800 text-red-400">
            <div className="text-2xl font-black">F</div>
            <div className="text-[11px] mt-1 text-slate-300">&lt; 60</div>
            <div className="text-[10px] text-slate-400">Failing</div>
          </div>
        </div>
      </div>

      {/* Findings Impact Breakdown Table */}
      <div className="bg-slate-900 border border-slate-800 rounded-2xl overflow-hidden shadow-lg">
        <div className="p-5 border-b border-slate-800 flex items-center justify-between">
          <h2 className="text-sm font-bold text-white flex items-center gap-2">
            <Layers className="w-4 h-4 text-sky-400" /> Cumulative Finding Multiplier Audit
          </h2>
          <span className="text-xs text-slate-500 font-mono">
            {findings.length} {findings.length === 1 ? 'finding' : 'findings'} evaluated
          </span>
        </div>

        {findings.length === 0 ? (
          <div className="p-8 text-center text-slate-400 text-xs">No active risk penalties evaluated.</div>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-left text-xs font-mono">
              <thead className="bg-slate-950/60 text-slate-400 uppercase text-[11px] border-b border-slate-800">
                <tr>
                  <th className="py-3 px-4">Severity</th>
                  <th className="py-3 px-4">Rule ID</th>
                  <th className="py-3 px-4">Title</th>
                  <th className="py-3 px-4 text-right">Risk (Ri)</th>
                  <th className="py-3 px-4 text-right">Factor Multiplier</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-800/60">
                {findings.map((f, idx) => {
                  const r = Number(f.risk_score || 0);
                  const factor = 1 - 0.6 * Math.min(r, 95) / 100;
                  return (
                    <tr key={idx} className="hover:bg-slate-800/40 transition-colors">
                      <td className="py-3 px-4">
                        <SeverityBadge severity={f.severity} size="sm" />
                      </td>
                      <td className="py-3 px-4 text-sky-400 font-bold">{f.rule_id}</td>
                      <td className="py-3 px-4 text-slate-200">{f.title}</td>
                      <td className="py-3 px-4 text-right text-amber-400 font-bold">{r.toFixed(1)}</td>
                      <td className="py-3 px-4 text-right text-white font-bold">{factor.toFixed(4)}x</td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        )}
      </div>
    </div>
  );
};

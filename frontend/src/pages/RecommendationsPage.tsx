import React, { useEffect, useState } from 'react';
import { useParams } from 'react-router-dom';
import { fetchRecommendations } from '../api/client';
import { AnalysisNav } from '../components/AnalysisNav';
import { CheckCircle2, Award } from 'lucide-react';

export const RecommendationsPage: React.FC = () => {
  const { id } = useParams<{ id: string }>();
  const [recs, setRecs] = useState<any[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    if (!id) return;
    const load = async () => {
      try {
        setLoading(true);
        const res = await fetchRecommendations(id);
        setRecs(res || []);
        setError(null);
      } catch (err: any) {
        setError(err?.error?.message || 'Failed to load recommendations');
      } finally {
        setLoading(false);
      }
    };
    load();
  }, [id]);

  return (
    <div className="max-w-7xl mx-auto px-4 py-8 space-y-6">
      <AnalysisNav />

      {/* Header */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 border-b border-slate-800 pb-5">
        <div>
          <h1 className="text-2xl font-bold text-white flex items-center gap-2.5">
            <CheckCircle2 className="w-6 h-6 text-emerald-400" /> Fix-First Prioritized Recommendations
          </h1>
          <p className="text-xs text-slate-400 mt-1">
            Ordered list of remediation actions ranked by posture improvement impact vs implementation effort.
          </p>
        </div>

        <div className="text-xs font-mono text-slate-400">
          <strong className="text-emerald-400 font-bold">{recs.length}</strong> prioritized actions
        </div>
      </div>

      {loading ? (
        <div className="p-16 text-center text-slate-400">Loading recommendations...</div>
      ) : error ? (
        <div className="p-6 rounded-xl bg-red-950/40 border border-red-800 text-red-300 text-sm">{error}</div>
      ) : recs.length === 0 ? (
        <div className="p-16 rounded-2xl bg-slate-900 border border-slate-800 text-center space-y-3">
          <Award className="w-12 h-12 text-emerald-400 mx-auto" />
          <h3 className="text-base font-bold text-slate-200">No Action Required</h3>
          <p className="text-xs text-slate-400 max-w-md mx-auto">
            Zero high-priority vulnerabilities were flagged in this capture. The evaluated IPsec configurations adhere to baseline security requirements.
          </p>
        </div>
      ) : (
        <div className="space-y-4">
          {recs.map((rec, index) => {
            const rank = rec.rank || index + 1;
            const effort = rec.effort || 'Medium';
            const impact = rec.risk_reduction_impact || rec.posture_gain || 0;

            const effortColor =
              effort === 'Low'
                ? 'bg-emerald-950/60 text-emerald-300 border-emerald-800'
                : effort === 'High'
                ? 'bg-red-950/60 text-red-300 border-red-800'
                : 'bg-amber-950/60 text-amber-300 border-amber-800';

            return (
              <div
                key={rec.id || index}
                className="bg-slate-900 border border-slate-800 rounded-2xl p-6 shadow-xl space-y-4 hover:border-slate-700 transition-all"
              >
                <div className="flex flex-col md:flex-row md:items-start justify-between gap-4">
                  {/* Rank badge + title */}
                  <div className="flex items-start gap-4">
                    <div className="w-9 h-9 rounded-xl bg-sky-500/10 border border-sky-500/30 flex items-center justify-center font-black text-sky-400 font-mono flex-shrink-0">
                      #{rank}
                    </div>

                    <div className="space-y-1.5">
                      <div className="flex flex-wrap items-center gap-2">
                        <span className={`text-[11px] font-bold px-2 py-0.5 rounded border uppercase ${effortColor}`}>
                          {effort} Effort
                        </span>

                        {rec.target_rule_ids && rec.target_rule_ids.length > 0 && (
                          <div className="flex flex-wrap gap-1">
                            {rec.target_rule_ids.map((r: string) => (
                              <span key={r} className="text-[10px] font-mono px-2 py-0.5 rounded bg-slate-950 text-slate-400 border border-slate-800">
                                {r}
                              </span>
                            ))}
                          </div>
                        )}
                      </div>

                      <h3 className="text-lg font-bold text-white">
                        {rec.title}
                      </h3>
                    </div>
                  </div>

                  {/* Impact badge */}
                  <div className="bg-slate-950 border border-slate-800 rounded-xl p-3 text-center md:text-right min-w-[130px] flex-shrink-0">
                    <div className="text-[10px] text-slate-500 uppercase font-mono">POSTURE DELTA</div>
                    <div className="text-xl font-black text-emerald-400 font-mono mt-0.5">
                      +{Number(impact).toFixed(1)}%
                    </div>
                    <div className="text-[10px] text-slate-400">Projected Gain</div>
                  </div>
                </div>

                {/* Action details */}
                <div className="p-4 rounded-xl bg-slate-950/60 border border-slate-800/80 text-xs text-slate-300 leading-relaxed">
                  <div className="font-semibold text-sky-400 uppercase tracking-wider text-[10px] mb-1">
                    Recommended Remediation:
                  </div>
                  <div>{rec.action || rec.description}</div>
                </div>

                {/* Configuration example if present */}
                {rec.configuration_example && (
                  <div className="space-y-1">
                    <div className="text-[10px] font-mono text-slate-400 uppercase">Configuration Snippet:</div>
                    <pre className="p-3 rounded-lg bg-slate-950 border border-slate-800 text-xs font-mono text-emerald-400 overflow-x-auto">
                      {rec.configuration_example}
                    </pre>
                  </div>
                )}
              </div>
            );
          })}
        </div>
      )}
    </div>
  );
};

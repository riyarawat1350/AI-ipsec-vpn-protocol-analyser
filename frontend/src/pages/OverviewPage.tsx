import React, { useEffect, useState } from 'react';
import { Link, useParams } from 'react-router-dom';
import { fetchOverview } from '../api/client';
import { PostureGauge } from '../components/PostureGauge';
import { SeverityBadge } from '../components/SeverityBadge';
import { AnalysisNav } from '../components/AnalysisNav';
import { Info } from 'lucide-react';

export const OverviewPage: React.FC = () => {
  const { id } = useParams<{ id: string }>();
  const [data, setData] = useState<any>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    if (!id) return;
    const load = async () => {
      try {
        setLoading(true);
        const res = await fetchOverview(id);
        setData(res);
        setError(null);
      } catch (err: any) {
        setError(err?.error?.message || 'Failed to load analysis overview');
      } finally {
        setLoading(false);
      }
    };
    load();
  }, [id]);

  if (loading) {
    return <div className="p-16 text-center text-slate-400">Loading analysis overview...</div>;
  }

  if (error || !data) {
    return (
      <div className="max-w-4xl mx-auto px-4 py-12">
        <div className="p-6 rounded-xl bg-red-950/40 border border-red-800 text-red-300 text-sm">
          {error || 'Analysis overview unavailable.'}
        </div>
      </div>
    );
  }

  const posture = data.posture || {};
  const score = posture.score !== undefined ? posture.score : 100.0;
  const grade = data.grade || posture.grade || 'A';
  const cap = data.capture || {};
  const ipsec = data.ipsec || {};
  const counts = data.severity_counts || {};

  const hasNoIpsec =
    (cap.total_packets || 0) > 0 &&
    (ipsec.ike_v1_sessions || 0) === 0 &&
    (ipsec.ike_v2_sessions || 0) === 0 &&
    (ipsec.esp_flows || 0) === 0 &&
    (ipsec.ah_flows || 0) === 0;

  return (
    <div className="max-w-7xl mx-auto px-4 py-8 space-y-6">
      <AnalysisNav />

      {hasNoIpsec && (
        <div className="p-4 rounded-xl bg-amber-950/40 border border-amber-800/80 text-amber-200 text-xs flex items-start gap-3">
          <Info className="w-5 h-5 text-amber-400 flex-shrink-0 mt-0.5" />
          <div className="space-y-1">
            <div className="font-bold text-amber-300 text-sm">Notice: No IPsec VPN Traffic Detected in Capture</div>
            <p className="leading-relaxed">
              This capture contains <strong>{cap.total_packets?.toLocaleString()}</strong> packets, but no IKE (ISAKMP) negotiations, ESP flows, or AH packets were identified. The traffic appears to consist of non-IPsec protocols (such as TCP/IPv6/HTTPS web traffic). Since no IPsec security associations or tunnels were present, no protocol vulnerabilities were evaluated.
            </p>
          </div>
        </div>
      )}

      {/* Top Banner */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 border-b border-slate-800 pb-6">
        <div>
          <div className="flex items-center gap-2 text-xs text-sky-400 font-mono mb-1">
            <span>PACKET AUDIT</span> · <span>ID: {id?.slice(0, 8)}...</span>
          </div>
          <h1 className="text-3xl font-extrabold text-white flex items-center gap-3">
            <span>📦</span> {data.filename || 'capture.pcap'}
          </h1>
          <p className="text-xs text-slate-400 mt-1">
            Total Packets: <strong>{cap.total_packets?.toLocaleString() || 0}</strong> ·
            Capture Size: <strong>{((cap.total_bytes || 0) / 1024).toFixed(1)} KB</strong> ·
            Duration: <strong>{(cap.duration_seconds || 0).toFixed(2)}s</strong>
          </p>
        </div>

        <div className="flex gap-2">
          <Link
            to={`/analyses/${id}/report`}
            className="px-4 py-2 rounded-lg bg-sky-500 hover:bg-sky-400 text-slate-950 font-bold text-sm shadow-md transition-all flex items-center gap-1.5"
          >
            <span>📄</span> Audit Report
          </Link>
          <Link
            to={`/analyses/${id}/fix-first`}
            className="px-4 py-2 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-200 font-semibold text-sm border border-slate-700 flex items-center gap-1.5"
          >
            <span>🔧</span> Fix-First List
          </Link>
        </div>
      </div>

      {/* Main Grid: Score Gauge + Executive Narrative */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
        {/* Posture Score Card */}
        <div className="lg:col-span-4 bg-slate-900 border border-slate-800 rounded-2xl p-6 shadow-xl flex flex-col items-center justify-center">
          <h2 className="text-sm font-semibold uppercase tracking-wider text-slate-400 mb-2">
            Security Posture Rating
          </h2>
          <PostureGauge score={score} grade={grade} size={200} />
          <div className="text-xs text-slate-500 text-center mt-2 px-4">
            Ground truth: NIST SP 800-77 Rev. 1 & RFC 8247 baseline policy
          </div>
        </div>

        {/* Executive Summary Narrative */}
        <div className="lg:col-span-8 bg-slate-900 border border-slate-800 rounded-2xl p-6 shadow-xl flex flex-col justify-between">
          <div className="space-y-4">
            <div className="flex items-center justify-between border-b border-slate-800 pb-3">
              <h2 className="text-lg font-bold text-white flex items-center gap-2">
                <span>📝</span> Executive Assessment Summary
              </h2>
              {data.narrative?.origin === 'llm' ? (
                <span className="text-[11px] font-medium px-2.5 py-0.5 rounded-full bg-indigo-950 text-indigo-300 border border-indigo-700/60 flex items-center gap-1 shadow-sm">
                  <span>✨</span> AI-generated summary, findings se verify karo
                </span>
              ) : (
                <span className="text-[11px] font-mono px-2 py-0.5 rounded bg-slate-800 text-slate-400 border border-slate-700">
                  template
                </span>
              )}
            </div>
            <p className="text-slate-300 text-sm leading-relaxed">
              {data.narrative?.executive_summary ||
                'Analysis concluded with no high-severity vulnerabilities flagged in the capture.'}
            </p>
          </div>

          {/* Severity Counters Bar */}
          <div className="grid grid-cols-5 gap-2 pt-6 border-t border-slate-800 mt-4 text-center">
            <div className="bg-red-950/30 border border-red-900/40 p-2.5 rounded-lg">
              <div className="text-xl font-black text-red-400">{counts.Critical || 0}</div>
              <div className="text-[10px] uppercase font-bold text-red-300">Critical</div>
            </div>
            <div className="bg-orange-950/30 border border-orange-900/40 p-2.5 rounded-lg">
              <div className="text-xl font-black text-orange-400">{counts.High || 0}</div>
              <div className="text-[10px] uppercase font-bold text-orange-300">High</div>
            </div>
            <div className="bg-amber-950/30 border border-amber-900/40 p-2.5 rounded-lg">
              <div className="text-xl font-black text-amber-400">{counts.Medium || 0}</div>
              <div className="text-[10px] uppercase font-bold text-amber-300">Medium</div>
            </div>
            <div className="bg-blue-950/30 border border-blue-900/40 p-2.5 rounded-lg">
              <div className="text-xl font-black text-blue-400">{counts.Low || 0}</div>
              <div className="text-[10px] uppercase font-bold text-blue-300">Low</div>
            </div>
            <div className="bg-slate-800/40 border border-slate-700/40 p-2.5 rounded-lg">
              <div className="text-xl font-black text-slate-300">{counts.Info || 0}</div>
              <div className="text-[10px] uppercase font-bold text-slate-400">Info</div>
            </div>
          </div>
        </div>
      </div>

      {/* Protocol & Flow Counters */}
      <div className="grid grid-cols-2 md:grid-cols-5 gap-4">
        <Link
          to={`/analyses/${id}/ike`}
          className="bg-slate-900 border border-slate-800 hover:border-sky-500/50 p-4 rounded-xl transition-all shadow-md group"
        >
          <div className="text-xs text-slate-400">IKEv2 Negotiations</div>
          <div className="text-2xl font-bold text-white group-hover:text-sky-400 mt-1">
            {ipsec.ike_v2_sessions || 0}
          </div>
          <div className="text-[11px] text-sky-400 mt-2 flex items-center gap-1">
            View Sessions →
          </div>
        </Link>

        <Link
          to={`/analyses/${id}/ike`}
          className="bg-slate-900 border border-slate-800 hover:border-sky-500/50 p-4 rounded-xl transition-all shadow-md group"
        >
          <div className="text-xs text-slate-400">IKEv1 Sessions</div>
          <div className="text-2xl font-bold text-white group-hover:text-sky-400 mt-1">
            {ipsec.ike_v1_sessions || 0}
          </div>
          <div className="text-[11px] text-sky-400 mt-2 flex items-center gap-1">
            View Sessions →
          </div>
        </Link>

        <Link
          to={`/analyses/${id}/esp`}
          className="bg-slate-900 border border-slate-800 hover:border-sky-500/50 p-4 rounded-xl transition-all shadow-md group"
        >
          <div className="text-xs text-slate-400">ESP Encrypted Flows</div>
          <div className="text-2xl font-bold text-white group-hover:text-sky-400 mt-1">
            {ipsec.esp_flows || 0}
          </div>
          <div className="text-[11px] text-sky-400 mt-2 flex items-center gap-1">
            Track Sequences →
          </div>
        </Link>

        <Link
          to={`/analyses/${id}/esp`}
          className="bg-slate-900 border border-slate-800 hover:border-sky-500/50 p-4 rounded-xl transition-all shadow-md group"
        >
          <div className="text-xs text-slate-400">AH Flows (Proto 51)</div>
          <div className="text-2xl font-bold text-white group-hover:text-sky-400 mt-1">
            {ipsec.ah_flows || 0}
          </div>
          <div className="text-[11px] text-sky-400 mt-2 flex items-center gap-1">
            Inspect Flows →
          </div>
        </Link>

        <Link
          to={`/analyses/${id}/protocols`}
          className="bg-slate-900 border border-slate-800 hover:border-sky-500/50 p-4 rounded-xl transition-all shadow-md group"
        >
          <div className="text-xs text-slate-400">NAT-T Encapsulated</div>
          <div className="text-2xl font-bold text-white group-hover:text-sky-400 mt-1">
            {ipsec.natt_flows || 0}
          </div>
          <div className="text-[11px] text-sky-400 mt-2 flex items-center gap-1">
            Protocols Breakdown →
          </div>
        </Link>
      </div>

      {/* Top Security Findings */}
      <div className="bg-slate-900 border border-slate-800 rounded-2xl p-6 shadow-xl space-y-4">
        <div className="flex items-center justify-between border-b border-slate-800 pb-3">
          <h2 className="text-lg font-bold text-white flex items-center gap-2">
            <span>⚠️</span> Prioritized Security Findings
          </h2>
          <Link
            to={`/analyses/${id}/findings`}
            className="text-xs text-sky-400 hover:underline font-semibold"
          >
            View All Findings →
          </Link>
        </div>

        {data.top_findings && data.top_findings.length > 0 ? (
          <div className="divide-y divide-slate-800">
            {data.top_findings.map((f: any) => (
              <div
                key={f._id || f.id}
                className="py-3 flex flex-col md:flex-row md:items-center justify-between gap-3 hover:bg-slate-800/30 p-2 rounded transition-colors"
              >
                <div className="space-y-1">
                  <div className="flex items-center gap-2">
                    <SeverityBadge severity={f.severity} size="sm" />
                    <span className="font-mono text-xs text-slate-400">{f.rule_id}</span>
                    <span className="font-semibold text-white text-sm">{f.title}</span>
                  </div>
                  <p className="text-xs text-slate-400 line-clamp-1">{f.explanation}</p>
                </div>

                <div className="flex items-center gap-4 self-end md:self-auto">
                  <div className="text-right">
                    <div className="text-xs font-mono font-bold text-sky-400">
                      Risk {f.risk_score?.toFixed(1)}
                    </div>
                    <div className="text-[10px] text-slate-500">
                      Impact {f.impact} · Likelihood {f.likelihood}
                    </div>
                  </div>
                  <Link
                    to={`/analyses/${id}/findings/${f._id || f.id}`}
                    className="px-3 py-1 rounded bg-slate-800 hover:bg-sky-600 text-xs font-medium text-slate-200 transition-colors"
                  >
                    Evidence
                  </Link>
                </div>
              </div>
            ))}
          </div>
        ) : (
          <div className="p-8 text-center text-slate-500 text-sm">
            No vulnerabilities or configuration weaknesses identified.
          </div>
        )}
      </div>
    </div>
  );
};

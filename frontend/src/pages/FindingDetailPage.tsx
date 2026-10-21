import React, { useEffect, useState } from 'react';
import { useParams, Link } from 'react-router-dom';
import { fetchFinding } from '../api/client';
import { AnalysisNav } from '../components/AnalysisNav';
import { SeverityBadge } from '../components/SeverityBadge';
import { HexViewer } from '../components/HexViewer';
import { Term } from '../components/Term';
import { ArrowLeft, Shield, BookOpen, Wrench, FileCode, ChevronDown, ChevronUp } from 'lucide-react';

export const FindingDetailPage: React.FC = () => {
  const { id, fid } = useParams<{ id: string; fid: string }>();
  const [finding, setFinding] = useState<any>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [showTechDetails, setShowTechDetails] = useState(false);
  const [isSimpleMode, setIsSimpleMode] = useState<boolean>(() => {
    return localStorage.getItem('ipsecscope_mode') !== 'technical';
  });

  useEffect(() => {
    const handleModeChange = () => {
      setIsSimpleMode(localStorage.getItem('ipsecscope_mode') !== 'technical');
    };
    window.addEventListener('mode_changed', handleModeChange);
    return () => window.removeEventListener('mode_changed', handleModeChange);
  }, []);

  useEffect(() => {
    if (!id || !fid) return;
    const load = async () => {
      try {
        setLoading(true);
        const res = await fetchFinding(id, fid);
        setFinding(res);
        setError(null);
      } catch (err: any) {
        setError(err?.error?.message || 'Failed to load finding details');
      } finally {
        setLoading(false);
      }
    };
    load();
  }, [id, fid]);

  if (loading) {
    return <div className="p-16 text-center text-slate-400">Loading finding details...</div>;
  }

  if (error || !finding) {
    return (
      <div className="max-w-7xl mx-auto px-4 py-8">
        <AnalysisNav />
        <div className="p-6 rounded-xl bg-red-950/40 border border-red-800 text-red-300 text-sm">
          {error || 'Finding not found.'}
        </div>
      </div>
    );
  }

  const evidenceList = Array.isArray(finding.evidence)
    ? finding.evidence
    : finding.evidence
    ? [finding.evidence]
    : [];

  const references = finding.references || [
    'NIST SP 800-77 Rev. 1: Guide to IPsec VPNs',
    'RFC 8247: Cryptographic Algorithm Implementation Requirements for IKEv2',
  ];

  const rScore = finding.risk_score !== undefined && finding.risk_score !== null
    ? Number(finding.risk_score).toFixed(1)
    : 'Not scored';

  const plainSummary = finding.plain_summary || finding.title;
  const plainImpact = finding.plain_impact || finding.why_this_matters || finding.explanation;
  const plainFix = finding.plain_fix || 'Review and reconfigure the parameter to match policy baseline.';
  const whyItMatters = finding.why_this_matters || finding.why_it_matters || finding.explanation;

  return (
    <div className="max-w-7xl mx-auto px-4 py-8 space-y-6">
      <AnalysisNav />

      {/* Breadcrumb */}
      <div className="flex items-center gap-2 text-xs text-slate-400">
        <Link to={`/analyses/${id}/findings`} className="hover:text-sky-400 flex items-center gap-1">
          <ArrowLeft className="w-3.5 h-3.5" /> Back to Findings
        </Link>
        <span>/</span>
        <span className="text-white font-mono">{finding.rule_id}</span>
      </div>

      {/* Hero Header */}
      <div className="bg-slate-900 border border-slate-800 rounded-2xl p-6 shadow-xl space-y-4">
        <div className="flex flex-col md:flex-row md:items-start justify-between gap-4 border-b border-slate-800 pb-4">
          <div className="space-y-2">
            <div className="flex items-center gap-2.5">
              <SeverityBadge severity={finding.severity} size="md" />
              <span className="text-xs font-mono px-2.5 py-0.5 rounded bg-slate-950 text-slate-300 border border-slate-800">
                {finding.rule_id}
              </span>
              <span className="text-xs font-mono text-slate-500 uppercase">
                <Term id={finding.category?.toLowerCase() || 'ipsec'}>{finding.category || 'General'}</Term>
              </span>
            </div>

            <h1 className="text-2xl font-bold text-white leading-tight">
              {finding.title}
            </h1>
          </div>

          <div className="bg-slate-950 border border-slate-800 rounded-xl p-3 text-center md:text-right min-w-[130px]">
            <div className="text-[10px] text-slate-500 uppercase font-mono">
              <Term id="risk-score">RISK SCORE (Ri)</Term>
            </div>
            <div className="text-2xl font-black text-amber-400 font-mono mt-0.5">
              {rScore === 'Not scored' ? rScore : `${rScore} / 100`}
            </div>
            <div className="text-[10px] text-slate-400 mt-0.5">Posture Factor</div>
          </div>
        </div>

        {/* Plain Language Card (Always visible first per Phase 4) */}
        <div className="bg-slate-950/80 border border-slate-800 rounded-xl p-5 space-y-3">
          <div className="flex items-center justify-between">
            <span className="text-xs font-bold text-sky-400 uppercase tracking-wider flex items-center gap-1.5">
              <Shield className="w-4 h-4 text-sky-400" /> Plain-Language Summary
            </span>
            <span className="text-[11px] text-slate-500 font-mono">Average sentence length &le; 20 words</span>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-3 gap-4 pt-1">
            <div className="p-3 rounded-lg bg-slate-900 border border-slate-800/80 space-y-1">
              <span className="text-[11px] font-bold text-slate-400 uppercase tracking-wider">1. What Was Found</span>
              <p className="text-xs text-slate-200 leading-relaxed font-medium">{plainSummary}</p>
            </div>

            <div className="p-3 rounded-lg bg-slate-900 border border-slate-800/80 space-y-1">
              <span className="text-[11px] font-bold text-amber-400/90 uppercase tracking-wider">2. What Could Happen</span>
              <p className="text-xs text-slate-300 leading-relaxed">{plainImpact}</p>
            </div>

            <div className="p-3 rounded-lg bg-slate-900 border border-slate-800/80 space-y-1">
              <span className="text-[11px] font-bold text-emerald-400 uppercase tracking-wider">3. What To Do</span>
              <p className="text-xs text-slate-300 leading-relaxed">{plainFix}</p>
            </div>
          </div>
        </div>
      </div>

      {/* Grid: Context & Actionable Guidance */}
      <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
        {/* Why it matters */}
        <div className="bg-slate-900 border border-slate-800 rounded-2xl p-6 shadow-lg space-y-3">
          <h2 className="text-sm font-bold text-white flex items-center gap-2">
            <Shield className="w-4 h-4 text-amber-400" /> Threat Context & Technical Rationale
          </h2>
          <p className="text-xs text-slate-300 leading-relaxed">
            {whyItMatters}
          </p>

          {rScore !== 'Not scored' && (
            <div className="pt-3 border-t border-slate-800 space-y-2">
              <div className="text-[11px] font-mono text-slate-400 uppercase">Risk Evaluation Factor:</div>
              <div className="p-2.5 rounded-lg bg-slate-950/60 border border-slate-800/80 text-xs text-slate-300 font-mono">
                Individual Impact: 1 - 0.6 &times; min({rScore}, 95)/100 ={' '}
                <strong className="text-amber-400">
                  {(1 - 0.6 * Math.min(Number(rScore), 95) / 100).toFixed(3)}
                </strong>
              </div>
            </div>
          )}
        </div>

        {/* Actionable Remediation */}
        <div className="bg-slate-900 border border-slate-800 rounded-2xl p-6 shadow-lg space-y-3">
          <h2 className="text-sm font-bold text-white flex items-center gap-2">
            <Wrench className="w-4 h-4 text-emerald-400" /> Actionable Remediation
          </h2>
          <p className="text-xs text-slate-300 leading-relaxed">
            {plainFix}
          </p>

          {/* Only display config snippet if actually present */}
          {finding.config_snippet && (
            <div className="pt-3 border-t border-slate-800">
              <div className="text-[11px] font-mono text-slate-400 uppercase mb-1">Recommended Configuration:</div>
              <pre className="p-3 rounded-lg bg-slate-950 font-mono text-xs text-emerald-400 border border-slate-800 overflow-x-auto">
                {finding.config_snippet}
              </pre>
            </div>
          )}
        </div>
      </div>

      {/* Technical Details Accordion (Toggleable in Simple View, open in Technical View) */}
      <div className="bg-slate-900 border border-slate-800 rounded-2xl overflow-hidden shadow-lg">
        <button
          onClick={() => setShowTechDetails(!showTechDetails)}
          className="w-full p-5 border-b border-slate-800 flex items-center justify-between text-left hover:bg-slate-800/40 transition-colors"
        >
          <div className="flex items-center gap-2">
            <FileCode className="w-4 h-4 text-sky-400" />
            <span className="text-sm font-bold text-white">Technical Audit Details & Byte Evidence</span>
            <span className="text-xs text-slate-500 font-mono">({evidenceList.length} evidence records)</span>
          </div>
          <div className="flex items-center gap-2 text-xs text-sky-400">
            <span>{showTechDetails ? 'Hide technical details' : 'Show technical details'}</span>
            {showTechDetails ? <ChevronUp className="w-4 h-4" /> : <ChevronDown className="w-4 h-4" />}
          </div>
        </button>

        {(showTechDetails || !isSimpleMode) && (
          <div className="p-5 space-y-6">
            {/* Impact, Likelihood & Confidence */}
            <div className="grid grid-cols-2 sm:grid-cols-4 gap-3 text-xs font-mono">
              <div className="bg-slate-950 p-2.5 rounded-lg border border-slate-800">
                <span className="text-slate-500 block uppercase">Impact Rating:</span>
                <span className="text-white font-bold text-sm">{finding.impact} / 5</span>
              </div>
              <div className="bg-slate-950 p-2.5 rounded-lg border border-slate-800">
                <span className="text-slate-500 block uppercase">Likelihood:</span>
                <span className="text-white font-bold text-sm">{finding.likelihood} / 5</span>
              </div>
              <div className="bg-slate-950 p-2.5 rounded-lg border border-slate-800">
                <span className="text-slate-500 block uppercase">Confidence:</span>
                <span className="text-white font-bold text-sm">{finding.confidence}</span>
              </div>
              <div className="bg-slate-950 p-2.5 rounded-lg border border-slate-800">
                <span className="text-slate-500 block uppercase">Severity:</span>
                <span className="text-white font-bold text-sm">{finding.severity}</span>
              </div>
            </div>

            {/* Evidence List */}
            {evidenceList.length === 0 ? (
              <div className="p-8 text-center text-xs text-slate-500 italic">
                No specific packet byte excerpts attached to this rule detection.
              </div>
            ) : (
              <div className="divide-y divide-slate-800/80 space-y-6">
                {evidenceList.map((ev: any, idx: number) => {
                  const hex = ev.hex_excerpt || ev.packet_hex || ev.hex_dump || ev.raw_bytes || '';
                  return (
                    <div key={idx} className="space-y-3 pt-4 first:pt-0">
                      <div className="flex flex-wrap items-center gap-3 text-xs font-mono">
                        {ev.packet_no && (
                          <span className="px-2 py-0.5 rounded bg-sky-950/70 border border-sky-800 text-sky-300">
                            Frame #{ev.packet_no}
                          </span>
                        )}
                        {ev.field_path && (
                          <span className="text-slate-300">
                            Field: <strong className="text-white">{ev.field_path}</strong>
                          </span>
                        )}
                        {ev.raw_value !== undefined && (
                          <span className="text-amber-400">
                            Raw Value: <strong>{String(ev.raw_value)}</strong>
                          </span>
                        )}
                        {ev.decoded && (
                          <span className="text-emerald-400">
                            Decoded: <strong>{ev.decoded}</strong>
                          </span>
                        )}
                      </div>

                      {ev.message && (
                        <p className="text-xs text-slate-400 font-mono">{ev.message}</p>
                      )}

                      {hex && (
                        <div className="mt-2">
                          <HexViewer hexString={hex} bytesPerRow={16} />
                        </div>
                      )}
                    </div>
                  );
                })}
              </div>
            )}
          </div>
        )}
      </div>

      {/* Standards & References */}
      <div className="bg-slate-900 border border-slate-800 rounded-2xl p-5 shadow-md space-y-3">
        <h3 className="text-xs font-bold text-slate-300 uppercase tracking-wider flex items-center gap-2">
          <BookOpen className="w-4 h-4 text-sky-400" /> References & Verified Standards
        </h3>
        <ul className="space-y-1.5 text-xs text-slate-400">
          {references.map((ref: string, idx: number) => (
            <li key={idx} className="flex items-center gap-2">
              <span className="text-sky-500">▪</span>
              <span>{ref}</span>
            </li>
          ))}
        </ul>
      </div>
    </div>
  );
};

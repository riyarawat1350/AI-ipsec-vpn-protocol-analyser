import React, { useEffect, useState } from 'react';
import { useParams, Link } from 'react-router-dom';
import { fetchFinding } from '../api/client';
import { AnalysisNav } from '../components/AnalysisNav';
import { SeverityBadge } from '../components/SeverityBadge';
import { HexViewer } from '../components/HexViewer';
import { ArrowLeft, Shield, BookOpen, Wrench, FileCode } from 'lucide-react';

export const FindingDetailPage: React.FC = () => {
  const { id, fid } = useParams<{ id: string; fid: string }>();
  const [finding, setFinding] = useState<any>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

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

  const rScore = finding.risk_score !== undefined ? Number(finding.risk_score).toFixed(1) : '0.0';

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
                {finding.category || 'General'}
              </span>
            </div>

            <h1 className="text-2xl font-bold text-white leading-tight">
              {finding.title}
            </h1>
          </div>

          <div className="bg-slate-950 border border-slate-800 rounded-xl p-3 text-center md:text-right min-w-[130px]">
            <div className="text-[10px] text-slate-500 uppercase font-mono">RISK SCORE (Ri)</div>
            <div className="text-2xl font-black text-amber-400 font-mono mt-0.5">{rScore} / 100</div>
            <div className="text-[10px] text-slate-400 mt-0.5">Posture Impact</div>
          </div>
        </div>

        {/* Description */}
        <div className="text-sm text-slate-300 leading-relaxed">
          {finding.description}
        </div>
      </div>

      {/* Grid: Why It Matters + Remediation */}
      <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
        {/* Why it matters */}
        <div className="bg-slate-900 border border-slate-800 rounded-2xl p-6 shadow-lg space-y-3">
          <h2 className="text-sm font-bold text-white flex items-center gap-2">
            <Shield className="w-4 h-4 text-amber-400" /> Why It Matters & Threat Context
          </h2>
          <p className="text-xs text-slate-300 leading-relaxed">
            {finding.why_it_matters ||
              'Weak cryptographic parameters or unauthenticated payloads leave the communication channel susceptible to passive eavesdropping, man-in-the-middle downgrade attacks, or replay exploits.'}
          </p>

          <div className="pt-3 border-t border-slate-800 space-y-2">
            <div className="text-[11px] font-mono text-slate-400 uppercase">Risk Evaluation Factor:</div>
            <div className="p-2.5 rounded-lg bg-slate-950/60 border border-slate-800/80 text-xs text-slate-300 font-mono">
              Individual Impact: 1 - 0.6 × min({rScore}, 95)/100 ={' '}
              <strong className="text-amber-400">
                {(1 - 0.6 * Math.min(Number(rScore), 95) / 100).toFixed(3)}
              </strong>
            </div>
          </div>
        </div>

        {/* Actionable Remediation */}
        <div className="bg-slate-900 border border-slate-800 rounded-2xl p-6 shadow-lg space-y-3">
          <h2 className="text-sm font-bold text-white flex items-center gap-2">
            <Wrench className="w-4 h-4 text-emerald-400" /> Actionable Remediation Guide
          </h2>
          <p className="text-xs text-slate-300 leading-relaxed">
            {finding.remediation ||
              'Update VPN gateway proposal configuration to disallow deprecated ciphers, weak Diffie-Hellman groups, or unauthenticated transforms.'}
          </p>

          <div className="pt-3 border-t border-slate-800">
            <div className="text-[11px] font-mono text-slate-400 uppercase mb-1">Recommended Configuration:</div>
            <div className="p-3 rounded-lg bg-slate-950 font-mono text-xs text-emerald-400 border border-slate-800 overflow-x-auto">
              ike = aes256gcm16-prfsha384-modp3072!<br />
              esp = aes256gcm16-modp3072!
            </div>
          </div>
        </div>
      </div>

      {/* Packet Evidence Section */}
      <div className="bg-slate-900 border border-slate-800 rounded-2xl overflow-hidden shadow-lg">
        <div className="p-5 border-b border-slate-800 flex items-center justify-between">
          <h2 className="text-sm font-bold text-white flex items-center gap-2">
            <FileCode className="w-4 h-4 text-sky-400" /> Packet-Level Evidence Excerpts
          </h2>
          <span className="text-xs text-slate-500 font-mono">
            {evidenceList.length} evidence records
          </span>
        </div>

        {evidenceList.length === 0 ? (
          <div className="p-8 text-center text-xs text-slate-500 italic">
            No specific packet byte excerpts attached to this rule detection.
          </div>
        ) : (
          <div className="divide-y divide-slate-800/80 p-5 space-y-6">
            {evidenceList.map((ev: any, idx: number) => {
              const hex = ev.packet_hex || ev.hex_dump || ev.raw_bytes || '';
              return (
                <div key={idx} className="space-y-3 pt-4 first:pt-0">
                  <div className="flex flex-wrap items-center gap-3 text-xs font-mono">
                    {ev.packet_number && (
                      <span className="px-2 py-0.5 rounded bg-sky-950/70 border border-sky-800 text-sky-300">
                        Frame #{ev.packet_number}
                      </span>
                    )}
                    {ev.field_name && (
                      <span className="text-slate-300">
                        Field: <strong className="text-white">{ev.field_name}</strong>
                      </span>
                    )}
                    {ev.value !== undefined && (
                      <span className="text-amber-400">
                        Value: <strong>{String(ev.value)}</strong>
                      </span>
                    )}
                    {ev.offset !== undefined && (
                      <span className="text-slate-500">
                        Offset: 0x{Number(ev.offset).toString(16)}
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

      {/* Standards & References */}
      <div className="bg-slate-900 border border-slate-800 rounded-2xl p-5 shadow-md space-y-3">
        <h3 className="text-xs font-bold text-slate-300 uppercase tracking-wider flex items-center gap-2">
          <BookOpen className="w-4 h-4 text-sky-400" /> References & Compliance Standards
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

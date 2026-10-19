import React, { useEffect, useState } from 'react';
import { useParams } from 'react-router-dom';
import { fetchProtocols } from '../api/client';
import { AnalysisNav } from '../components/AnalysisNav';
import { Network, ArrowUpDown, Shield } from 'lucide-react';

export const ProtocolsPage: React.FC = () => {
  const { id } = useParams<{ id: string }>();
  const [data, setData] = useState<any>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    if (!id) return;
    const load = async () => {
      try {
        setLoading(true);
        const res = await fetchProtocols(id);
        setData(res);
        setError(null);
      } catch (err: any) {
        setError(err?.error?.message || 'Failed to load protocol distribution');
      } finally {
        setLoading(false);
      }
    };
    load();
  }, [id]);

  if (loading) {
    return <div className="p-16 text-center text-slate-400">Loading protocol distribution...</div>;
  }

  if (error || !data) {
    return (
      <div className="max-w-6xl mx-auto px-4 py-8">
        <AnalysisNav />
        <div className="p-6 rounded-xl bg-red-950/40 border border-red-800 text-red-300 text-sm">
          {error || 'Protocol data unavailable.'}
        </div>
      </div>
    );
  }

  const dist = data.protocol_distribution || {};
  const counts = data.counts || {};
  const talkers = data.top_talkers || [];
  const nat = data.nat_traversal || {};
  const ikeVer = data.ike_versions || { v1: counts.ikev1 || 0, v2: counts.ikev2 || 0 };
  const totalPkts = data.capture?.total_packets || 1;

  const ikePkts = dist.ike_packets ?? ((counts.ikev2 || 0) + (counts.ikev1 || 0) + (counts.ike || 0));
  const espPkts = dist.esp_packets ?? (counts.esp || 0);
  const ahPkts = dist.ah_packets ?? (counts.ah || 0);
  const nattPkts = dist.nat_keepalive_packets ?? (counts.natt_keepalive || 0);
  const otherPkts = dist.other_packets ?? (counts.other || 0);

  const protocolCards = [
    { name: 'IKE (ISAKMP)', pkts: ikePkts, desc: 'UDP 500 / 4500 negotiations', color: 'border-sky-500/40 bg-sky-950/20 text-sky-400' },
    { name: 'ESP (IP 50)', pkts: espPkts, desc: 'Encapsulating Security Payload', color: 'border-emerald-500/40 bg-emerald-950/20 text-emerald-400' },
    { name: 'AH (IP 51)', pkts: ahPkts, desc: 'Authentication Header', color: 'border-amber-500/40 bg-amber-950/20 text-amber-400' },
    { name: 'NAT-T Keepalives', pkts: nattPkts, desc: 'UDP 4500 Single-byte 0xFF', color: 'border-indigo-500/40 bg-indigo-950/20 text-indigo-400' },
    { name: 'Other Traffic', pkts: otherPkts, desc: 'Non-IPsec bypass or cleartext', color: 'border-slate-700 bg-slate-900 text-slate-400' },
  ];

  return (
    <div className="max-w-7xl mx-auto px-4 py-8 space-y-6">
      <AnalysisNav />

      {/* Header */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 border-b border-slate-800 pb-5">
        <div>
          <h1 className="text-2xl font-bold text-white flex items-center gap-2.5">
            <Network className="w-6 h-6 text-sky-400" /> Protocol Distribution & Top Talkers
          </h1>
          <p className="text-xs text-slate-400 mt-1">
            Capture breakdown across IKE, ESP, AH, and UDP encapsulation endpoints.
          </p>
        </div>
        <div className="flex items-center gap-3">
          <span className="text-xs px-3 py-1.5 rounded-lg bg-slate-800 border border-slate-700 text-slate-300 font-mono">
            Total Packets: {totalPkts.toLocaleString()}
          </span>
        </div>
      </div>

      {/* Protocol Cards */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-5 gap-4">
        {protocolCards.map((p) => {
          const pct = ((p.pkts / (totalPkts || 1)) * 100).toFixed(1);
          return (
            <div key={p.name} className={`p-4 rounded-xl border ${p.color} shadow-sm`}>
              <div className="text-xs font-semibold uppercase tracking-wider">{p.name}</div>
              <div className="text-2xl font-extrabold text-white mt-2">{p.pkts.toLocaleString()}</div>
              <div className="text-[11px] text-slate-400 mt-1">{pct}% of capture</div>
              <div className="text-[10px] text-slate-500 mt-2 line-clamp-1">{p.desc}</div>
            </div>
          );
        })}
      </div>

      {/* NAT-T & IKE Summary Banner */}
      <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
        <div className="p-5 rounded-2xl bg-slate-900 border border-slate-800 shadow-md">
          <h2 className="text-sm font-bold text-white flex items-center gap-2 mb-3">
            <Shield className="w-4 h-4 text-sky-400" /> NAT Traversal (RFC 3948)
          </h2>
          <div className="space-y-2 text-xs">
            <div className="flex justify-between py-1.5 border-b border-slate-800 text-slate-300">
              <span>NAT-T Present:</span>
              <span className={`font-semibold ${nat.detected ? 'text-amber-400' : 'text-slate-400'}`}>
                {nat.detected ? 'Yes (Detected)' : 'No (Direct IP Encapsulation)'}
              </span>
            </div>
            <div className="flex justify-between py-1.5 border-b border-slate-800 text-slate-300">
              <span>UDP Port 4500 Flows:</span>
              <span className="font-mono text-white">{nat.port_4500_flows || 0}</span>
            </div>
            <div className="flex justify-between py-1.5 text-slate-300">
              <span>Non-ESP Marker Packets:</span>
              <span className="font-mono text-white">{nat.non_esp_marker_packets || 0}</span>
            </div>
          </div>
        </div>

        <div className="p-5 rounded-2xl bg-slate-900 border border-slate-800 shadow-md">
          <h2 className="text-sm font-bold text-white flex items-center gap-2 mb-3">
            <ArrowUpDown className="w-4 h-4 text-emerald-400" /> IKE Protocol Versions
          </h2>
          <div className="space-y-2 text-xs">
            <div className="flex justify-between py-1.5 border-b border-slate-800 text-slate-300">
              <span>IKEv2 Exchanges:</span>
              <span className="font-mono font-semibold text-emerald-400">{ikeVer.v2 || 0}</span>
            </div>
            <div className="flex justify-between py-1.5 border-b border-slate-800 text-slate-300">
              <span>IKEv1 Exchanges:</span>
              <span className={`font-mono font-semibold ${ikeVer.v1 ? 'text-amber-400' : 'text-slate-400'}`}>
                {ikeVer.v1 || 0} {ikeVer.v1 ? '(Deprecated protocol)' : ''}
              </span>
            </div>
            <div className="flex justify-between py-1.5 text-slate-300">
              <span>Unsupported Protocols:</span>
              <span className="font-mono text-slate-400">{data.unsupported_protocols?.length || 0}</span>
            </div>
          </div>
        </div>
      </div>

      {/* Top Talkers Table */}
      <div className="bg-slate-900 border border-slate-800 rounded-2xl overflow-hidden shadow-lg">
        <div className="px-6 py-4 border-b border-slate-800 flex items-center justify-between">
          <h2 className="text-base font-bold text-white flex items-center gap-2">
            <span>👥</span> Conversation Pairs (Top Talkers)
          </h2>
          <span className="text-xs text-slate-500 font-mono">{talkers.length} active pairs</span>
        </div>

        {talkers.length === 0 ? (
          <div className="p-8 text-center text-slate-500 text-sm">No conversation pairs detected in this capture.</div>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-left text-xs">
              <thead className="bg-slate-950/60 text-slate-400 font-mono uppercase text-[11px] border-b border-slate-800">
                <tr>
                  <th className="py-3 px-4">Endpoint A</th>
                  <th className="py-3 px-4">Endpoint B</th>
                  <th className="py-3 px-4 text-right">Packets</th>
                  <th className="py-3 px-4 text-right">Volume</th>
                  <th className="py-3 px-4 text-right">% Traffic</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-800/60 font-mono">
                {talkers.map((t: any, idx: number) => {
                  const pct = ((t.packets / (totalPkts || 1)) * 100).toFixed(1);
                  const kb = ((t.bytes || 0) / 1024).toFixed(1);
                  return (
                    <tr key={idx} className="hover:bg-slate-800/40 transition-colors">
                      <td className="py-3 px-4 font-mono">
                        <span className="text-sky-400 font-semibold">{t.endpoint_a || t.ip || 'Unknown'}</span>
                        {t.role_a && (
                          <span className="ml-2 text-[10px] font-sans font-bold px-1.5 py-0.5 rounded bg-sky-950 text-sky-400 border border-sky-800">
                            {t.role_a}
                          </span>
                        )}
                      </td>
                      <td className="py-3 px-4 font-mono">
                        <span className="text-indigo-400 font-semibold">{t.endpoint_b || '-'}</span>
                        {t.role_b && (
                          <span className="ml-2 text-[10px] font-sans font-bold px-1.5 py-0.5 rounded bg-indigo-950 text-indigo-400 border border-indigo-800">
                            {t.role_b}
                          </span>
                        )}
                      </td>
                      <td className="py-3 px-4 text-right text-white font-semibold">{(t.packets || 0).toLocaleString()}</td>
                      <td className="py-3 px-4 text-right text-slate-300">{kb} KB</td>
                      <td className="py-3 px-4 text-right text-slate-400">{pct}%</td>
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

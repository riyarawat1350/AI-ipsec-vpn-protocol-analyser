import React, { useEffect, useState } from 'react';
import { useParams, Link } from 'react-router-dom';
import { fetchEspFlows } from '../api/client';
import { AnalysisNav } from '../components/AnalysisNav';
import { ShieldAlert, AlertTriangle, Filter, Layers } from 'lucide-react';

export const EspFlowsPage: React.FC = () => {
  const { id } = useParams<{ id: string }>();
  const [flows, setFlows] = useState<any[]>([]);
  const [total, setTotal] = useState(0);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  // Filter
  const [protoFilter, setProtoFilter] = useState<string>('all');

  useEffect(() => {
    if (!id) return;
    const load = async () => {
      try {
        setLoading(true);
        const protoParam = protoFilter === 'all' ? undefined : protoFilter;
        const res = await fetchEspFlows(id, 1, 50, protoParam);
        setFlows(res.items || []);
        setTotal(res.total || 0);
        setError(null);
      } catch (err: any) {
        setError(err?.error?.message || 'Failed to load ESP flows');
      } finally {
        setLoading(false);
      }
    };
    load();
  }, [id, protoFilter]);

  // Aggregate metrics
  const totalPackets = flows.reduce((sum, f) => sum + (f.packets ?? f.packet_count ?? 0), 0);
  const totalBytes = flows.reduce((sum, f) => sum + (f.bytes ?? f.byte_count ?? 0), 0);
  const totalGaps = flows.reduce((sum, f) => {
    const g = f.seq?.gaps || f.seq_gaps || [];
    return sum + (Array.isArray(g) ? g.length : (g || 0));
  }, 0);
  const espNullCount = flows.filter((f) => f.null_suspected || f.esp_null_detected).length;

  return (
    <div className="max-w-7xl mx-auto px-4 py-8 space-y-6">
      <AnalysisNav />

      {/* Header */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 border-b border-slate-800 pb-5">
        <div>
          <h1 className="text-2xl font-bold text-white flex items-center gap-2.5">
            <ShieldAlert className="w-6 h-6 text-sky-400" /> ESP & AH Directional Flows
          </h1>
          <p className="text-xs text-slate-400 mt-1">
            Tracking sequence numbers, replay window gaps, ESP-NULL detection, and IKE association.
          </p>
        </div>

        <div className="flex items-center gap-3">
          <div className="flex items-center gap-1.5 text-xs text-slate-400 bg-slate-800/80 px-3 py-1.5 rounded-lg border border-slate-700">
            <Filter className="w-3.5 h-3.5 text-slate-400" />
            <span>Protocol:</span>
            <select
              value={protoFilter}
              onChange={(e) => setProtoFilter(e.target.value)}
              className="bg-transparent text-white font-medium focus:outline-none cursor-pointer"
            >
              <option value="all" className="bg-slate-800">All</option>
              <option value="ESP" className="bg-slate-800">ESP (50)</option>
              <option value="AH" className="bg-slate-800">AH (51)</option>
            </select>
          </div>
        </div>
      </div>

      {/* Metric Cards */}
      <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
        <div className="p-4 rounded-xl bg-slate-900 border border-slate-800 shadow-md">
          <div className="text-xs text-slate-400">Total Encrypted Flows</div>
          <div className="text-2xl font-black text-white mt-1">{flows.length}</div>
          <div className="text-[10px] text-slate-500 mt-1">{total} recorded in capture</div>
        </div>

        <div className="p-4 rounded-xl bg-slate-900 border border-slate-800 shadow-md">
          <div className="text-xs text-slate-400">Total Data Volume</div>
          <div className="text-2xl font-black text-white mt-1">{(totalBytes / 1024).toFixed(1)} KB</div>
          <div className="text-[10px] text-slate-500 mt-1">{totalPackets.toLocaleString()} packets</div>
        </div>

        <div className="p-4 rounded-xl bg-slate-900 border border-slate-800 shadow-md">
          <div className="text-xs text-slate-400">Sequence Gaps / Loss</div>
          <div className={`text-2xl font-black mt-1 ${totalGaps > 0 ? 'text-amber-400' : 'text-emerald-400'}`}>
            {totalGaps}
          </div>
          <div className="text-[10px] text-slate-500 mt-1">Potential packet drops</div>
        </div>

        <div className="p-4 rounded-xl bg-slate-900 border border-slate-800 shadow-md">
          <div className="text-xs text-slate-400">ESP-NULL Heuristics</div>
          <div className={`text-2xl font-black mt-1 ${espNullCount > 0 ? 'text-red-400' : 'text-slate-400'}`}>
            {espNullCount}
          </div>
          <div className="text-[10px] text-slate-500 mt-1">{espNullCount > 0 ? 'Unencrypted plaintext flag' : 'Zero unencrypted flagged'}</div>
        </div>
      </div>

      {loading ? (
        <div className="p-16 text-center text-slate-400">Loading ESP flows...</div>
      ) : error ? (
        <div className="p-6 rounded-xl bg-red-950/40 border border-red-800 text-red-300 text-sm">{error}</div>
      ) : flows.length === 0 ? (
        <div className="p-16 rounded-2xl bg-slate-900 border border-slate-800 text-center space-y-3">
          <Layers className="w-10 h-10 text-slate-600 mx-auto" />
          <h3 className="text-base font-bold text-slate-300">No ESP/AH Flows Found</h3>
          <p className="text-xs text-slate-500 max-w-md mx-auto">
            No active ESP or AH encapsulation traffic was detected matching the selected protocol criteria.
          </p>
        </div>
      ) : (
        <div className="space-y-3 font-mono">
          {flows.map((f) => {
            const fid = f.flow_id || f.id;
            const proto = (f.proto || f.protocol || 'ESP').toUpperCase();
            const isAh = proto === 'AH';
            const srcIp = f.src || f.src_ip || '0.0.0.0';
            const dstIp = f.dst || f.dst_ip || '0.0.0.0';
            const pkts = f.packets ?? f.packet_count ?? 0;
            const bytes = f.bytes ?? f.byte_count ?? 0;
            const maxSeq = f.seq?.max_seq ?? f.max_seq ?? pkts;
            const minSeq = f.seq?.min_seq ?? f.min_seq ?? (pkts > 0 ? 1 : 0);
            const gaps = f.seq?.gaps ? (Array.isArray(f.seq.gaps) ? f.seq.gaps.length : f.seq.gaps) : (Array.isArray(f.seq_gaps) ? f.seq_gaps.length : (f.seq_gaps || 0));
            const dups = f.seq?.duplicates ?? (Array.isArray(f.duplicates) ? f.duplicates.length : (f.duplicates || 0));
            const isNull = Boolean(f.null_suspected || f.esp_null_detected);

            return (
              <div
                key={fid}
                className="bg-slate-900 border border-slate-800 p-5 rounded-2xl shadow-md space-y-4 hover:border-slate-700 transition-colors"
              >
                <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 border-b border-slate-800/80 pb-3">
                  <div className="flex items-center gap-3">
                    <span className={`text-[11px] font-bold px-2 py-0.5 rounded border uppercase ${
                      isAh
                        ? 'bg-amber-950/60 text-amber-400 border-amber-800'
                        : 'bg-emerald-950/60 text-emerald-400 border-emerald-800'
                    }`}>
                      {proto}
                    </span>

                    <span className="text-sm font-bold text-white">
                      {srcIp} → {dstIp}
                    </span>

                    {f.encap && (
                      <span className="text-xs text-slate-400 font-mono">
                        ({f.encap.toUpperCase()})
                      </span>
                    )}

                    {isNull && (
                      <span className="text-[11px] font-bold px-2 py-0.5 rounded bg-red-950 text-red-400 border border-red-800 flex items-center gap-1">
                        <AlertTriangle className="w-3 h-3" /> ESP-NULL Flagged
                      </span>
                    )}
                  </div>

                  <div className="text-xs text-slate-400 flex items-center gap-3">
                    <span>SPI: <strong className="text-sky-400">{typeof f.spi === 'number' ? `0x${f.spi.toString(16)}` : f.spi}</strong></span>
                    {f.linked_ike_session_id && (
                      <Link
                        to={`/analyses/${id}/ike/${f.linked_ike_session_id}`}
                        className="text-sky-400 hover:underline flex items-center gap-1"
                      >
                        Linked IKE →
                      </Link>
                    )}
                  </div>
                </div>

                {/* Flow Plain Language Story */}
                <div className="p-3 rounded-xl bg-slate-950/70 border border-slate-800/80 text-xs text-slate-300 flex items-start gap-2.5 font-sans">
                  <span className="text-sm">📖</span>
                  <div className="leading-relaxed">
                    {f.story || `${pkts} ${proto} packets sent from ${srcIp} to ${dstIp}, sequences ${minSeq} to ${maxSeq} with ${gaps} gap(s).`}
                  </div>
                </div>

                {/* Flow Metrics Strip */}
                <div className="grid grid-cols-2 sm:grid-cols-4 gap-3 text-xs">
                  <div className="p-2.5 rounded-lg bg-slate-950/60 border border-slate-800/80">
                    <div className="text-slate-500 text-[10px]">PACKET COUNT</div>
                    <div className="text-white font-bold text-sm mt-0.5">{pkts.toLocaleString()}</div>
                    <div className="text-slate-400 text-[10px] mt-0.5">{(bytes / 1024).toFixed(1)} KB</div>
                  </div>

                  <div className="p-2.5 rounded-lg bg-slate-950/60 border border-slate-800/80">
                    <div className="text-slate-500 text-[10px]">SEQUENCE RANGE</div>
                    <div className="text-sky-300 font-bold text-sm mt-0.5">
                      {minSeq} ... {maxSeq}
                    </div>
                    <div className="text-slate-400 text-[10px] mt-0.5">Delta: {maxSeq - minSeq}</div>
                  </div>

                  <div className="p-2.5 rounded-lg bg-slate-950/60 border border-slate-800/80">
                    <div className="text-slate-500 text-[10px]">SEQUENCE GAPS</div>
                    <div className={`font-bold text-sm mt-0.5 ${gaps > 0 ? 'text-amber-400' : 'text-emerald-400'}`}>
                      {gaps}
                    </div>
                    <div className="text-slate-400 text-[10px] mt-0.5">
                      {gaps > 0 ? 'Missing seq numbers' : 'Continuous order'}
                    </div>
                  </div>

                  <div className="p-2.5 rounded-lg bg-slate-950/60 border border-slate-800/80">
                    <div className="text-slate-500 text-[10px]">REPLAY DUPLICATES</div>
                    <div className={`font-bold text-sm mt-0.5 ${dups > 0 ? 'text-red-400' : 'text-emerald-400'}`}>
                      {dups}
                    </div>
                    <div className="text-slate-400 text-[10px] mt-0.5">
                      {dups > 0 ? 'Repeated sequence IDs' : 'Clean window'}
                    </div>
                  </div>
                </div>
              </div>
            );
          })}
        </div>
      )}
    </div>
  );
};

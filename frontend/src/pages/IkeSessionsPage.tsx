import React, { useEffect, useState } from 'react';
import { useParams, Link } from 'react-router-dom';
import { fetchIkeSessions } from '../api/client';
import { AnalysisNav } from '../components/AnalysisNav';
import { KeyRound, ArrowRight, ShieldCheck, ShieldAlert, Filter } from 'lucide-react';

export const IkeSessionsPage: React.FC = () => {
  const { id } = useParams<{ id: string }>();
  const [sessions, setSessions] = useState<any[]>([]);
  const [total, setTotal] = useState(0);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  // Filters
  const [versionFilter, setVersionFilter] = useState<string>('all');
  const [outcomeFilter, setOutcomeFilter] = useState<string>('all');

  useEffect(() => {
    if (!id) return;
    const load = async () => {
      try {
        setLoading(true);
        const verNum = versionFilter === 'all' ? undefined : Number(versionFilter);
        const outVal = outcomeFilter === 'all' ? undefined : outcomeFilter;
        const res = await fetchIkeSessions(id, 1, 50, verNum, outVal);
        setSessions(res.items || []);
        setTotal(res.total || 0);
        setError(null);
      } catch (err: any) {
        setError(err?.error?.message || 'Failed to load IKE sessions');
      } finally {
        setLoading(false);
      }
    };
    load();
  }, [id, versionFilter, outcomeFilter]);

  return (
    <div className="max-w-7xl mx-auto px-4 py-8 space-y-6">
      <AnalysisNav />

      {/* Header */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 border-b border-slate-800 pb-5">
        <div>
          <h1 className="text-2xl font-bold text-white flex items-center gap-2.5">
            <KeyRound className="w-6 h-6 text-sky-400" /> IKE Sessions & Key Exchanges
          </h1>
          <p className="text-xs text-slate-400 mt-1">
            Reconstructed IKEv1 and IKEv2 handshakes ({total} total), cryptographic proposals, and outcome states.
          </p>
        </div>

        {/* Filter controls */}
        <div className="flex items-center gap-3">
          <div className="flex items-center gap-1.5 text-xs text-slate-400 bg-slate-800/80 px-3 py-1.5 rounded-lg border border-slate-700">
            <Filter className="w-3.5 h-3.5 text-slate-400" />
            <span>Version:</span>
            <select
              value={versionFilter}
              onChange={(e) => setVersionFilter(e.target.value)}
              className="bg-transparent text-white font-medium focus:outline-none cursor-pointer"
            >
              <option value="all" className="bg-slate-800">All</option>
              <option value="2" className="bg-slate-800">IKEv2</option>
              <option value="1" className="bg-slate-800">IKEv1</option>
            </select>
          </div>

          <div className="flex items-center gap-1.5 text-xs text-slate-400 bg-slate-800/80 px-3 py-1.5 rounded-lg border border-slate-700">
            <span>Outcome:</span>
            <select
              value={outcomeFilter}
              onChange={(e) => setOutcomeFilter(e.target.value)}
              className="bg-transparent text-white font-medium focus:outline-none cursor-pointer"
            >
              <option value="all" className="bg-slate-800">All</option>
              <option value="established" className="bg-slate-800">Established</option>
              <option value="failed" className="bg-slate-800">Failed</option>
              <option value="partial" className="bg-slate-800">Partial</option>
            </select>
          </div>
        </div>
      </div>

      {loading ? (
        <div className="p-16 text-center text-slate-400">Loading sessions...</div>
      ) : error ? (
        <div className="p-6 rounded-xl bg-red-950/40 border border-red-800 text-red-300 text-sm">
          {error}
        </div>
      ) : sessions.length === 0 ? (
        <div className="p-16 rounded-2xl bg-slate-900 border border-slate-800 text-center space-y-3">
          <KeyRound className="w-10 h-10 text-slate-600 mx-auto" />
          <h3 className="text-base font-bold text-slate-300">No IKE Sessions Found</h3>
          <p className="text-xs text-slate-500 max-w-md mx-auto">
            No IKE handshake exchanges matching the active filters were identified in this capture.
          </p>
        </div>
      ) : (
        <div className="space-y-3">
          {sessions.map((s) => {
            const sid = s.session_id || s.id;
            const isV2 = s.version === 2;
            const isEst = s.outcome === 'established';
            const isFailed = s.outcome === 'failed';

            return (
              <Link
                key={sid}
                to={`/analyses/${id}/ike/${sid}`}
                className="block bg-slate-900 border border-slate-800 hover:border-sky-500/50 p-5 rounded-2xl transition-all shadow-md group"
              >
                <div className="flex flex-col md:flex-row md:items-center justify-between gap-4">
                  {/* Left: Version + Endpoints + SPI */}
                  <div className="space-y-2">
                    <div className="flex items-center gap-2.5">
                      <span className={`text-[11px] font-bold px-2 py-0.5 rounded border uppercase ${
                        isV2
                          ? 'bg-sky-950/60 text-sky-400 border-sky-800'
                          : 'bg-amber-950/60 text-amber-400 border-amber-800'
                      }`}>
                        IKEv{s.version}
                      </span>

                      <span className={`text-[11px] font-bold px-2 py-0.5 rounded border flex items-center gap-1 ${
                        isEst
                          ? 'bg-emerald-950/60 text-emerald-400 border-emerald-800'
                          : isFailed
                          ? 'bg-red-950/60 text-red-400 border-red-800'
                          : 'bg-slate-800 text-slate-400 border-slate-700'
                      }`}>
                        {isEst ? <ShieldCheck className="w-3 h-3" /> : <ShieldAlert className="w-3 h-3" />}
                        {s.outcome || 'unknown'}
                      </span>

                      <span className="text-xs font-mono text-slate-400">
                        Messages: {s.message_count || s.messages?.length || 0}
                      </span>
                    </div>

                    {(() => {
                      const initIp = s.initiator?.ip || s.initiator_ip || '0.0.0.0';
                      const initPort = s.initiator?.port || s.initiator_port || 500;
                      const respIp = s.responder?.ip || s.responder_ip || '0.0.0.0';
                      const respPort = s.responder?.port || s.responder_port || 500;
                      const spiI = s.spi_i || s.initiator_spi || '';
                      const spiR = s.spi_r || s.responder_spi || '';
                      return (
                        <>
                          <div className="flex flex-wrap items-center gap-2 text-sm font-mono text-white">
                            <span className="text-sky-300">{initIp}:{initPort}</span>
                            <span className="text-slate-500">↔</span>
                            <span className="text-indigo-300">{respIp}:{respPort}</span>
                          </div>

                          <div className="text-[11px] font-mono text-slate-500 flex flex-wrap gap-x-4">
                            {spiI && <span>SPI-i: <strong className="text-slate-400">{spiI.slice(0, 16)}...</strong></span>}
                            {spiR && <span>SPI-r: <strong className="text-slate-400">{spiR.slice(0, 16)}...</strong></span>}
                          </div>
                        </>
                      );
                    })()}
                  </div>

                  {/* Right: Crypto Suite & Action */}
                  <div className="flex flex-col md:items-end justify-between gap-3">
                    <div className="text-xs text-right">
                      {(() => {
                        const sel = s.selected || s.selected_proposal;
                        if (!sel) {
                          return <div className="text-slate-500 text-xs italic">Encrypted or incomplete proposal</div>;
                        }
                        const transforms = sel.transforms || [];
                        const encr = transforms.find((t: any) => t.kind === 'ENCR')?.name || sel.encr || sel.cipher || 'AES-GCM';
                        const prf = transforms.find((t: any) => t.kind === 'PRF')?.name || sel.prf || 'HMAC-SHA256';
                        const dh = transforms.find((t: any) => t.kind === 'DH')?.name || sel.dh || sel.dh_group || '19';
                        return (
                          <div className="space-y-1">
                            <div className="text-[11px] text-slate-400">Selected Cipher:</div>
                            <div className="font-mono font-semibold text-emerald-400">{encr}</div>
                            <div className="text-[10px] font-mono text-slate-400">
                              PRF: {prf} · DH: {dh}
                            </div>
                          </div>
                        );
                      })()}
                    </div>

                    <div className="flex items-center gap-1.5 text-xs text-sky-400 group-hover:text-sky-300 font-semibold">
                      <span>Inspect Sequence Ladder</span>
                      <ArrowRight className="w-4 h-4 transition-transform group-hover:translate-x-1" />
                    </div>
                  </div>
                </div>
              </Link>
            );
          })}
        </div>
      )}
    </div>
  );
};

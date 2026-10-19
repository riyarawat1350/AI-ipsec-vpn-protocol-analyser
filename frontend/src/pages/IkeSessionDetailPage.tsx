import React, { useEffect, useState } from 'react';
import { useParams, Link } from 'react-router-dom';
import { fetchIkeSession } from '../api/client';
import { AnalysisNav } from '../components/AnalysisNav';
import { HandshakeLadder } from '../components/HandshakeLadder';
import { ProposalCompareTable } from '../components/ProposalCompareTable';
import { parseVendorId } from '../utils/formatters';
import { ArrowLeft, ShieldCheck, ShieldAlert, EyeOff } from 'lucide-react';

export const IkeSessionDetailPage: React.FC = () => {
  const { id, sid } = useParams<{ id: string; sid: string }>();
  const [session, setSession] = useState<any>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    if (!id || !sid) return;
    const load = async () => {
      try {
        setLoading(true);
        const res = await fetchIkeSession(id, sid);
        const sessData = res?.session
          ? {
              ...res.session,
              messages: res.messages || res.session.messages || [],
              findings: res.findings || [],
            }
          : res;
        setSession(sessData);
        setError(null);
      } catch (err: any) {
        setError(err?.error?.message || 'Failed to load IKE session details');
      } finally {
        setLoading(false);
      }
    };
    load();
  }, [id, sid]);

  if (loading) {
    return <div className="p-16 text-center text-slate-400">Loading session details...</div>;
  }

  if (error || !session) {
    return (
      <div className="max-w-7xl mx-auto px-4 py-8">
        <AnalysisNav />
        <div className="p-6 rounded-xl bg-red-950/40 border border-red-800 text-red-300 text-sm">
          {error || 'Session not found.'}
        </div>
      </div>
    );
  }

  const isV2 = session.version === 2;
  const isEst = session.outcome === 'established' || session.outcome === 'established_observed';
  const initIp = session.initiator?.ip || session.initiator_ip || (typeof session.initiator === 'string' ? session.initiator : 'Initiator');
  const initPort = session.initiator?.port || session.initiator_port || 500;
  const respIp = session.responder?.ip || session.responder_ip || (typeof session.responder === 'string' ? session.responder : 'Responder');
  const respPort = session.responder?.port || session.responder_port || 500;
  const spiI = session.spi_i || session.initiator_spi || 'N/A';
  const spiR = session.spi_r || session.responder_spi || 'N/A';
  const rawMessages = session.messages || [];
  const messages = rawMessages.map((m: any) => ({
    ...m,
    direction: m.direction || (m.src?.ip === initIp ? 'i2r' : 'r2i'),
  }));
  const offered = session.offered || session.offered_proposals || session.proposals || [];
  const selected = session.selected || session.selected_proposal || null;
  const vendorIds = session.vendor_ids || [];
  const notifies = session.notifies || [];


  return (
    <div className="max-w-7xl mx-auto px-4 py-8 space-y-6">
      <AnalysisNav />

      {/* Breadcrumb & Navigation */}
      <div className="flex items-center gap-2 text-xs text-slate-400">
        <Link to={`/analyses/${id}/ike`} className="hover:text-sky-400 flex items-center gap-1">
          <ArrowLeft className="w-3.5 h-3.5" /> Back to IKE Sessions
        </Link>
        <span>/</span>
        <span className="text-white font-mono">{sid}</span>
      </div>

      {/* Session Hero Banner */}
      <div className="bg-slate-900 border border-slate-800 rounded-2xl p-6 shadow-xl space-y-4">
        <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 border-b border-slate-800 pb-4">
          <div className="space-y-1">
            <div className="flex items-center gap-2">
              <span className={`text-xs font-bold px-2 py-0.5 rounded border uppercase ${
                isV2
                  ? 'bg-sky-950/60 text-sky-400 border-sky-800'
                  : 'bg-amber-950/60 text-amber-400 border-amber-800'
              }`}>
                IKEv{session.version}
              </span>

              <span className={`text-xs font-bold px-2.5 py-0.5 rounded border flex items-center gap-1 ${
                isEst
                  ? 'bg-emerald-950/60 text-emerald-400 border-emerald-800'
                  : 'bg-red-950/60 text-red-400 border-red-800'
              }`}>
                {isEst ? <ShieldCheck className="w-3.5 h-3.5" /> : <ShieldAlert className="w-3.5 h-3.5" />}
                {session.outcome?.toUpperCase() || 'UNKNOWN'}
              </span>
            </div>

            <h1 className="text-xl font-mono font-bold text-white mt-1">
              {initIp}:{initPort} ↔ {respIp}:{respPort}
            </h1>
          </div>

          <div className="text-right text-xs font-mono text-slate-400 space-y-1">
            <div>SPI-i: <strong className="text-sky-400">{spiI}</strong></div>
            <div>SPI-r: <strong className="text-indigo-400">{spiR}</strong></div>
          </div>
        </div>

        {/* Passive scope statement */}
        <div className="p-3.5 rounded-xl bg-slate-950/70 border border-slate-800 flex items-start gap-3 text-xs text-slate-400">
          <EyeOff className="w-4 h-4 text-amber-400 flex-shrink-0 mt-0.5" />
          <div>
            <strong className="text-slate-300">Passive Offline Observability Boundary:</strong>{' '}
            {isV2 ? (
              <span>
                Under RFC 7296, all payloads after the initial unencrypted IKE_SA_INIT exchange (such as IKE_AUTH identities, certificates, and CHILD_SA offers) are authenticated and encrypted under the negotiated session key (SK_ei / SK_er). In accordance with our passive offline architecture, encrypted payloads are labeled opaque unless decryption keys are provided.
              </span>
            ) : (
              <span>
                In IKEv1, Main Mode exchanges identities in encrypted packets 5 and 6, while Aggressive Mode transmits identities in cleartext. Quick Mode exchanges are negotiated under Phase 1 keys.
              </span>
            )}
          </div>
        </div>
      </div>

      {/* Handshake Ladder Diagram */}
      <HandshakeLadder
        initiatorIp={session.initiator_ip || 'Initiator'}
        responderIp={session.responder_ip || 'Responder'}
        messages={messages}
      />

      {/* Proposals Comparison */}
      <ProposalCompareTable offered={offered} selected={selected} />

      {/* Notifies & Vendor IDs */}
      <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
        {/* Vendor IDs */}
        <div className="bg-slate-900 border border-slate-800 rounded-2xl p-5 shadow-lg space-y-3">
          <h3 className="text-sm font-bold text-white flex items-center gap-2">
            <span>🏷️</span> Vendor ID Payloads (Fingerprints)
          </h3>
          {vendorIds.length === 0 ? (
            <p className="text-xs text-slate-500 italic">No Vendor ID payloads detected.</p>
          ) : (
            <div className="space-y-2">
              {vendorIds.map((v: any, idx: number) => {
                const vidName = typeof v === 'string' ? v : v.vendor || v.raw_hex;
                return (
                  <div key={idx} className="p-2.5 rounded-lg bg-slate-950/60 border border-slate-800/80 text-xs font-mono flex items-center justify-between">
                    <span className="text-sky-300">{vidName}</span>
                    <span className="text-[10px] text-slate-500 uppercase">Vendor Hash</span>
                  </div>
                );
              })}
            </div>
          )}
        </div>

        {/* Notifies */}
        <div className="bg-slate-900 border border-slate-800 rounded-2xl p-5 shadow-lg space-y-3">
          <h3 className="text-sm font-bold text-white flex items-center gap-2">
            <span>🔔</span> Notify Status & Error Payloads
          </h3>
          {notifies.length === 0 ? (
            <p className="text-xs text-slate-500 italic">No notify payloads present in observed messages.</p>
          ) : (
            <div className="space-y-2">
              {notifies.map((n: any, idx: number) => {
                const nType = n.notify_type || n.type || 'NOTIFY';
                const isErr = n.is_error || (n.type_code && n.type_code < 16384);
                return (
                  <div key={idx} className="p-2.5 rounded-lg bg-slate-950/60 border border-slate-800/80 text-xs font-mono flex items-center justify-between">
                    <span className={isErr ? 'text-red-400 font-bold' : 'text-slate-300'}>{nType}</span>
                    <span className="text-[10px] text-slate-500">MsgID: {n.message_id ?? 0}</span>
                  </div>
                );
              })}
            </div>
          )}
        </div>
      </div>
    </div>
  );
};

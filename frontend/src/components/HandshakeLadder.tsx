import React, { useState } from 'react';
import { formatUtcDateTime, parseVendorId } from '../utils/formatters';

interface HandshakeMessage {
  pkt_no: number;
  ts: number;
  direction: 'i2r' | 'r2i';
  exchange_name: string;
  exchange_type: number;
  message_id: number;
  encrypted: boolean;
  proposals?: any[];
  notifies?: any[];
  vendor_ids?: string[];
  anomalies?: string[];
}

interface HandshakeLadderProps {
  initiatorIp: string;
  responderIp: string;
  messages: HandshakeMessage[];
}

export const HandshakeLadder: React.FC<HandshakeLadderProps> = ({
  initiatorIp,
  responderIp,
  messages,
}) => {
  const [selectedMsg, setSelectedMsg] = useState<HandshakeMessage | null>(
    messages.length > 0 ? messages[0] : null
  );

  const rowHeight = 70;
  const svgHeight = Math.max(280, messages.length * rowHeight + 80);
  const leftX = 80;
  const rightX = 380;

  return (
    <div className="bg-slate-900 border border-slate-800 rounded-xl p-5 shadow-lg">
      <div className="flex items-center justify-between pb-4 border-b border-slate-800 mb-4">
        <h3 className="font-semibold text-slate-200 flex items-center gap-2">
          <span>🪜</span> IKE Handshake Sequence Ladder
        </h3>
        <span className="text-xs text-slate-400">
          Click an exchange arrow to inspect raw packet parameters
        </span>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
        {/* SVG Diagram */}
        <div className="lg:col-span-7 overflow-x-auto bg-slate-950/60 rounded-lg p-2 border border-slate-800/80">
          <svg
            className="w-full min-w-[460px]"
            height={svgHeight}
            viewBox={`0 0 460 ${svgHeight}`}
          >
            {/* Initiator vertical line */}
            <line
              x1={leftX}
              y1={45}
              x2={leftX}
              y2={svgHeight - 20}
              stroke="#38bdf8"
              strokeWidth={2}
              strokeDasharray="4 4"
            />
            {/* Responder vertical line */}
            <line
              x1={rightX}
              y1={45}
              x2={rightX}
              y2={svgHeight - 20}
              stroke="#818cf8"
              strokeWidth={2}
              strokeDasharray="4 4"
            />

            {/* Column Headers */}
            <rect x={leftX - 60} y={10} width={120} height={30} rx={6} fill="#0369a1" />
            <text
              x={leftX}
              y={29}
              textAnchor="middle"
              fill="white"
              fontSize={11}
              fontWeight="bold"
            >
              {initiatorIp && initiatorIp !== 'Initiator' ? `Initiator (${initiatorIp})` : 'Initiator'}
            </text>

            <rect x={rightX - 60} y={10} width={120} height={30} rx={6} fill="#4338ca" />
            <text
              x={rightX}
              y={29}
              textAnchor="middle"
              fill="white"
              fontSize={11}
              fontWeight="bold"
            >
              {responderIp && responderIp !== 'Responder' ? `Responder (${responderIp})` : 'Responder'}
            </text>

            {/* Exchange arrows */}
            {messages.map((msg, idx) => {
              const y = 75 + idx * rowHeight;
              const isI2R = msg.direction === 'i2r';
              const x1 = isI2R ? leftX : rightX;
              const x2 = isI2R ? rightX : leftX;
              const isSelected = selectedMsg?.pkt_no === msg.pkt_no;

              return (
                <g
                  key={msg.pkt_no}
                  className="cursor-pointer group"
                  onClick={() => setSelectedMsg(msg)}
                >
                  {/* Hover / selection glow */}
                  {isSelected && (
                    <rect
                      x={leftX - 10}
                      y={y - 20}
                      width={rightX - leftX + 20}
                      height={40}
                      rx={6}
                      fill="#0284c7"
                      fillOpacity={0.15}
                    />
                  )}

                  {/* Horizontal Arrow Line */}
                  <line
                    x1={x1}
                    y1={y}
                    x2={x2}
                    y2={y}
                    stroke={isSelected ? '#38bdf8' : msg.encrypted ? '#94a3b8' : '#38bdf8'}
                    strokeWidth={isSelected ? 3 : 2}
                  />

                  {/* Arrowhead */}
                  <polygon
                    points={
                      isI2R
                        ? `${x2},${y} ${x2 - 8},${y - 4} ${x2 - 8},${y + 4}`
                        : `${x2},${y} ${x2 + 8},${y - 4} ${x2 + 8},${y + 4}`
                    }
                    fill={isSelected ? '#38bdf8' : msg.encrypted ? '#94a3b8' : '#38bdf8'}
                  />

                  {/* Message Label Badge */}
                  <rect
                    x={230 - 75}
                    y={y - 14}
                    width={150}
                    height={24}
                    rx={4}
                    fill={msg.encrypted ? '#1e293b' : '#0f172a'}
                    stroke={isSelected ? '#38bdf8' : '#334155'}
                    strokeWidth={1}
                  />
                  <text
                    x={230}
                    y={y + 2}
                    textAnchor="middle"
                    fill={msg.encrypted ? '#94a3b8' : '#f8fafc'}
                    fontSize={10}
                    fontWeight="600"
                  >
                    #{msg.pkt_no}: {msg.exchange_name} {msg.encrypted ? '🔒' : ''}
                  </text>
                </g>
              );
            })}
          </svg>
        </div>

        {/* Selected Message Inspector */}
        <div className="lg:col-span-5 bg-slate-950/70 rounded-lg p-4 border border-slate-800 text-xs text-slate-300">
          {selectedMsg ? (
            <div className="space-y-3">
              <div className="flex items-center justify-between border-b border-slate-800 pb-2">
                <span className="font-bold text-sm text-sky-400">
                  Packet #{selectedMsg.pkt_no} Details
                </span>
                <span
                  className={`px-2 py-0.5 rounded text-[10px] font-bold ${
                    selectedMsg.encrypted
                      ? 'bg-amber-950/70 text-amber-400 border border-amber-800/50'
                      : 'bg-emerald-950/70 text-emerald-400 border border-emerald-800/50'
                  }`}
                >
                  {selectedMsg.encrypted ? 'ENCRYPTED (OPAQUE)' : 'CLEARTEXT OBSERVED'}
                </span>
              </div>

              <div className="grid grid-cols-2 gap-2 text-slate-400">
                <div>
                  <span className="text-slate-500">Exchange:</span>{' '}
                  <span className="text-slate-200">{selectedMsg.exchange_name} ({selectedMsg.exchange_type})</span>
                </div>
                <div>
                  <span className="text-slate-500">Message ID:</span>{' '}
                  <span className="text-slate-200">{selectedMsg.message_id}</span>
                </div>
                <div>
                  <span className="text-slate-500">Direction:</span>{' '}
                  <span className="text-slate-200">
                    {selectedMsg.direction === 'i2r' ? 'Initiator → Responder' : 'Responder → Initiator'}
                  </span>
                </div>
                <div>
                  <span className="text-slate-500">Timestamp:</span>{' '}
                  <span className="text-slate-200">{formatUtcDateTime(selectedMsg.ts)}</span>
                </div>
              </div>

              {selectedMsg.proposals && selectedMsg.proposals.length > 0 && (
                <div>
                  <div className="font-semibold text-slate-300 mb-1">Cryptographic Proposals:</div>
                  <div className="space-y-1.5">
                    {selectedMsg.proposals.map((p: any, idx: number) => (
                      <div key={idx} className="bg-slate-900 p-2 rounded border border-slate-800 text-[11px]">
                        <span className="text-sky-400 font-bold">Proposal #{p.num || idx + 1}:</span>{' '}
                        {p.transforms?.map((t: any) => `${t.kind || t.type}: ${t.name || t.id}`).join(' · ')}
                      </div>
                    ))}
                  </div>
                </div>
              )}

              {selectedMsg.notifies && selectedMsg.notifies.length > 0 && (
                <div>
                  <div className="font-semibold text-slate-300 mb-1">Notifications:</div>
                  <div className="flex flex-wrap gap-1">
                    {selectedMsg.notifies.map((n: any, idx: number) => (
                      <span key={idx} className="bg-slate-900 px-2 py-0.5 rounded border border-slate-800 text-amber-300">
                        {n.name} (type {n.type})
                      </span>
                    ))}
                  </div>
                </div>
              )}

              {selectedMsg.vendor_ids && selectedMsg.vendor_ids.length > 0 && (
                <div>
                  <div className="font-semibold text-slate-300 mb-1 flex items-center justify-between">
                    <span>Reported Vendor IDs:</span>
                    <span className="text-[10px] text-amber-400 font-normal">
                      peer-reported (may be spoofed)
                    </span>
                  </div>
                  <div className="space-y-1.5">
                    {selectedMsg.vendor_ids.map((v: any, idx: number) => {
                      const parsed = parseVendorId(v);
                      return (
                        <div key={idx} className="bg-slate-900 p-2 rounded border border-slate-800 text-[11px] font-mono">
                          <div className="text-sky-300 font-semibold">{parsed.display}</div>
                          {parsed.ascii_decoded && parsed.ascii_decoded !== parsed.display && (
                            <div className="text-emerald-400 text-[10px]">ASCII: "{parsed.ascii_decoded}"</div>
                          )}
                          <div className="text-slate-500 text-[10px] break-all">Hex: {parsed.raw_hex}</div>
                        </div>
                      );
                    })}
                  </div>
                </div>
              )}

            </div>
          ) : (
            <div className="text-slate-500 py-8 text-center">
              No message selected. Click an exchange arrow on the left to inspect.
            </div>
          )}
        </div>
      </div>
    </div>
  );
};

import React from 'react';

interface Transform {
  kind?: string;
  type?: string;
  id: number;
  name: string;
  key_length?: number | null;
}

interface Proposal {
  num?: number;
  protocol?: string;
  transforms: Transform[];
}

interface ProposalCompareTableProps {
  offered: Proposal[];
  selected?: Proposal | null;
}

const WEAK_TRANSFORMS = new Set([
  'DES', '3DES', 'DES-CBC', '3DES-CBC', 'MODP-768', 'MODP-1024', 'MODP-1536',
  'MD5', 'SHA1', 'HMAC_MD5', 'HMAC_SHA1', 'HMAC_MD5_96', 'HMAC_SHA1_96'
]);

export const ProposalCompareTable: React.FC<ProposalCompareTableProps> = ({
  offered,
  selected,
}) => {
  return (
    <div className="bg-slate-900 border border-slate-800 rounded-xl overflow-hidden shadow-lg">
      <div className="p-4 bg-slate-800/50 border-b border-slate-800 flex justify-between items-center">
        <h3 className="font-semibold text-slate-200 flex items-center gap-2">
          <span>⚖️</span> Cryptographic Proposals: Offered vs Selected
        </h3>
        <span className="text-xs text-slate-400">
          Weak/deprecated transforms flagged in red/amber
        </span>
      </div>

      <div className="overflow-x-auto">
        <table className="w-full text-left text-sm text-slate-300">
          <thead className="bg-slate-950 text-xs uppercase text-slate-400 border-b border-slate-800">
            <tr>
              <th className="py-3 px-4">Role</th>
              <th className="py-3 px-4">Proposal</th>
              <th className="py-3 px-4">Transform Type</th>
              <th className="py-3 px-4">Algorithm Name</th>
              <th className="py-3 px-4">Key Size</th>
              <th className="py-3 px-4">Cryptographic Status</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-slate-800">
            {/* Selected Proposal First */}
            {selected ? (
              selected.transforms.map((t, idx) => {
                const isWeak = WEAK_TRANSFORMS.has(t.name);
                return (
                  <tr key={`sel-${idx}`} className="bg-sky-950/20 border-l-4 border-sky-500">
                    <td className="py-3 px-4 font-bold text-sky-400">
                      {idx === 0 ? 'SELECTED' : ''}
                    </td>
                    <td className="py-3 px-4 font-mono text-xs">#{selected.num || 1}</td>
                    <td className="py-3 px-4 font-medium">{t.kind || t.type}</td>
                    <td className="py-3 px-4 font-bold text-white">{t.name}</td>
                    <td className="py-3 px-4 text-slate-400">
                      {t.key_length ? `${t.key_length} bits` : 'Standard'}
                    </td>
                    <td className="py-3 px-4">
                      {isWeak ? (
                        <span className="inline-flex items-center gap-1 text-xs px-2 py-0.5 rounded bg-red-950 text-red-400 border border-red-800/60 font-semibold">
                          ⚠️ Deprecated / Weak
                        </span>
                      ) : (
                        <span className="inline-flex items-center gap-1 text-xs px-2 py-0.5 rounded bg-emerald-950 text-emerald-400 border border-emerald-800/60 font-semibold">
                          ✅ Approved Standards
                        </span>
                      )}
                    </td>
                  </tr>
                );
              })
            ) : (
              <tr>
                <td colSpan={6} className="py-3 px-4 text-slate-500 italic">
                  No proposal selected (negotiation unanswered or failed)
                </td>
              </tr>
            )}

            {/* Offered Proposals */}
            {offered.flatMap((p, pIdx) =>
              p.transforms.map((t, tIdx) => {
                const isWeak = WEAK_TRANSFORMS.has(t.name);
                return (
                  <tr key={`off-${pIdx}-${tIdx}`} className="hover:bg-slate-800/30">
                    <td className="py-3 px-4 text-slate-500">
                      {tIdx === 0 && pIdx === 0 ? 'Offered' : ''}
                    </td>
                    <td className="py-3 px-4 font-mono text-xs text-slate-400">#{p.num || pIdx + 1}</td>
                    <td className="py-3 px-4 text-slate-400">{t.kind || t.type}</td>
                    <td className="py-3 px-4 text-slate-200">{t.name}</td>
                    <td className="py-3 px-4 text-slate-500">
                      {t.key_length ? `${t.key_length} bits` : 'Standard'}
                    </td>
                    <td className="py-3 px-4">
                      {isWeak ? (
                        <span className="inline-flex items-center gap-1 text-xs px-2 py-0.5 rounded bg-amber-950/60 text-amber-400 border border-amber-800/40">
                          ⚠️ Offered Weak
                        </span>
                      ) : (
                        <span className="inline-flex items-center gap-1 text-xs px-2 py-0.5 rounded bg-slate-800 text-slate-400">
                          Offered
                        </span>
                      )}
                    </td>
                  </tr>
                );
              })
            )}
          </tbody>
        </table>
      </div>
    </div>
  );
};

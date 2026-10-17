import React, { useEffect, useState } from 'react';
import { fetchCapabilities } from '../api/client';
import { CapabilityEntry } from '../types';
import { CapabilityBadge } from '../components/CapabilityBadge';
import { ShieldCheck, AlertCircle, Info, RefreshCw } from 'lucide-react';

export const CapabilitiesPage: React.FC = () => {
  const [capabilities, setCapabilities] = useState<CapabilityEntry[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const loadCapabilities = async () => {
    setLoading(true);
    setError(null);
    try {
      const data = await fetchCapabilities();
      setCapabilities(data);
    } catch (err: unknown) {
      const msg = err && typeof err === 'object' && 'error' in err
        ? (err as { error: { message: string } }).error.message
        : 'Failed to connect to backend capabilities API';
      setError(msg);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    loadCapabilities();
  }, []);

  return (
    <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-8">
      <div className="flex items-center justify-between mb-8">
        <div>
          <h1 className="text-2xl font-bold text-white flex items-center gap-3">
            <ShieldCheck className="w-8 h-8 text-sky-400" /> System Capabilities & Observability Boundaries
          </h1>
          <p className="mt-1 text-sm text-slate-400">
            Real implementation status served live by <code className="text-sky-300">GET /api/v1/capabilities</code> (FR-85).
            No simulated or pretend features.
          </p>
        </div>
        <button
          onClick={loadCapabilities}
          disabled={loading}
          className="flex items-center space-x-2 px-3 py-1.5 rounded bg-slate-800 hover:bg-slate-700 text-slate-300 text-sm font-medium border border-slate-700 transition-colors"
        >
          <RefreshCw className={`w-4 h-4 ${loading ? 'animate-spin' : ''}`} />
          <span>Refresh</span>
        </button>
      </div>

      {/* Honest Limitation Notice */}
      <div className="bg-sky-950/40 border border-sky-800/60 rounded-lg p-5 mb-8 flex items-start gap-4">
        <Info className="w-6 h-6 text-sky-400 shrink-0 mt-0.5" />
        <div className="text-sm">
          <h4 className="font-semibold text-sky-200">Cryptographic Observability Guarantee (Normative Rule)</h4>
          <p className="mt-1 text-slate-300 leading-relaxed">
            IPsecScope performs <strong>passive, keyless network capture analysis</strong>. Encrypted traffic regions (including IKEv2 <code className="text-sky-300">IKE_AUTH</code> identities, IKEv1 <code className="text-sky-300">Quick Mode</code>, and all <code className="text-sky-300">ESP</code> payloads) cannot be decrypted without private keys and are strictly labeled as <strong className="text-white">not_observable</strong>. The tool will never fabricate cipher attributes or guess unobservable parameters.
          </p>
        </div>
      </div>

      {loading && (
        <div className="flex flex-col items-center justify-center p-12 bg-slate-800/50 border border-slate-700 rounded-lg">
          <RefreshCw className="w-8 h-8 text-sky-400 animate-spin mb-3" />
          <p className="text-slate-400 text-sm">Querying backend capabilities registry...</p>
        </div>
      )}

      {error && (
        <div className="bg-red-950/50 border border-red-800 rounded-lg p-6 text-center">
          <AlertCircle className="w-8 h-8 text-red-400 mx-auto mb-2" />
          <h3 className="text-base font-semibold text-red-200">Unable to load capabilities</h3>
          <p className="text-sm text-red-300 mt-1">{error}</p>
          <button
            onClick={loadCapabilities}
            className="mt-4 px-4 py-1.5 bg-red-800 hover:bg-red-700 text-white rounded text-sm font-medium"
          >
            Retry Connection
          </button>
        </div>
      )}

      {!loading && !error && (
        <div className="bg-slate-800/80 border border-slate-700 rounded-lg shadow overflow-hidden">
          <div className="overflow-x-auto">
            <table className="min-w-full divide-y divide-slate-700 text-left text-sm">
              <thead className="bg-slate-900/60 text-slate-300 text-xs uppercase tracking-wider font-semibold">
                <tr>
                  <th className="py-3 px-4">Req ID</th>
                  <th className="py-3 px-4">Feature Description</th>
                  <th className="py-3 px-4">Priority</th>
                  <th className="py-3 px-4">Status</th>
                  <th className="py-3 px-4">Implementation Notes & Boundaries</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-700/60 text-slate-200">
                {capabilities.map((cap) => (
                  <tr key={cap.id} className="hover:bg-slate-700/30 transition-colors">
                    <td className="py-3 px-4 font-mono text-xs font-semibold text-sky-400 whitespace-nowrap">
                      {cap.id}
                    </td>
                    <td className="py-3 px-4 font-medium text-white max-w-xs sm:max-w-md">
                      {cap.feature}
                      {cap.heuristic && (
                        <span className="ml-2 px-1.5 py-0.5 text-[10px] bg-amber-950 text-amber-300 border border-amber-800 rounded font-normal">
                          heuristic (conf: {cap.confidence})
                        </span>
                      )}
                    </td>
                    <td className="py-3 px-4">
                      <span className="px-2 py-0.5 rounded text-xs font-semibold bg-slate-700 text-slate-300">
                        {cap.priority}
                      </span>
                    </td>
                    <td className="py-3 px-4 whitespace-nowrap">
                      <CapabilityBadge status={cap.status} />
                    </td>
                    <td className="py-3 px-4 text-xs text-slate-400 leading-relaxed max-w-lg">
                      {cap.notes}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}
    </div>
  );
};

import React, { useEffect, useState } from 'react';
import { useParams, Link } from 'react-router-dom';
import { fetchFindings } from '../api/client';
import { AnalysisNav } from '../components/AnalysisNav';
import { SeverityBadge } from '../components/SeverityBadge';
import { AlertTriangle, Search, ArrowRight, ShieldCheck } from 'lucide-react';

export const FindingsPage: React.FC = () => {
  const { id } = useParams<{ id: string }>();
  const [findings, setFindings] = useState<any[]>([]);
  const [total, setTotal] = useState(0);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  // Filters
  const [severityFilter, setSeverityFilter] = useState<string>('all');
  const [categoryFilter, setCategoryFilter] = useState<string>('all');
  const [searchQuery, setSearchQuery] = useState<string>('');

  useEffect(() => {
    if (!id) return;
    const load = async () => {
      try {
        setLoading(true);
        const filters: any = { page: 1, page_size: 50 };
        if (severityFilter !== 'all') filters.severity = severityFilter;
        if (categoryFilter !== 'all') filters.category = categoryFilter;
        if (searchQuery.trim()) filters.q = searchQuery.trim();

        const res = await fetchFindings(id, filters);
        setFindings(res.items || []);
        setTotal(res.total || 0);
        setError(null);
      } catch (err: any) {
        setError(err?.error?.message || 'Failed to load security findings');
      } finally {
        setLoading(false);
      }
    };
    load();
  }, [id, severityFilter, categoryFilter, searchQuery]);

  const severities = ['all', 'Critical', 'High', 'Medium', 'Low', 'Info'];
  const categories = ['all', 'cryptography', 'protocol', 'implementation', 'replay', 'configuration'];

  return (
    <div className="max-w-7xl mx-auto px-4 py-8 space-y-6">
      <AnalysisNav />

      {/* Header */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 border-b border-slate-800 pb-5">
        <div>
          <h1 className="text-2xl font-bold text-white flex items-center gap-2.5">
            <AlertTriangle className="w-6 h-6 text-amber-400" /> Security Findings Catalogue
          </h1>
          <p className="text-xs text-slate-400 mt-1">
            Deterministic rule evaluations and heuristic vulnerability detections based on NIST SP 800-77.
          </p>
        </div>

        <div className="text-xs font-mono text-slate-400">
          Showing <strong className="text-white">{findings.length}</strong> of <strong className="text-white">{total}</strong> findings
        </div>
      </div>

      {/* Filter and Search Bar */}
      <div className="bg-slate-900 border border-slate-800 p-4 rounded-xl space-y-3">
        {/* Search */}
        <div className="relative">
          <Search className="w-4 h-4 text-slate-500 absolute left-3 top-3" />
          <input
            type="text"
            placeholder="Search by rule ID, title, cipher, or description keyword..."
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
            className="w-full bg-slate-950 border border-slate-800 rounded-lg pl-9 pr-4 py-2 text-xs text-white placeholder-slate-500 focus:outline-none focus:border-sky-500 transition-colors"
          />
        </div>

        {/* Severity Pills & Category Dropdown */}
        <div className="flex flex-wrap items-center justify-between gap-3 pt-1">
          <div className="flex flex-wrap items-center gap-1.5">
            <span className="text-[11px] font-mono text-slate-500 uppercase mr-1">Severity:</span>
            {severities.map((sev) => (
              <button
                key={sev}
                onClick={() => setSeverityFilter(sev)}
                className={`px-3 py-1 rounded-md text-xs font-semibold capitalize transition-all ${
                  severityFilter === sev
                    ? 'bg-sky-500 text-slate-950 font-bold shadow'
                    : 'bg-slate-800/80 text-slate-400 hover:text-white hover:bg-slate-800'
                }`}
              >
                {sev}
              </button>
            ))}
          </div>

          <div className="flex items-center gap-2 text-xs text-slate-400">
            <span className="text-[11px] font-mono text-slate-500 uppercase">Category:</span>
            <select
              value={categoryFilter}
              onChange={(e) => setCategoryFilter(e.target.value)}
              className="bg-slate-950 border border-slate-800 text-slate-300 rounded-lg px-2.5 py-1 text-xs focus:outline-none focus:border-sky-500"
            >
              {categories.map((c) => (
                <option key={c} value={c} className="bg-slate-900 capitalize">
                  {c}
                </option>
              ))}
            </select>
          </div>
        </div>
      </div>

      {/* Findings List */}
      {loading ? (
        <div className="p-16 text-center text-slate-400">Loading findings...</div>
      ) : error ? (
        <div className="p-6 rounded-xl bg-red-950/40 border border-red-800 text-red-300 text-sm">{error}</div>
      ) : findings.length === 0 ? (
        <div className="p-16 rounded-2xl bg-slate-900 border border-slate-800 text-center space-y-3">
          <ShieldCheck className="w-10 h-10 text-emerald-500 mx-auto" />
          <h3 className="text-base font-bold text-slate-200">No Findings Detected</h3>
          <p className="text-xs text-slate-400 max-w-md mx-auto">
            {searchQuery || severityFilter !== 'all' || categoryFilter !== 'all'
              ? 'No security findings match your current active filters.'
              : 'Excellent! No security vulnerabilities or compliance warnings were flagged in this capture.'}
          </p>
        </div>
      ) : (
        <div className="space-y-3">
          {findings.map((f) => {
            const fid = f.finding_id || f.id;
            const rScore = f.risk_score !== undefined ? f.risk_score.toFixed(0) : '0';

            return (
              <Link
                key={fid}
                to={`/analyses/${id}/findings/${fid}`}
                className="block bg-slate-900 border border-slate-800 hover:border-sky-500/50 p-5 rounded-2xl transition-all shadow-md group"
              >
                <div className="flex flex-col md:flex-row md:items-center justify-between gap-4">
                  {/* Left: Badge, Rule ID, Title & Description */}
                  <div className="space-y-2">
                    <div className="flex items-center gap-2.5">
                      <SeverityBadge severity={f.severity} size="sm" />
                      <span className="text-[11px] font-mono px-2 py-0.5 rounded bg-slate-950 text-slate-400 border border-slate-800">
                        {f.rule_id}
                      </span>
                      <span className="text-[11px] font-mono text-slate-500 uppercase">
                        {f.category}
                      </span>
                    </div>

                    <h3 className="text-base font-bold text-white group-hover:text-sky-300 transition-colors">
                      {f.title}
                    </h3>

                    <p className="text-xs text-slate-400 line-clamp-2 max-w-4xl">
                      {f.description}
                    </p>
                  </div>

                  {/* Right: Risk Score & Action */}
                  <div className="flex md:flex-col items-center md:items-end justify-between gap-3 flex-shrink-0">
                    <div className="text-right">
                      <div className="text-[10px] text-slate-500 uppercase font-mono">RISK (Ri)</div>
                      <div className="text-xl font-black text-amber-400 font-mono">{rScore}/100</div>
                    </div>

                    <div className="flex items-center gap-1.5 text-xs text-sky-400 group-hover:text-sky-300 font-semibold">
                      <span>Inspect Evidence</span>
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

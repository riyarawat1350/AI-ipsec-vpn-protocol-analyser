import React, { useState, useEffect } from 'react';
import { Search, BookOpen, HelpCircle, ArrowUpRight } from 'lucide-react';
import { fetchGlossary, GlossaryTerm } from '../api/client';

export const GlossaryPage: React.FC = () => {
  const [terms, setTerms] = useState<GlossaryTerm[]>([]);
  const [search, setSearch] = useState('');
  const [loading, setLoading] = useState(true);
  const [activeCategory, setActiveCategory] = useState('all');

  useEffect(() => {
    loadTerms();
  }, []);

  const loadTerms = async () => {
    setLoading(true);
    try {
      const data = await fetchGlossary();
      setTerms(data);
    } catch (err) {
      console.error('Failed to load glossary', err);
    } finally {
      setLoading(false);
    }
  };

  const categories = [
    { id: 'all', label: 'All Terms' },
    { id: 'crypto', label: 'Cryptography', filter: ['dh-group', 'aead', 'aes-gcm', '3des', 'des', 'md5', 'sha-1', 'sha-2', 'psk', 'ecp', 'modp', 'cipher', 'iv', 'mac', 'prf', 'integrity', 'esp-null'] },
    { id: 'protocols', label: 'Protocols', filter: ['ipsec', 'vpn', 'ike', 'ikev1', 'ikev2', 'esp', 'ah', 'nat-t', 'nat-keepalive', 'icmp'] },
    { id: 'handshake', label: 'Handshake & Sessions', filter: ['sa', 'spi', 'handshake', 'initiator', 'responder', 'main-mode', 'aggressive-mode', 'nonce', 'notify', 'vendor-id', 'cookie', 'rekey', 'proposal', 'transform', 'payload', 'exchange-type'] },
    { id: 'assurance', label: 'Risk & Assurance', filter: ['risk-score', 'impact', 'likelihood', 'confidence', 'severity', 'posture-grade', 'evidence', 'heuristic', 'false-positive', 'policy-baseline', 'cve', 'cvss', 'mitre-attack', 'ioc', 'not-observable'] },
  ];

  const filteredTerms = terms.filter((term) => {
    const matchesSearch =
      search === '' ||
      term.name.toLowerCase().includes(search.toLowerCase()) ||
      term.expansion.toLowerCase().includes(search.toLowerCase()) ||
      term.simple.toLowerCase().includes(search.toLowerCase()) ||
      term.why_it_matters.toLowerCase().includes(search.toLowerCase()) ||
      term.id.toLowerCase().includes(search.toLowerCase());

    if (!matchesSearch) return false;

    if (activeCategory === 'all') return true;
    const cat = categories.find((c) => c.id === activeCategory);
    return cat?.filter ? cat.filter.includes(term.id) : true;
  });

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="bg-slate-900 border border-slate-800 rounded-2xl p-6 sm:p-8 shadow-xl">
        <div className="flex flex-col md:flex-row md:items-center justify-between gap-4">
          <div>
            <div className="inline-flex items-center gap-2 px-3 py-1 rounded-full bg-sky-950/80 border border-sky-800 text-sky-400 text-xs font-semibold uppercase tracking-wider mb-2">
              <BookOpen className="w-3.5 h-3.5" /> Plain-Language Reference
            </div>
            <h1 className="text-2xl sm:text-3xl font-extrabold text-white tracking-tight">
              IPsec & VPN Security Glossary
            </h1>
            <p className="text-sm text-slate-400 mt-1 max-w-2xl leading-relaxed">
              Every technical term explained in simple English (average sentence length &le; 20 words) with real-world analogies, why it matters, and technical RFC specifications.
            </p>
          </div>

          <div className="text-right">
            <span className="text-3xl font-black text-sky-400">{terms.length}</span>
            <div className="text-xs text-slate-400 uppercase font-mono">Defined Terms</div>
          </div>
        </div>

        {/* Search Bar */}
        <div className="mt-6 flex flex-col sm:flex-row gap-3">
          <div className="relative flex-1">
            <Search className="w-5 h-5 absolute left-3.5 top-1/2 -translate-y-1/2 text-slate-400" />
            <input
              type="text"
              placeholder="Search by term (e.g. DH Group, ESP, PFS, AEAD, SHA-2)..."
              value={search}
              onChange={(e) => setSearch(e.target.value)}
              className="w-full pl-11 pr-4 py-2.5 rounded-xl bg-slate-950/80 border border-slate-700 text-white placeholder-slate-500 focus:outline-none focus:ring-2 focus:ring-sky-500 text-sm shadow-inner"
            />
          </div>

          <div className="flex flex-wrap gap-1.5 items-center">
            {categories.map((cat) => (
              <button
                key={cat.id}
                onClick={() => setActiveCategory(cat.id)}
                className={`px-3 py-1.5 rounded-lg text-xs font-medium transition-colors ${
                  activeCategory === cat.id
                    ? 'bg-sky-500 text-white shadow-md'
                    : 'bg-slate-800/80 text-slate-400 hover:text-white hover:bg-slate-800 border border-slate-700/60'
                }`}
              >
                {cat.label}
              </button>
            ))}
          </div>
        </div>
      </div>

      {/* Grid of Terms */}
      {loading ? (
        <div className="p-12 text-center text-slate-400">Loading glossary terms...</div>
      ) : filteredTerms.length === 0 ? (
        <div className="bg-slate-900 border border-slate-800 rounded-2xl p-12 text-center text-slate-400 space-y-2">
          <HelpCircle className="w-8 h-8 text-slate-500 mx-auto" />
          <p className="text-base font-semibold text-slate-300">No matching terms found</p>
          <p className="text-xs text-slate-500">Try adjusting your search query or switching categories.</p>
        </div>
      ) : (
        <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
          {filteredTerms.map((term) => (
            <div
              key={term.id}
              id={term.id}
              className="bg-slate-900/90 border border-slate-800 hover:border-slate-700 rounded-xl p-5 shadow-lg space-y-3 transition-all hover:bg-slate-900"
            >
              <div className="flex items-start justify-between border-b border-slate-800/80 pb-2">
                <div>
                  <h3 className="text-base font-bold text-white flex items-center gap-2">
                    {term.name}
                    <span className="text-xs font-mono px-2 py-0.5 rounded bg-slate-800 text-sky-400 border border-slate-700">
                      {term.id}
                    </span>
                  </h3>
                  <div className="text-xs text-sky-400/90 font-mono mt-0.5">{term.expansion}</div>
                </div>
                <a
                  href={`#${term.id}`}
                  className="text-slate-500 hover:text-sky-400 p-1"
                  title="Direct link to term"
                >
                  <ArrowUpRight className="w-4 h-4" />
                </a>
              </div>

              {/* Plain English Definition */}
              <div className="space-y-1">
                <span className="text-[10px] uppercase font-bold text-slate-400 tracking-wider">
                  Plain English Explanation:
                </span>
                <p className="text-xs sm:text-sm text-slate-200 leading-relaxed font-normal">
                  {term.simple}
                </p>
              </div>

              {/* Analogy */}
              {term.analogy && (
                <div className="bg-slate-950/60 p-2.5 rounded-lg border border-slate-800/80">
                  <span className="text-[10px] uppercase font-bold text-amber-400/90 tracking-wider">
                    Real-World Analogy:
                  </span>
                  <p className="text-xs text-slate-300 italic mt-0.5">{term.analogy}</p>
                </div>
              )}

              {/* Why It Matters */}
              <div className="space-y-1">
                <span className="text-[10px] uppercase font-bold text-slate-400 tracking-wider">
                  Why It Matters:
                </span>
                <p className="text-xs text-slate-300 leading-relaxed">{term.why_it_matters}</p>
              </div>

              {/* Technical Details */}
              <div className="pt-2 border-t border-slate-800/60 text-[11px] text-slate-400 font-mono">
                <strong className="text-slate-500 uppercase">RFC Standard:</strong> {term.technical}
              </div>
            </div>
          ))}
        </div>
      )}
    </div>
  );
};

import React, { useState, useEffect, useRef } from 'react';
import { Link } from 'react-router-dom';
import { Info, ExternalLink } from 'lucide-react';
import { fetchGlossaryTerm, GlossaryTerm } from '../api/client';

interface TermProps {
  id: string;
  children?: React.ReactNode;
  showIcon?: boolean;
  className?: string;
}

// In-memory cache across component instances
const termCache: Record<string, GlossaryTerm> = {};

export const Term: React.FC<TermProps> = ({ id, children, showIcon = true, className = '' }) => {
  const [isOpen, setIsOpen] = useState(false);
  const [termData, setTermData] = useState<GlossaryTerm | null>(termCache[id] || null);
  const [loading, setLoading] = useState(false);
  const popoverRef = useRef<HTMLDivElement>(null);

  const loadData = async () => {
    if (termCache[id]) {
      setTermData(termCache[id]);
      return;
    }
    setLoading(true);
    try {
      const data = await fetchGlossaryTerm(id);
      termCache[id] = data;
      setTermData(data);
    } catch {
      // Fallback display
      setTermData({
        id,
        name: id.toUpperCase(),
        expansion: id.toUpperCase(),
        simple: 'Security protocol term.',
        why_it_matters: 'Affects VPN encryption and policy compliance.',
        technical: 'Refer to glossary for RFC specifications.',
      });
    } finally {
      setLoading(false);
    }
  };

  const handleMouseEnter = () => {
    loadData();
    setIsOpen(true);
  };

  const handleMouseLeave = () => {
    setIsOpen(false);
  };

  const handleClick = (e: React.MouseEvent) => {
    e.stopPropagation();
    loadData();
    setIsOpen(!isOpen);
  };

  // Close on outside click
  useEffect(() => {
    if (!isOpen) return;
    const handleClickOutside = (e: MouseEvent) => {
      if (popoverRef.current && !popoverRef.current.contains(e.target as Node)) {
        setIsOpen(false);
      }
    };
    document.addEventListener('mousedown', handleClickOutside);
    return () => document.removeEventListener('mousedown', handleClickOutside);
  }, [isOpen]);

  const displayName = children || termData?.name || id;

  return (
    <span
      className="relative inline-flex items-center group cursor-pointer"
      onMouseEnter={handleMouseEnter}
      onMouseLeave={handleMouseLeave}
      onClick={handleClick}
    >
      <span className={`border-b border-dotted border-sky-400/80 text-sky-300 hover:text-sky-200 transition-colors ${className}`}>
        {displayName}
      </span>
      {showIcon && (
        <Info className="w-3.5 h-3.5 ml-1 text-sky-400/70 group-hover:text-sky-300 inline-block transition-colors" />
      )}

      {isOpen && (
        <div
          ref={popoverRef}
          className="absolute bottom-full left-1/2 -translate-x-1/2 mb-2 z-50 w-72 sm:w-80 p-3.5 rounded-xl bg-slate-900/95 border border-slate-700/80 shadow-2xl backdrop-blur-md text-left text-xs pointer-events-auto transition-all animate-in fade-in zoom-in-95 duration-150"
        >
          {loading && !termData ? (
            <div className="py-2 text-center text-slate-400">Loading explanation...</div>
          ) : termData ? (
            <div className="space-y-2">
              <div className="flex items-start justify-between border-b border-slate-800 pb-1.5">
                <div>
                  <h4 className="font-bold text-white text-sm tracking-tight">{termData.name}</h4>
                  <span className="text-[11px] text-sky-400 font-mono">{termData.expansion}</span>
                </div>
                <Link
                  to={`/glossary#${termData.id}`}
                  className="text-slate-400 hover:text-sky-400 p-1 rounded hover:bg-slate-800 transition-colors"
                  title="View full glossary entry"
                >
                  <ExternalLink className="w-3.5 h-3.5" />
                </Link>
              </div>

              <div>
                <span className="text-[10px] uppercase font-bold text-slate-400 tracking-wider">Plain English:</span>
                <p className="text-slate-200 mt-0.5 leading-relaxed">{termData.simple}</p>
              </div>

              {termData.analogy && (
                <div className="bg-slate-950/70 p-2 rounded-lg border border-slate-800/80">
                  <span className="text-[10px] uppercase font-bold text-amber-400/90 tracking-wider">Analogy:</span>
                  <p className="text-slate-300 italic mt-0.5">{termData.analogy}</p>
                </div>
              )}

              <div>
                <span className="text-[10px] uppercase font-bold text-slate-400 tracking-wider">Why It Matters:</span>
                <p className="text-slate-300 mt-0.5 leading-relaxed">{termData.why_it_matters}</p>
              </div>
            </div>
          ) : null}

          {/* Arrow */}
          <div className="absolute top-full left-1/2 -translate-x-1/2 -mt-px w-2 h-2 bg-slate-900 border-r border-b border-slate-700 rotate-45" />
        </div>
      )}
    </span>
  );
};

import React from 'react';
import { useParams, useLocation, Link } from 'react-router-dom';
import { Layers, ArrowLeft } from 'lucide-react';

interface Props {
  title: string;
  screenId: number;
  description: string;
}

export const EmptyStatePage: React.FC<Props> = ({ title, screenId, description }) => {
  const { id } = useParams<{ id?: string }>();
  const location = useLocation();

  return (
    <div className="max-w-5xl mx-auto px-4 py-12">
      {id && (
        <Link
          to={`/analyses/${id}`}
          className="inline-flex items-center space-x-2 text-sm text-sky-400 hover:text-sky-300 mb-6 transition-colors"
        >
          <ArrowLeft className="w-4 h-4" />
          <span>Back to Analysis Overview</span>
        </Link>
      )}

      <div className="bg-slate-800/60 border border-slate-700 rounded-xl p-8 text-center shadow-lg">
        <div className="w-16 h-16 bg-sky-950/80 border border-sky-800 rounded-full flex items-center justify-center mx-auto mb-4 text-sky-400">
          <Layers className="w-8 h-8" />
        </div>
        <div className="inline-block px-2.5 py-1 rounded bg-slate-900 border border-slate-700 text-xs font-mono text-slate-400 mb-2">
          Screen #{screenId} • Route: {location.pathname}
        </div>
        <h2 className="text-xl font-bold text-white mb-2">{title}</h2>
        <p className="text-slate-400 max-w-md mx-auto text-sm leading-relaxed mb-6">
          {description}
        </p>

        <div className="bg-slate-900/80 border border-slate-800 rounded-lg p-4 max-w-lg mx-auto text-left text-xs text-slate-400 space-y-1 font-mono">
          <div>Status: Route registered (TASK-005 Shell)</div>
          <div>Analysis ID: {id || 'N/A'}</div>
          <div>Data Source: Real API consumption (No mock data permitted)</div>
        </div>
      </div>
    </div>
  );
};

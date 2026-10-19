import React from 'react';
import { CapabilityStatus } from '../types';

interface Props {
  status: CapabilityStatus;
}

export const CapabilityBadge: React.FC<Props> = ({ status }) => {
  switch (status) {
    case 'implemented':
      return (
        <span className="inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium bg-emerald-950 text-emerald-400 border border-emerald-800">
          Implemented
        </span>
      );
    case 'partial':
      return (
        <span className="inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium bg-amber-950 text-amber-400 border border-amber-800">
          Partial / Heuristic
        </span>
      );
    case 'not_implemented':
      return (
        <span className="inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium bg-slate-800 text-slate-400 border border-slate-700">
          Not Implemented
        </span>
      );
    case 'not_configured':
      return (
        <span className="inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium bg-slate-800 text-amber-400 border border-amber-800/60">
          Not Configured
        </span>
      );
    default:
      return null;
  }
};

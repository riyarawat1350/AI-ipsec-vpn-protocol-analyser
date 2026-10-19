import React from 'react';
import { NavLink, useParams } from 'react-router-dom';
import {
  LayoutDashboard,
  Network,
  KeyRound,
  ShieldAlert,
  AlertTriangle,
  Flame,
  CheckCircle2,
  Clock,
  FileText,
} from 'lucide-react';

interface AnalysisNavProps {
  analysisId?: string;
}

export const AnalysisNav: React.FC<AnalysisNavProps> = ({ analysisId }) => {
  const params = useParams<{ id: string }>();
  const id = analysisId || params.id;

  if (!id) return null;

  const links = [
    { to: `/analyses/${id}`, label: 'Overview', icon: LayoutDashboard, end: true },
    { to: `/analyses/${id}/protocols`, label: 'Protocols', icon: Network },
    { to: `/analyses/${id}/ike`, label: 'IKE Sessions', icon: KeyRound },
    { to: `/analyses/${id}/esp`, label: 'ESP Flows', icon: ShieldAlert },
    { to: `/analyses/${id}/findings`, label: 'Findings', icon: AlertTriangle },
    { to: `/analyses/${id}/risk`, label: 'Risk Math', icon: Flame },
    { to: `/analyses/${id}/fix-first`, label: 'Fix-First', icon: CheckCircle2 },
    { to: `/analyses/${id}/timeline`, label: 'Timeline', icon: Clock },
    { to: `/analyses/${id}/report`, label: 'Report', icon: FileText },
  ];

  return (
    <nav className="flex items-center space-x-1 overflow-x-auto pb-1 mb-6 border-b border-slate-800 scrollbar-thin">
      {links.map((link) => {
        const Icon = link.icon;
        return (
          <NavLink
            key={link.to}
            to={link.to}
            end={link.end}
            className={({ isActive }) =>
              `flex items-center space-x-2 px-3.5 py-2 rounded-lg text-xs font-semibold whitespace-nowrap transition-colors ${
                isActive
                  ? 'bg-sky-500/15 text-sky-400 border border-sky-500/30'
                  : 'text-slate-400 hover:text-slate-200 hover:bg-slate-800/60'
              }`
            }
          >
            <Icon className="w-3.5 h-3.5" />
            <span>{link.label}</span>
          </NavLink>
        );
      })}
    </nav>
  );
};

import React from 'react';

interface SeverityBadgeProps {
  severity: string;
  size?: 'sm' | 'md' | 'lg';
}

export const SeverityBadge: React.FC<SeverityBadgeProps> = ({ severity, size = 'md' }) => {
  const sevLower = severity.toLowerCase();

  const styles: Record<string, { bg: string; text: string; border: string; icon: string }> = {
    critical: {
      bg: 'bg-red-950/70',
      text: 'text-red-400',
      border: 'border-red-600/50',
      icon: '🚨',
    },
    high: {
      bg: 'bg-orange-950/70',
      text: 'text-orange-400',
      border: 'border-orange-600/50',
      icon: '⚠️',
    },
    medium: {
      bg: 'bg-amber-950/70',
      text: 'text-amber-400',
      border: 'border-amber-600/50',
      icon: '⚡',
    },
    low: {
      bg: 'bg-blue-950/70',
      text: 'text-blue-400',
      border: 'border-blue-600/50',
      icon: 'ℹ️',
    },
    info: {
      bg: 'bg-slate-800/80',
      text: 'text-slate-300',
      border: 'border-slate-600/50',
      icon: '📋',
    },
  };

  const style = styles[sevLower] || styles.info;

  const sizeClasses = {
    sm: 'text-xs px-2 py-0.5 gap-1',
    md: 'text-xs px-2.5 py-1 gap-1.5 font-semibold',
    lg: 'text-sm px-3.5 py-1.5 gap-2 font-bold',
  }[size];

  return (
    <span
      className={`inline-flex items-center rounded-full border shadow-sm ${style.bg} ${style.text} ${style.border} ${sizeClasses}`}
    >
      <span className="text-[11px]">{style.icon}</span>
      <span>{severity.toUpperCase()}</span>
    </span>
  );
};

import React from 'react';

interface PostureGaugeProps {
  score: number;
  grade: string;
  size?: number;
}

export const PostureGauge: React.FC<PostureGaugeProps> = ({ score, grade, size = 180 }) => {
  const clampedScore = Math.max(0, Math.min(100, score));
  const strokeWidth = 14;
  const radius = (size - strokeWidth) / 2;
  const circumference = 2 * Math.PI * radius;
  // Use 75% arc or full circle
  const strokeDashoffset = circumference - (clampedScore / 100) * circumference;

  const getGradeColor = (g: string) => {
    switch (g.toUpperCase()) {
      case 'A':
        return { stroke: '#10b981', text: 'text-emerald-400', label: 'No weaknesses in observed parts' };
      case 'B':
        return { stroke: '#3b82f6', text: 'text-blue-400', label: 'Standard parameters observed' };
      case 'C':
        return { stroke: '#f59e0b', text: 'text-amber-400', label: 'Needs attention' };
      case 'D':
        return { stroke: '#ea580c', text: 'text-orange-400', label: 'Elevated risk' };
      default:
        return { stroke: '#ef4444', text: 'text-red-400', label: 'Critical risk' };
    }
  };

  const style = getGradeColor(grade);

  return (
    <div className="flex flex-col items-center justify-center p-4">
      <div className="relative" style={{ width: size, height: size }}>
        <svg className="w-full h-full transform -rotate-90" viewBox={`0 0 ${size} ${size}`}>
          {/* Background Track */}
          <circle
            cx={size / 2}
            cy={size / 2}
            r={radius}
            stroke="#1e293b"
            strokeWidth={strokeWidth}
            fill="transparent"
          />
          {/* Animated Value Arc */}
          <circle
            cx={size / 2}
            cy={size / 2}
            r={radius}
            stroke={style.stroke}
            strokeWidth={strokeWidth}
            strokeDasharray={circumference}
            strokeDashoffset={strokeDashoffset}
            strokeLinecap="round"
            fill="transparent"
            className="transition-all duration-1000 ease-out"
          />
        </svg>

        {/* Center Text */}
        <div className="absolute inset-0 flex flex-col items-center justify-center text-center">
          <div className="text-3xl font-extrabold tracking-tight text-white">
            {clampedScore.toFixed(1)}
          </div>
          <div className={`text-xl font-black ${style.text}`}>
            GRADE {grade}
          </div>
        </div>
      </div>

      <div className="mt-3 text-center">
        <span className={`inline-block px-3 py-0.5 rounded-full text-xs font-semibold uppercase tracking-wider bg-slate-800 border border-slate-700 ${style.text}`}>
          {style.label}
        </span>
      </div>
    </div>
  );
};

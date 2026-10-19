import React from 'react';
import { useParams } from 'react-router-dom';
import { AnalysisNav } from '../components/AnalysisNav';
import { FileText, Download, Printer, ExternalLink, Code, FileSpreadsheet } from 'lucide-react';

export const ReportPage: React.FC = () => {
  const { id } = useParams<{ id: string }>();

  if (!id) return null;

  const previewUrl = `/api/v1/analyses/${id}/report?format=html`;

  const handleDownload = (fmt: 'html' | 'json' | 'csv') => {
    window.open(`/api/v1/analyses/${id}/report?format=${fmt}`, '_blank');
  };

  const handlePrint = () => {
    const iframe = document.getElementById('report-preview-frame') as HTMLIFrameElement;
    if (iframe && iframe.contentWindow) {
      iframe.contentWindow.focus();
      iframe.contentWindow.print();
    } else {
      window.print();
    }
  };

  return (
    <div className="max-w-7xl mx-auto px-4 py-8 space-y-6">
      <AnalysisNav />

      {/* Header */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 border-b border-slate-800 pb-5">
        <div>
          <h1 className="text-2xl font-bold text-white flex items-center gap-2.5">
            <FileText className="w-6 h-6 text-sky-400" /> Compliance Audit Report Generation
          </h1>
          <p className="text-xs text-slate-400 mt-1">
            Export executive summaries, protocol distributions, and packet findings for audit readiness.
          </p>
        </div>

        {/* Action Buttons */}
        <div className="flex flex-wrap items-center gap-2">
          <button
            onClick={() => handleDownload('html')}
            className="px-3.5 py-2 rounded-lg bg-sky-500 hover:bg-sky-400 text-slate-950 font-bold text-xs shadow-md transition-all flex items-center gap-1.5"
          >
            <Download className="w-3.5 h-3.5" />
            <span>Download HTML</span>
          </button>

          <button
            onClick={() => handleDownload('json')}
            className="px-3.5 py-2 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-200 font-semibold text-xs border border-slate-700 transition-all flex items-center gap-1.5"
          >
            <Code className="w-3.5 h-3.5 text-sky-400" />
            <span>JSON</span>
          </button>

          <button
            onClick={() => handleDownload('csv')}
            className="px-3.5 py-2 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-200 font-semibold text-xs border border-slate-700 transition-all flex items-center gap-1.5"
          >
            <FileSpreadsheet className="w-3.5 h-3.5 text-emerald-400" />
            <span>CSV</span>
          </button>

          <button
            onClick={handlePrint}
            className="px-3.5 py-2 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-200 font-semibold text-xs border border-slate-700 transition-all flex items-center gap-1.5"
          >
            <Printer className="w-3.5 h-3.5 text-slate-400" />
            <span>Print / PDF</span>
          </button>
        </div>
      </div>

      {/* Embedded Live Sandboxed Preview */}
      <div className="bg-slate-900 border border-slate-800 rounded-2xl overflow-hidden shadow-2xl flex flex-col">
        <div className="px-5 py-3 bg-slate-950 border-b border-slate-800 flex items-center justify-between text-xs text-slate-400">
          <div className="flex items-center gap-2">
            <span className="w-2.5 h-2.5 rounded-full bg-emerald-500 animate-pulse" />
            <span className="font-mono text-slate-300">Live Sandboxed Report Preview</span>
          </div>
          <a
            href={previewUrl}
            target="_blank"
            rel="noopener noreferrer"
            className="hover:text-sky-400 flex items-center gap-1 text-[11px]"
          >
            <span>Open in Full Tab</span>
            <ExternalLink className="w-3 h-3" />
          </a>
        </div>

        <div className="w-full h-[850px] bg-white">
          <iframe
            id="report-preview-frame"
            src={previewUrl}
            title="Analysis Audit Report Preview"
            className="w-full h-full border-none"
            sandbox="allow-same-origin allow-scripts allow-modals"
          />
        </div>
      </div>
    </div>
  );
};

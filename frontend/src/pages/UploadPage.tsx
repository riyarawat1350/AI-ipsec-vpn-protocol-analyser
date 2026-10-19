import React, { useEffect, useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { fetchCapabilities, uploadCapture } from '../api/client';

export const UploadPage: React.FC = () => {
  const [file, setFile] = useState<File | null>(null);
  const [policy, setPolicy] = useState('nist_default');
  const [enableMl, setEnableMl] = useState(true);
  const [enableLlm, setEnableLlm] = useState(false);
  const [llmConfigured, setLlmConfigured] = useState(true);
  const [redactIdentities, setRedactIdentities] = useState(true);
  const [isDragging, setIsDragging] = useState(false);
  const [uploading, setUploading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const navigate = useNavigate();

  useEffect(() => {
    fetchCapabilities()
      .then((caps) => {
        const fr60 = caps.find((c) => c.id === 'FR-60');
        if (fr60 && fr60.status === 'not_configured') {
          setLlmConfigured(false);
          setEnableLlm(false);
        } else {
          setLlmConfigured(true);
        }
      })
      .catch(() => setLlmConfigured(false));
  }, []);

  const handleDragOver = (e: React.DragEvent) => {
    e.preventDefault();
    setIsDragging(true);
  };

  const handleDragLeave = (e: React.DragEvent) => {
    e.preventDefault();
    setIsDragging(false);
  };

  const handleDrop = (e: React.DragEvent) => {
    e.preventDefault();
    setIsDragging(false);
    if (e.dataTransfer.files && e.dataTransfer.files.length > 0) {
      setFile(e.dataTransfer.files[0]);
    }
  };

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!file) {
      setError('Please select or drop a capture file.');
      return;
    }

    try {
      setUploading(true);
      setError(null);

      const formData = new FormData();
      formData.append('file', file);
      formData.append('policy', policy);
      formData.append('enable_ml', String(enableMl));
      formData.append('enable_llm', String(enableLlm));
      formData.append('redact_identities', String(redactIdentities));

      const res = await uploadCapture(formData);
      navigate(`/analyses/${res.analysis_id}/progress`);
    } catch (err: any) {
      setError(err?.error?.message || 'Upload failed. Please check capture format.');
      setUploading(false);
    }
  };

  return (
    <div className="max-w-4xl mx-auto px-4 py-10 space-y-6">
      <div className="text-center space-y-2">
        <h1 className="text-3xl font-extrabold text-white">Upload IPsec Capture File</h1>
        <p className="text-slate-400 text-sm">
          Select or drag a PCAP or PCAPNG packet trace containing IKE or ESP/AH communication.
        </p>
      </div>

      {error && (
        <div className="p-4 rounded-lg bg-red-950/50 border border-red-800 text-red-300 text-sm flex items-center gap-3">
          <span>❌</span>
          <span>{error}</span>
        </div>
      )}

      <form onSubmit={handleSubmit} className="bg-slate-900 border border-slate-800 rounded-2xl p-8 space-y-6 shadow-xl">
        {/* Drop Zone */}
        <div
          onDragOver={handleDragOver}
          onDragLeave={handleDragLeave}
          onDrop={handleDrop}
          className={`border-2 border-dashed rounded-xl p-10 text-center cursor-pointer transition-all ${
            isDragging
              ? 'border-sky-400 bg-sky-950/20'
              : file
              ? 'border-emerald-500/60 bg-emerald-950/10'
              : 'border-slate-700 hover:border-slate-600 bg-slate-950/50'
          }`}
          onClick={() => document.getElementById('capture-input')?.click()}
        >
          <input
            id="capture-input"
            type="file"
            accept=".pcap,.pcapng,.cap"
            className="hidden"
            onChange={(e) => {
              if (e.target.files && e.target.files.length > 0) {
                setFile(e.target.files[0]);
              }
            }}
          />

          {file ? (
            <div className="space-y-2">
              <div className="text-4xl text-emerald-400">📄</div>
              <div className="font-semibold text-white text-base">{file.name}</div>
              <div className="text-xs text-slate-400">
                {(file.size / 1024).toFixed(1)} KB · Ready to analyze
              </div>
              <button
                type="button"
                onClick={(e) => {
                  e.stopPropagation();
                  setFile(null);
                }}
                className="text-xs text-red-400 hover:underline pt-2"
              >
                Choose another file
              </button>
            </div>
          ) : (
            <div className="space-y-3">
              <div className="text-5xl text-sky-400">📥</div>
              <div className="text-base font-semibold text-slate-200">
                Drag and drop your capture here, or <span className="text-sky-400 underline">browse</span>
              </div>
              <div className="text-xs text-slate-500">
                Supports .pcap, .pcapng files up to 200 MB
              </div>
            </div>
          )}
        </div>

        {/* Options Grid */}
        <div className="grid grid-cols-1 md:grid-cols-2 gap-6 pt-2">
          {/* Policy Profile */}
          <div className="space-y-2">
            <label className="text-sm font-semibold text-slate-300 flex items-center gap-1.5">
              <span>📋</span> Security Policy Profile
            </label>
            <select
              value={policy}
              onChange={(e) => setPolicy(e.target.value)}
              className="w-full bg-slate-950 border border-slate-700 rounded-lg px-3 py-2 text-sm text-slate-200 focus:outline-none focus:border-sky-500"
            >
              <option value="nist_default">NIST SP 800-77 Default (Recommended)</option>
              <option value="strict">Strict (Disallow SHA-1 & Non-AEAD)</option>
              <option value="legacy_tolerant">Legacy Tolerant (Permits 3DES & MODP-1536)</option>
            </select>
            <p className="text-xs text-slate-500">
              Governs acceptable Diffie-Hellman groups, PRFs, and cipher thresholds.
            </p>
          </div>

          {/* Toggle Switches */}
          <div className="space-y-3">
            <label className="text-sm font-semibold text-slate-300 block">
              Inspection Options
            </label>

            <label className="flex items-center gap-3 cursor-pointer">
              <input
                type="checkbox"
                checked={enableMl}
                onChange={(e) => setEnableMl(e.target.checked)}
                className="w-4 h-4 rounded bg-slate-950 border-slate-700 text-sky-500 focus:ring-0"
              />
              <span className="text-xs text-slate-300">
                Enable Behavioral Heuristics (Flood & Scan Detectors)
              </span>
            </label>

            <label className="flex items-center gap-3 cursor-pointer">
              <input
                type="checkbox"
                checked={redactIdentities}
                onChange={(e) => setRedactIdentities(e.target.checked)}
                className="w-4 h-4 rounded bg-slate-950 border-slate-700 text-sky-500 focus:ring-0"
              />
              <span className="text-xs text-slate-300">
                Redact Peer Identity Strings in Aggressive Mode
              </span>
            </label>

            <label className={`flex items-center gap-3 ${!llmConfigured ? 'opacity-50 cursor-not-allowed' : 'cursor-pointer'}`}>
              <input
                type="checkbox"
                checked={enableLlm && llmConfigured}
                disabled={!llmConfigured}
                onChange={(e) => setEnableLlm(e.target.checked)}
                className="w-4 h-4 rounded bg-slate-950 border-slate-700 text-sky-500 focus:ring-0 disabled:opacity-40"
              />
              <span className="text-xs text-slate-300">
                Enable AI Executive Narrative {llmConfigured ? '(Groq / LLaMA 3.3)' : '(Disabled - Not configured in .env)'}
              </span>
            </label>
          </div>
        </div>

        {/* Submit */}
        <div className="pt-4 border-t border-slate-800 flex justify-end gap-3">
          <button
            type="button"
            onClick={() => navigate('/')}
            className="px-4 py-2 rounded-lg text-sm text-slate-400 hover:text-white"
          >
            Cancel
          </button>
          <button
            type="submit"
            disabled={!file || uploading}
            className={`px-6 py-2.5 rounded-lg text-sm font-bold shadow-lg transition-all ${
              !file || uploading
                ? 'bg-slate-800 text-slate-500 cursor-not-allowed'
                : 'bg-sky-500 hover:bg-sky-400 text-slate-950 shadow-sky-500/20'
            }`}
          >
            {uploading ? 'Uploading & Starting...' : 'Run Security Assessment 🚀'}
          </button>
        </div>
      </form>
    </div>
  );
};

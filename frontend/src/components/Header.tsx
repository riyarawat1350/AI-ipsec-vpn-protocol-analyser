import React, { useState } from 'react';
import { Link, useLocation } from 'react-router-dom';
import { Shield, Key, Info, UploadCloud, Layers } from 'lucide-react';
import { getStoredApiToken, setStoredApiToken } from '../api/client';

export const Header: React.FC = () => {
  const location = useLocation();
  const [tokenModalOpen, setTokenModalOpen] = useState(false);
  const [tokenInput, setTokenInput] = useState(getStoredApiToken());
  const [currentToken, setCurrentToken] = useState(getStoredApiToken());

  const handleSaveToken = () => {
    setStoredApiToken(tokenInput);
    setCurrentToken(tokenInput);
    setTokenModalOpen(false);
  };

  const navLinks = [
    { to: '/', label: 'Analyses', icon: Layers },
    { to: '/new', label: 'Upload Capture', icon: UploadCloud },
    { to: '/compare', label: 'Compare', icon: Shield },
    { to: '/about', label: 'Capabilities', icon: Info },
  ];

  return (
    <header className="bg-slate-800 border-b border-slate-700 sticky top-0 z-50">
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 h-16 flex items-center justify-between">
        <div className="flex items-center space-x-8">
          <Link to="/" className="flex items-center space-x-3 text-sky-400 hover:text-sky-300 transition-colors">
            <Shield className="w-8 h-8 text-sky-500" />
            <div>
              <span className="text-xl font-bold tracking-tight text-white">IPsec<span className="text-sky-400">Scope</span></span>
              <span className="ml-2 text-xs px-2 py-0.5 rounded bg-sky-950 text-sky-400 border border-sky-800">v0.1.0</span>
            </div>
          </Link>

          <nav className="hidden md:flex space-x-1">
            {navLinks.map((link) => {
              const Icon = link.icon;
              const isActive = location.pathname === link.to;
              return (
                <Link
                  key={link.to}
                  to={link.to}
                  className={`flex items-center space-x-2 px-3 py-2 rounded-md text-sm font-medium transition-colors ${
                    isActive
                      ? 'bg-slate-900 text-sky-400'
                      : 'text-slate-300 hover:bg-slate-700/50 hover:text-white'
                  }`}
                >
                  <Icon className="w-4 h-4" />
                  <span>{link.label}</span>
                </Link>
              );
            })}
          </nav>
        </div>

        <div className="flex items-center space-x-4">
          <button
            onClick={() => setTokenModalOpen(true)}
            className={`flex items-center space-x-1.5 px-3 py-1.5 rounded text-xs font-medium border transition-colors ${
              currentToken
                ? 'bg-emerald-950/60 border-emerald-700 text-emerald-400 hover:bg-emerald-900/60'
                : 'bg-slate-900 border-slate-700 text-slate-400 hover:text-slate-200'
            }`}
          >
            <Key className="w-3.5 h-3.5" />
            <span>{currentToken ? 'Token Configured' : 'Auth Token'}</span>
          </button>
        </div>
      </div>

      {tokenModalOpen && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 backdrop-blur-sm">
          <div className="bg-slate-800 border border-slate-700 rounded-lg p-6 max-w-md w-full mx-4 shadow-xl">
            <h3 className="text-lg font-semibold text-white mb-2 flex items-center gap-2">
              <Key className="w-5 h-5 text-sky-400" /> API Authentication Token
            </h3>
            <p className="text-sm text-slate-400 mb-4">
              Enter the Bearer token for accessing protected analyses. This is stored exclusively in your browser session memory.
            </p>
            <input
              type="password"
              placeholder="Enter Bearer Token..."
              value={tokenInput}
              onChange={(e) => setTokenInput(e.target.value)}
              className="w-full bg-slate-900 border border-slate-700 rounded px-3 py-2 text-sm text-slate-100 focus:outline-none focus:border-sky-500 mb-4"
            />
            <div className="flex justify-end space-x-3">
              <button
                onClick={() => setTokenModalOpen(false)}
                className="px-4 py-2 text-sm font-medium text-slate-400 hover:text-white"
              >
                Cancel
              </button>
              <button
                onClick={handleSaveToken}
                className="px-4 py-2 text-sm font-medium bg-sky-600 hover:bg-sky-500 text-white rounded transition-colors"
              >
                Save Token
              </button>
            </div>
          </div>
        </div>
      )}
    </header>
  );
};

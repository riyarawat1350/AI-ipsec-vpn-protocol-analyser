import React from 'react';
import { BrowserRouter, Routes, Route, Navigate } from 'react-router-dom';
import { Header } from './components/Header';

// 16 Complete Screen Pages
import { LandingPage } from './pages/LandingPage';
import { UploadPage } from './pages/UploadPage';
import { ProgressPage } from './pages/ProgressPage';
import { OverviewPage } from './pages/OverviewPage';
import { ProtocolsPage } from './pages/ProtocolsPage';
import { IkeSessionsPage } from './pages/IkeSessionsPage';
import { IkeSessionDetailPage } from './pages/IkeSessionDetailPage';
import { EspFlowsPage } from './pages/EspFlowsPage';
import { FindingsPage } from './pages/FindingsPage';
import { FindingDetailPage } from './pages/FindingDetailPage';
import { RiskPage } from './pages/RiskPage';
import { RecommendationsPage } from './pages/RecommendationsPage';
import { TimelinePage } from './pages/TimelinePage';
import { ComparePage } from './pages/ComparePage';
import { ReportPage } from './pages/ReportPage';
import { CapabilitiesPage } from './pages/CapabilitiesPage';

export const App: React.FC = () => {
  return (
    <BrowserRouter>
      <div className="min-h-screen flex flex-col bg-slate-900 text-slate-100">
        <Header />
        <main className="flex-1">
          <Routes>
            {/* Screen 1: Landing */}
            <Route path="/" element={<LandingPage />} />

            {/* Screen 2: Upload */}
            <Route path="/new" element={<UploadPage />} />

            {/* Screen 3: Progress */}
            <Route path="/analyses/:id/progress" element={<ProgressPage />} />

            {/* Screen 4: Overview */}
            <Route path="/analyses/:id" element={<OverviewPage />} />

            {/* Screen 5: Protocols */}
            <Route path="/analyses/:id/protocols" element={<ProtocolsPage />} />

            {/* Screen 6: IKE Sessions */}
            <Route path="/analyses/:id/ike" element={<IkeSessionsPage />} />

            {/* Screen 7: IKE Session Detail */}
            <Route path="/analyses/:id/ike/:sid" element={<IkeSessionDetailPage />} />

            {/* Screen 8: ESP/AH Flows */}
            <Route path="/analyses/:id/esp" element={<EspFlowsPage />} />

            {/* Screen 9: Findings */}
            <Route path="/analyses/:id/findings" element={<FindingsPage />} />

            {/* Screen 10: Finding Detail */}
            <Route path="/analyses/:id/findings/:fid" element={<FindingDetailPage />} />

            {/* Screen 11: Risk Math & Breakdown */}
            <Route path="/analyses/:id/risk" element={<RiskPage />} />

            {/* Screen 12: Fix-First Recommendations */}
            <Route path="/analyses/:id/fix-first" element={<RecommendationsPage />} />

            {/* Screen 13: Capture Events Timeline */}
            <Route path="/analyses/:id/timeline" element={<TimelinePage />} />

            {/* Screen 14: Capture Comparison & Delta */}
            <Route path="/compare" element={<ComparePage />} />

            {/* Screen 15: Compliance Audit Report */}
            <Route path="/analyses/:id/report" element={<ReportPage />} />

            {/* Screen 16: Capabilities & Scope Declaration */}
            <Route path="/about" element={<CapabilitiesPage />} />
            <Route path="/capabilities" element={<Navigate to="/about" replace />} />

            {/* Fallback */}
            <Route path="*" element={<Navigate to="/" replace />} />
          </Routes>
        </main>
      </div>
    </BrowserRouter>
  );
};

export default App;

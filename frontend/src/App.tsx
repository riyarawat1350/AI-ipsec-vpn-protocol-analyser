import React from 'react';
import { BrowserRouter, Routes, Route, Navigate } from 'react-router-dom';
import { Header } from './components/Header';
import { CapabilitiesPage } from './pages/CapabilitiesPage';
import { EmptyStatePage } from './pages/EmptyStatePage';

export const App: React.FC = () => {
  return (
    <BrowserRouter>
      <div className="min-h-screen flex flex-col bg-slate-900 text-slate-100">
        <Header />
        <main className="flex-1">
          <Routes>
            {/* Screen 1: Landing */}
            <Route
              path="/"
              element={
                <EmptyStatePage
                  screenId={1}
                  title="Landing & Recent Analyses"
                  description="Overview of recent capture analyses, quick status indicators, and analysis upload entrypoint."
                />
              }
            />

            {/* Screen 2: Upload */}
            <Route
              path="/new"
              element={
                <EmptyStatePage
                  screenId={2}
                  title="Upload Capture"
                  description="Drag-and-drop PCAP/PCAPNG capture upload with policy selection and processing options."
                />
              }
            />

            {/* Screen 3: Progress */}
            <Route
              path="/analyses/:id/progress"
              element={
                <EmptyStatePage
                  screenId={3}
                  title="Analysis Progress"
                  description="Real-time multi-stage ingestion and pipeline execution progress stepper."
                />
              }
            />

            {/* Screen 4: Overview */}
            <Route
              path="/analyses/:id"
              element={
                <EmptyStatePage
                  screenId={4}
                  title="Analysis Overview"
                  description="Comprehensive security posture dashboard, score gauge, grade, and protocol distribution."
                />
              }
            />

            {/* Screen 5: Protocols */}
            <Route
              path="/analyses/:id/protocols"
              element={
                <EmptyStatePage
                  screenId={5}
                  title="Protocol Distribution & Top Talkers"
                  description="Breakdown of IKE, ESP, AH, keepalives, conversation pairs, and port statistics."
                />
              }
            />

            {/* Screen 6: IKE Sessions */}
            <Route
              path="/analyses/:id/ike"
              element={
                <EmptyStatePage
                  screenId={6}
                  title="IKE Sessions List"
                  description="Reconstructed IKEv1 and IKEv2 negotiations, outcome states, and crypto summaries."
                />
              }
            />

            {/* Screen 7: IKE Session Detail */}
            <Route
              path="/analyses/:id/ike/:sid"
              element={
                <EmptyStatePage
                  screenId={7}
                  title="IKE Session Detail & Handshake Ladder"
                  description="Interactive sequence ladder, offered vs selected proposal comparison, and unobservable region notes."
                />
              }
            />

            {/* Screen 8: ESP/AH Flows */}
            <Route
              path="/analyses/:id/esp"
              element={
                <EmptyStatePage
                  screenId={8}
                  title="ESP/AH Directional Flows"
                  description="Sequence numbers, gap tracking, timing statistics, and ESP-NULL detection indicators."
                />
              }
            />

            {/* Screen 9: Findings */}
            <Route
              path="/analyses/:id/findings"
              element={
                <EmptyStatePage
                  screenId={9}
                  title="Security Findings List"
                  description="Filterable, server-paginated security findings categorized by severity and risk score."
                />
              }
            />

            {/* Screen 10: Finding Detail */}
            <Route
              path="/analyses/:id/findings/:fid"
              element={
                <EmptyStatePage
                  screenId={10}
                  title="Finding Detail & Packet Evidence"
                  description="Deep dive into vulnerability explanation, why it matters, packet-level hex excerpts, and references."
                />
              }
            />

            {/* Screen 11: Risk Dashboard */}
            <Route
              path="/analyses/:id/risk"
              element={
                <EmptyStatePage
                  screenId={11}
                  title="Risk Assessment & ML Anomalies"
                  description="Formula-based risk scoring breakdown, category distribution, and unsupervised anomaly window scores."
                />
              }
            />

            {/* Screen 12: Recommendations */}
            <Route
              path="/analyses/:id/fix-first"
              element={
                <EmptyStatePage
                  screenId={12}
                  title="Fix-First Recommendations"
                  description="Prioritized remediation actions ranked by risk reduction impact and operational effort."
                />
              }
            />

            {/* Screen 13: Timeline */}
            <Route
              path="/analyses/:id/timeline"
              element={
                <EmptyStatePage
                  screenId={13}
                  title="Capture Events Timeline"
                  description="Chronological event viewer spanning handshakes, rekeys, floods, and error notifications."
                />
              }
            />

            {/* Screen 14: Compare */}
            <Route
              path="/compare"
              element={
                <EmptyStatePage
                  screenId={14}
                  title="Capture Comparison & Delta"
                  description="Side-by-side comparison of two captures highlighting resolved, new, and persistent vulnerabilities."
                />
              }
            />

            {/* Screen 15: Report */}
            <Route
              path="/analyses/:id/report"
              element={
                <EmptyStatePage
                  screenId={15}
                  title="Report Generation & Export"
                  description="Audit report generation in HTML, PDF, JSON, and CSV formats with live sandboxed preview."
                />
              }
            />

            {/* Screen 16: Capabilities */}
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

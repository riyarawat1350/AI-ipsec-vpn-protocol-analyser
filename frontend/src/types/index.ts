export type CapabilityStatus = 'implemented' | 'partial' | 'not_implemented' | 'not_configured';

export interface CapabilityEntry {
  id: string;
  feature: string;
  status: CapabilityStatus;
  priority: 'M' | 'S' | 'A' | 'F';
  notes: string;
  confidence: number;
  heuristic: boolean;
}

export interface StandardError {
  error: {
    code: string;
    message: string;
    details?: Record<string, unknown>;
  };
}

export interface AnalysisSummary {
  id: string;
  upload_id: string;
  status: 'queued' | 'running' | 'completed' | 'failed';
  stage: string;
  progress: number;
  policy_id: string;
  posture_score?: number | null;
  grade?: string | null;
  created_at: string;
  completed_at?: string | null;
  error_code?: string | null;
  error_message?: string | null;
}

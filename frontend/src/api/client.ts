import { CapabilityEntry, StandardError } from '../types';

const API_BASE = '/api/v1';

export function getStoredApiToken(): string {
  return sessionStorage.getItem('ipsecscope_api_token') || '';
}

export function setStoredApiToken(token: string): void {
  if (token) {
    sessionStorage.setItem('ipsecscope_api_token', token);
  } else {
    sessionStorage.removeItem('ipsecscope_api_token');
  }
}

async function request<T>(endpoint: string, options: RequestInit = {}): Promise<T> {
  const headers = new Headers(options.headers || {});
  if (!options.body || !(options.body instanceof FormData)) {
    headers.set('Accept', 'application/json');
    if (!headers.has('Content-Type')) {
      headers.set('Content-Type', 'application/json');
    }
  }

  const token = getStoredApiToken();
  if (token) {
    headers.set('Authorization', `Bearer ${token}`);
  }

  const response = await fetch(`${API_BASE}${endpoint}`, {
    ...options,
    headers,
  });

  if (!response.ok) {
    let errBody: StandardError;
    try {
      errBody = await response.json();
    } catch {
      errBody = {
        error: {
          code: 'NETWORK_ERROR',
          message: response.statusText || 'Unknown network error',
        },
      };
    }
    throw errBody;
  }

  if (response.status === 204) {
    return {} as T;
  }

  return response.json();
}

// Meta
export async function fetchCapabilities(): Promise<CapabilityEntry[]> {
  return request<CapabilityEntry[]>('/capabilities');
}

export async function fetchHealth(): Promise<{ status: string; version: string }> {
  return request<{ status: string; version: string }>('/health');
}

export async function fetchPolicies(): Promise<any[]> {
  return request<any[]>('/policies');
}

// Analyses
export async function uploadCapture(formData: FormData): Promise<{ analysis_id: string; status: string }> {
  return request<{ analysis_id: string; status: string }>('/analyses', {
    method: 'POST',
    body: formData,
  });
}

export async function fetchAnalyses(page = 1, pageSize = 20, status?: string): Promise<{ items: any[]; total: number; page: number; page_size: number }> {
  const params = new URLSearchParams({ page: String(page), page_size: String(pageSize) });
  if (status) params.set('status', status);
  return request(`/analyses?${params.toString()}`);
}

export async function fetchAnalysis(id: string): Promise<any> {
  return request<any>(`/analyses/${id}`);
}

export async function deleteAnalysis(id: string): Promise<void> {
  await request<void>(`/analyses/${id}`, { method: 'DELETE' });
}

export async function fetchOverview(id: string): Promise<any> {
  return request<any>(`/analyses/${id}/overview`);
}

export async function fetchProtocols(id: string): Promise<any> {
  return request<any>(`/analyses/${id}/protocols`);
}

export async function fetchTimeline(id: string): Promise<any[]> {
  return request<any[]>(`/analyses/${id}/timeline`);
}

// IKE
export async function fetchIkeSessions(id: string, page = 1, pageSize = 50, version?: number, outcome?: string): Promise<{ items: any[]; total: number }> {
  const params = new URLSearchParams({ page: String(page), page_size: String(pageSize) });
  if (version) params.set('version', String(version));
  if (outcome) params.set('outcome', outcome);
  return request(`/analyses/${id}/ike?${params.toString()}`);
}

export async function fetchIkeSession(id: string, sid: string): Promise<any> {
  return request<any>(`/analyses/${id}/ike/${sid}`);
}

// ESP
export async function fetchEspFlows(id: string, page = 1, pageSize = 50, proto?: string): Promise<{ items: any[]; total: number }> {
  const params = new URLSearchParams({ page: String(page), page_size: String(pageSize) });
  if (proto) params.set('proto', proto);
  return request(`/analyses/${id}/esp?${params.toString()}`);
}

export async function fetchEspFlow(id: string, fid: string): Promise<any> {
  return request<any>(`/analyses/${id}/esp/${fid}`);
}

// Findings
export async function fetchFindings(id: string, filters: { severity?: string; rule_id?: string; category?: string; q?: string; page?: number; page_size?: number } = {}): Promise<{ items: any[]; total: number }> {
  const params = new URLSearchParams();
  if (filters.severity) params.set('severity', filters.severity);
  if (filters.rule_id) params.set('rule_id', filters.rule_id);
  if (filters.category) params.set('category', filters.category);
  if (filters.q) params.set('q', filters.q);
  if (filters.page) params.set('page', String(filters.page));
  if (filters.page_size) params.set('page_size', String(filters.page_size));
  return request(`/analyses/${id}/findings?${params.toString()}`);
}

export async function fetchFinding(id: string, fid: string): Promise<any> {
  return request<any>(`/analyses/${id}/findings/${fid}`);
}

export async function fetchRecommendations(id: string): Promise<any[]> {
  return request<any[]>(`/analyses/${id}/recommendations`);
}

// Comparison
export async function compareAnalyses(baselineId: string, candidateId: string): Promise<any> {
  return request<any>('/compare', {
    method: 'POST',
    body: JSON.stringify({ baseline_id: baselineId, candidate_id: candidateId }),
  });
}

// Reports
export async function generateReport(id: string, format = 'html'): Promise<any> {
  return request<any>(`/analyses/${id}/reports`, {
    method: 'POST',
    body: JSON.stringify({ format }),
  });
}

// Glossary
export interface GlossaryTerm {
  id: string;
  name: string;
  expansion: string;
  simple: string;
  analogy?: string;
  why_it_matters: string;
  technical: string;
}

export async function fetchGlossary(q?: string): Promise<GlossaryTerm[]> {
  const query = q ? `?q=${encodeURIComponent(q)}` : '';
  const res = await request<any>(`/glossary${query}`);
  return Array.isArray(res) ? res : res.items || [];
}

export async function fetchGlossaryTerm(termId: string): Promise<GlossaryTerm> {
  return request<GlossaryTerm>(`/glossary/${encodeURIComponent(termId)}`);
}

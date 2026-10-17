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
  headers.set('Accept', 'application/json');

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

  return response.json();
}

export async function fetchCapabilities(): Promise<CapabilityEntry[]> {
  return request<CapabilityEntry[]>('/capabilities');
}

export async function fetchHealth(): Promise<{ status: string; version: string }> {
  return request<{ status: string; version: string }>('/health');
}

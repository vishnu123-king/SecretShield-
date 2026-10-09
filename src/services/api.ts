import {
  Repository,
  ScanRecord,
  Finding,
  AuditLog,
  DashboardMetrics,
  FindingStatus,
  UrlValidationResult,
  PolicyConfig
} from '../types';

let authToken: string | null = null;

export const setAuthToken = (token: string | null) => {
  authToken = token;
};

const getHeaders = () => {
  const headers: Record<string, string> = {
    'Content-Type': 'application/json',
  };
  if (authToken) {
    headers['Authorization'] = `Bearer ${authToken}`;
  }
  return headers;
};

export const api = {
  // Auth
  async login(credentials: any) {
    const res = await fetch('/api/auth/login', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(credentials)
    });
    if (!res.ok) {
      const err = await res.json();
      throw new Error(err.error || 'Login failed');
    }
    const data = await res.json();
    setAuthToken(data.token);
    localStorage.setItem('ss_token', data.token);
    return data;
  },

  async register(data: any) {
    const res = await fetch('/api/auth/register', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(data)
    });
    if (!res.ok) {
      const err = await res.json();
      throw new Error(err.error || 'Registration failed');
    }
    const dataRes = await res.json();
    setAuthToken(dataRes.token);
    localStorage.setItem('ss_token', dataRes.token);
    return dataRes;
  },

  async logout() {
    setAuthToken(null);
    localStorage.removeItem('ss_token');
  },

  async getMe() {
    const res = await fetch('/api/auth/me', { headers: getHeaders() });
    if (!res.ok) throw new Error('Failed to fetch user profile');
    return res.json();
  },

  // Health
  async getHealth() {
    const res = await fetch('/api/health');
    return res.json();
  },

  // Overview
  async getOverview(): Promise<{
    metrics: DashboardMetrics;
    secrets_by_type: Array<{ name: string; count: number }>;
    repositories: Repository[];
    recent_scans: ScanRecord[];
    recent_findings: Finding[];
    security_policy: PolicyConfig;
  }> {
    const res = await fetch('/api/overview', { headers: getHeaders() });
    if (!res.ok) throw new Error('Failed to fetch overview');
    return res.json();
  },

  // Repositories
  async validateUrl(url: string): Promise<UrlValidationResult> {
    const res = await fetch('/api/repositories/validate-url', {
      method: 'POST',
      headers: getHeaders(),
      body: JSON.stringify({ url })
    });
    return res.json();
  },

  async previewRepository(url: string): Promise<any> {
    const res = await fetch('/api/repositories/preview', {
      method: 'POST',
      headers: getHeaders(),
      body: JSON.stringify({ url })
    });
    if (!res.ok) throw new Error('Failed to preview repository');
    return res.json();
  },

  // Scans
  async triggerUrlScan(data: {
    url: string;
    scan_scope?: 'current' | 'history' | 'full';
    branch?: string;
    token?: string;
    depth?: number;
  }): Promise<{ scan: ScanRecord; repository: Repository; findings?: Finding[]; summary?: any }> {
    const res = await fetch('/api/scans/url', {
      method: 'POST',
      headers: getHeaders(),
      body: JSON.stringify(data)
    });
    if (!res.ok) {
      const err = await res.json().catch(() => ({}));
      throw new Error(err.error || 'Scan failed to complete');
    }
    return res.json();
  },

  // Findings
  async getFindings(): Promise<Finding[]> {
    const res = await fetch('/api/findings', { headers: getHeaders() });
    return res.json();
  },

  async updateFindingStatus(
    id: number,
    payload: string | { status: string; resolutionNote?: string; approverName?: string; expiryDate?: string },
    legacyNote?: string
  ): Promise<{ success: boolean; finding: Finding }> {
    const body = typeof payload === 'string'
      ? { status: payload, resolutionNote: legacyNote }
      : payload;

    const res = await fetch(`/api/findings/${id}/status`, {
      method: 'POST',
      headers: getHeaders(),
      body: JSON.stringify(body)
    });
    if (!res.ok) {
      const err = await res.json().catch(() => ({}));
      throw new Error(err.error || 'Failed to update finding status');
    }
    return res.json();
  },

  async getRemediationScript(id: number): Promise<{
    finding_id: string;
    purge_script: string;
    env_template: string;
    remediation_steps: string[];
  }> {
    const res = await fetch(`/api/findings/${id}/remediation-script`, {
      method: 'POST',
      headers: getHeaders()
    });
    if (!res.ok) throw new Error('Failed to generate remediation script');
    return res.json();
  },

  async testRule(text: string): Promise<{ tested_text: string; matched: boolean; matches: any[] }> {
    const res = await fetch('/api/rules/test', {
      method: 'POST',
      headers: getHeaders(),
      body: JSON.stringify({ text })
    });
    if (!res.ok) throw new Error('Rule test failed');
    return res.json();
  },

  async testRuleSandbox(data: {
    pattern: string;
    text: string;
    keywords?: string[];
    min_entropy?: number;
  }): Promise<{
    matched: boolean;
    regex_matched: boolean;
    matched_text: string | null;
    entropy: number;
    meets_entropy: boolean;
    keyword_matched: boolean;
    execution_ms: number;
    simulated_confidence: number;
    error?: string;
  }> {
    const res = await fetch('/api/rules/test-sandbox', {
      method: 'POST',
      headers: getHeaders(),
      body: JSON.stringify(data)
    });
    if (!res.ok) {
      const err = await res.json().catch(() => ({}));
      throw new Error(err.error || 'Rule sandbox execution failed');
    }
    return res.json();
  },

  async getRepositoryDrift(repoId: number): Promise<any> {
    const res = await fetch(`/api/repositories/${repoId}/drift`, { headers: getHeaders() });
    if (!res.ok) throw new Error('Failed to fetch drift analysis');
    return res.json();
  },

  async getExecutiveReport(): Promise<any> {
    const res = await fetch('/api/reports/executive', { headers: getHeaders() });
    if (!res.ok) throw new Error('Failed to fetch executive report');
    return res.json();
  },

  // Exposure
  async getExposure(fingerprint: string): Promise<any> {
    const res = await fetch(`/api/exposure/${encodeURIComponent(fingerprint)}`, { headers: getHeaders() });
    if (!res.ok) throw new Error('Failed to fetch exposure record');
    return res.json();
  },

  // Policies
  async getPolicies(): Promise<PolicyConfig> {
    const res = await fetch('/api/policies', { headers: getHeaders() });
    return res.json();
  },

  async updatePolicies(data: Partial<PolicyConfig>): Promise<{ success: boolean; policy: PolicyConfig }> {
    const res = await fetch('/api/policies', {
      method: 'POST',
      headers: getHeaders(),
      body: JSON.stringify(data)
    });
    return res.json();
  },

  // Audit Logs
  async getAuditLogs(): Promise<AuditLog[]> {
    const res = await fetch('/api/audit-logs', { headers: getHeaders() });
    return res.json();
  }
};

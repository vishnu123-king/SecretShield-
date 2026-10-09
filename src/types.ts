export type Severity = 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'INFO';

export type FindingStatus =
  | 'Open'
  | 'Investigating'
  | 'Confirmed'
  | 'False Positive'
  | 'Resolved'
  | 'Accepted Risk';

export interface GitProviderInfo {
  id: string;
  name: string;
  badge_color: string;
}

export interface UrlValidationResult {
  is_valid: boolean;
  is_local?: boolean;
  original_url?: string;
  normalized_url?: string;
  clone_url?: string;
  host?: string;
  owner?: string;
  repo_name?: string;
  protocol?: string;
  provider_info?: GitProviderInfo;
  error?: string;
}

export interface RepoOwnerDetails {
  login: string;
  name?: string | null;
  avatar_url?: string;
  bio?: string | null;
  company?: string | null;
  location?: string | null;
  profile_url: string;
  public_repos?: number;
  type?: string;
}

export interface LinuxSandboxTelemetry {
  sandbox_id: string;
  sandbox_path: string;
  platform: string;
  isolation_mode?: string;
  file_count?: number;
  size_kb?: number;
  security_policies?: string[];
  status: string;
}

export interface RepoIntelligence {
  name: string;
  full_name: string;
  description?: string | null;
  stars: number;
  forks: number;
  watchers: number;
  open_issues: number;
  language?: string | null;
  license?: string | null;
  default_branch: string;
  topics: string[];
  visibility: string;
  created_at?: string | null;
  updated_at?: string | null;
  pushed_at?: string | null;
  size_kb: number;
  size_mb: number;
  approximate_files_count?: number;
  clone_url: string;
  normalized_url: string;
  web_url?: string;
  owner: RepoOwnerDetails;
  provider: string;
  provider_id: string;
  sandbox_info: {
    engine: string;
    isolation: string;
    sandbox_path: string;
    security_policies: string[];
  };
}

export interface Repository {
  id: number;
  name: string;
  url?: string;
  path: string;
  source: string;
  provider_name?: string;
  provider_badge?: string;
  default_branch: string;
  last_scanned_at: string | null;
  risk_index: number;
  status: string;
  total_findings: number;
}

export interface ScanRecord {
  id: number;
  scan_id: string;
  repository_id: number;
  repository_name: string;
  repository_url?: string;
  provider?: string;
  scan_mode: string;
  status: 'running' | 'completed' | 'failed';
  current_stage?: string;
  duration_seconds: number;
  total_findings: number;
  critical_count: number;
  high_count: number;
  medium_count: number;
  low_count: number;
  currently_exposed_count: number;
  historical_only_count: number;
  risk_index: number;
  created_at: string;
}

export interface Finding {
  id: number;
  finding_id: string;
  scan_id: number;
  repository_id: number;
  repository_name: string;
  fingerprint: string;
  title: string;
  secret_type: string;
  rule_id: string;
  rule_name: string;
  severity: Severity;
  confidence: number;
  score: number;
  masked_secret: string;
  primary_file: string;
  primary_line: number;
  status: FindingStatus;
  is_currently_present: boolean;
  first_seen: string | null;
  last_seen: string | null;
  total_occurrences: number;
  remediation: string;
  risk_reasons: any;
  context: any;
  files: string[];
  commits: string[];
  branches: string[];
  occurrences: any[];
  ai_explanation?: string;
  evidence_points?: string[];
  operational_risk?: string;
  blast_radius?: any;
  exposure_events?: any[];
  history_logs?: any[];
}

export interface PolicyConfig {
  critical: 'block' | 'warn' | 'inform';
  high: 'block' | 'warn' | 'inform';
  medium: 'block' | 'warn' | 'inform';
  low: 'block' | 'warn' | 'inform';
  precommit_enforced: boolean;
  diff_scan_enforced: boolean;
  pr_checks_enforced: boolean;
  ci_gate_enforced: boolean;
  max_allowed_risk_score: number;
}

export interface DashboardMetrics {
  total_repositories: number;
  total_scans: number;
  total_findings: number;
  critical_count: number;
  high_count: number;
  medium_count: number;
  low_count: number;
  open_findings: number;
  resolved_findings: number;
  currently_exposed: number;
  historical_only: number;
  overall_risk_index: number;
}

export interface AuditLog {
  id: number;
  user_email: string;
  action: string;
  target_type: string;
  target_id: string;
  details: string;
  created_at: string;
}

export interface DependencyVulnerability {
  package: string;
  installed_version: string;
  cve_id: string;
  severity: Severity;
  cvss: number;
  title: string;
  remediation: string;
  advisory: string;
  manifest_file: string;
}

export interface ScaAnalysisResult {
  manifest_files: string[];
  total_dependencies: number;
  vulnerabilities_count: number;
  severity_counts: {
    CRITICAL: number;
    HIGH: number;
    MEDIUM: number;
    LOW: number;
  };
  vulnerabilities: DependencyVulnerability[];
  dependencies: Array<{ ecosystem: string; name: string; version: string; file: string }>;
}

export interface ContributorSecurityPassport {
  name: string;
  email: string;
  commits: number;
  secrets_flagged: number;
  security_score: number;
}

export interface SecurityDriftReport {
  repository: Repository;
  drift_status: 'IMPROVING' | 'DEGRADING' | 'STABLE';
  drift_delta: number;
  scan_history: Array<{
    scan_id: string;
    date: string;
    risk_index: number;
    total_findings: number;
    critical_count: number;
  }>;
  monitoring_mode: string;
  sla_status: 'HEALTHY' | 'NEEDS_ATTENTION';
}

export interface ExecutiveReport {
  executive_summary: {
    total_findings: number;
    resolved_findings: number;
    open_critical: number;
    open_high: number;
    mttr_hours: number;
    mttr_days: number;
    exposure_reduction_percent: number;
    sla_compliance_rate: number;
    organization_grade: string;
    reporting_period: string;
  };
  repositories_analyzed: number;
  scans_executed: number;
}

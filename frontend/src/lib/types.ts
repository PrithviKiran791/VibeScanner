// Mirrors backend/vibeguard/api/schemas.py

export type Severity = "CRITICAL" | "HIGH" | "MEDIUM" | "LOW" | "INFO";
export type ScanStatus =
  | "QUEUED"
  | "CLONING"
  | "ANALYZING_STATIC"
  | "ANALYZING_LLM"
  | "COMPLETED"
  | "FAILED";
export type ScanSource = "GITHUB" | "ZIP" | "LOCAL";
export type FindingStatus = "OPEN" | "PATCH_APPLIED" | "DISMISSED_FALSE_POSITIVE" | "RESOLVED";
export type FindingSource = "STATIC" | "LLM" | "MERGED";
/** SECURITY feeds the Hardening Index; QUALITY feeds the Code Quality Score */
export type FindingDomain = "SECURITY" | "QUALITY";
export type QualityGrade = "A" | "B" | "C" | "D" | "F";

export interface QualityBreakdown {
  modularity: number;
  type_safety: number;
  error_hygiene: number;
  cleanliness: number;
  architecture: number;
  total_loc: number;
  files_scanned: number;
  code_smells_count: number;
}

export interface Counts {
  critical: number;
  high: number;
  medium: number;
  low: number;
  /** Open findings only; patched ones are counted separately */
  total: number;
  /** Fixed through a VibeGuard PR */
  patched: number;
}

export interface Progress {
  step: string;
  percentage: number;
}

export interface Scan {
  id: string;
  status: ScanStatus;
  source_type: ScanSource;
  target: string;
  repository: string;
  commit_hash: string | null;
  hardening_score: number | null;
  /** Null when not measured (older scans, or no JS/TS/Python in the repo) */
  quality_score: number | null;
  quality_grade: QualityGrade | null;
  quality_breakdown: QualityBreakdown | null;
  counts: Counts;
  files_scanned: number | null;
  llm_used: boolean;
  warnings: string[];
  duration_ms: number | null;
  error_message: string | null;
  progress: Progress | null;
  created_by: string | null;
  created_at: string;
  completed_at: string | null;
}

export interface Remediation {
  kind: string;
  file_path: string;
  line: number;
  col_start: number;
  col_end: number;
  replacement: string;
  env_var_name: string | null;
  expected_text: string | null;
  verify_rule: string | null;
}

export interface PullRequest {
  pr_number: number;
  pr_url: string;
  branch_name: string;
  opened_by: string | null;
}

export interface Finding {
  id: string;
  scan_id: string;
  rule_id: string;
  severity: Severity;
  category: string;
  title: string;
  cwe_id: string | null;
  file_path: string;
  line_start: number;
  line_end: number;
  snippet_original: string;
  snippet_fixed: string | null;
  unified_diff: string | null;
  explanation: string;
  source: FindingSource;
  domain: FindingDomain;
  status: FindingStatus;
  remediation: Remediation | null;
  pull_request: PullRequest | null;
}

export interface ScoreUpdate {
  scan_id: string;
  hardening_score: number | null;
  counts: Counts;
}

export interface FindingUpdateResult {
  finding: Finding;
  scan: ScoreUpdate;
}

export interface OpenPullRequestResult extends FindingUpdateResult {
  created: boolean;
}

export interface ScanOptions {
  llm: boolean;
  registry: boolean;
}

export const TERMINAL: ReadonlySet<ScanStatus> = new Set(["COMPLETED", "FAILED"]);

export interface Me {
  uid: string;
  /** GitHub accounts without a public email have none */
  email: string | null;
  name: string | null;
  picture: string | null;
}

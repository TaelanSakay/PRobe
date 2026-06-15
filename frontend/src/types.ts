export interface Finding {
  file_path: string;
  line_number: number;
  rule_id: string;
  severity: 'high' | 'medium' | 'low';
}

export interface Scan {
  id: number;
  repo_name?: string;
  owner?: string;
  repo_id?: number;
  pr_number: number;
  risk_score: number | null;
  status: string;
  created_at: string;
  finding_count: number;
  findings: Finding[];
}

export interface RepoMemory {
  id: number;
  rule_id: string;
  file_pattern: string;
  outcome: string;
  created_at: string;
}

export type Severity = 'critical' | 'high' | 'medium' | 'low' | 'info'

export interface Scan {
  id: string
  target: string
  started_at: string
  completed_at: string | null
  duration_seconds: number | null
  ai_analysis: string | null
  ai_attack_paths: string[] | null
  error_count: number
  created_at: string
}

export interface Finding {
  id: string
  scan_id: string
  agent: string
  type: string
  title: string
  description: string
  severity: Severity
  data: Record<string, unknown> | null
  mitre_techniques: string[] | null
  raw: string | null
  found_at: string
  created_at: string
}

export interface ScanWithCounts extends Scan {
  findings_count: number
  critical_count: number
  high_count: number
  medium_count: number
  low_count: number
  info_count: number
}

export interface DashboardStats {
  total_scans: number
  total_findings: number
  critical_count: number
  high_count: number
}

// Supabase Database types
export interface Database {
  public: {
    Tables: {
      scans: {
        Row: Scan
        Insert: Omit<Scan, 'id' | 'created_at'>
        Update: Partial<Omit<Scan, 'id'>>
      }
      findings: {
        Row: Finding
        Insert: Omit<Finding, 'id' | 'created_at'>
        Update: Partial<Omit<Finding, 'id'>>
      }
    }
    Views: Record<string, never>
    Functions: Record<string, never>
    Enums: {
      severity: Severity
    }
  }
}

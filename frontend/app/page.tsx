import Link from 'next/link'
import { supabase } from '@/lib/supabase'
import type { Scan, Severity } from '@/lib/types'
import { StatsCard } from '@/components/StatsCard'
import { SeverityBadge } from '@/components/SeverityBadge'
import { NewScanModal } from '@/components/NewScanModal'

interface FindingCountRow {
  scan_id: string
  severity: Severity
  count: string
}

interface ScanRow extends Scan {
  critical_count: number
  high_count: number
  medium_count: number
  low_count: number
  info_count: number
  findings_count: number
}

async function getScansWithCounts(): Promise<ScanRow[]> {
  // Fetch all scans
  const { data: scans, error: scansError } = await supabase
    .from('scans')
    .select('*')
    .order('created_at', { ascending: false })

  if (scansError || !scans) return []

  if (scans.length === 0) return []

  // Fetch finding counts grouped by scan_id and severity
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  const { data: countsData, error: countsError } = await (supabase as any)
    .from('findings')
    .select('scan_id, severity')
  const counts = countsData as Array<{ scan_id: string; severity: string }> | null

  if (countsError || !counts) {
    return scans.map((s) => ({
      ...(s as unknown as Scan),
      critical_count: 0,
      high_count: 0,
      medium_count: 0,
      low_count: 0,
      info_count: 0,
      findings_count: 0,
    }))
  }

  // Aggregate counts per scan
  const countMap = new Map<string, Record<Severity, number>>()
  for (const row of counts) {
    if (!countMap.has(row.scan_id)) {
      countMap.set(row.scan_id, { critical: 0, high: 0, medium: 0, low: 0, info: 0 })
    }
    const entry = countMap.get(row.scan_id)!
    const sev = row.severity as Severity
    if (sev in entry) {
      entry[sev]++
    }
  }

  return scans.map((s) => {
    const c = countMap.get(s.id) ?? { critical: 0, high: 0, medium: 0, low: 0, info: 0 }
    const total = c.critical + c.high + c.medium + c.low + c.info
    return {
      ...(s as unknown as Scan),
      critical_count: c.critical,
      high_count: c.high,
      medium_count: c.medium,
      low_count: c.low,
      info_count: c.info,
      findings_count: total,
    }
  })
}

function formatDuration(seconds: number | null): string {
  if (seconds === null) return '—'
  if (seconds < 60) return `${Math.round(seconds)}s`
  const m = Math.floor(seconds / 60)
  const s = Math.round(seconds % 60)
  return `${m}m ${s}s`
}

function formatDate(dateStr: string): string {
  return new Date(dateStr).toLocaleString('en-US', {
    month: 'short',
    day: 'numeric',
    year: 'numeric',
    hour: '2-digit',
    minute: '2-digit',
  })
}

export default async function DashboardPage() {
  const scans = await getScansWithCounts()

  const totalFindings = scans.reduce((a, s) => a + s.findings_count, 0)
  const totalCritical = scans.reduce((a, s) => a + s.critical_count, 0)
  const totalHigh = scans.reduce((a, s) => a + s.high_count, 0)

  return (
    <div className="space-y-8">
      {/* Page header */}
      <div className="flex items-start justify-between gap-4">
        <div>
          <h1 className="text-2xl font-bold font-mono text-[#e6edf3]">
            Scan Dashboard
          </h1>
          <p className="text-[#8b949e] text-sm mt-1">
            Recon results from authorized targets — HTB, THM, RFC1918
          </p>
        </div>
        <NewScanModal />
      </div>

      {/* Stats row */}
      <div className="grid grid-cols-2 sm:grid-cols-4 gap-4">
        <StatsCard label="Total Scans" value={scans.length} />
        <StatsCard label="Total Findings" value={totalFindings} />
        <StatsCard
          label="Critical"
          value={totalCritical}
          accent="#ff4444"
          sublabel="immediate action"
        />
        <StatsCard
          label="High"
          value={totalHigh}
          accent="#ff8800"
          sublabel="needs remediation"
        />
      </div>

      {/* Scans table */}
      <div className="bg-[#161b22] border border-[#30363d] rounded-lg overflow-hidden">
        <div className="px-4 py-3 border-b border-[#30363d] flex items-center justify-between">
          <h2 className="text-sm font-mono font-semibold text-[#e6edf3]">Scan History</h2>
          <span className="text-xs text-[#8b949e] font-mono">{scans.length} scan{scans.length !== 1 ? 's' : ''}</span>
        </div>

        {scans.length === 0 ? (
          <div className="px-6 py-16 text-center">
            <div className="inline-flex items-center justify-center w-12 h-12 rounded-full bg-[#30363d]/50 mb-4">
              <svg width="24" height="24" viewBox="0 0 24 24" fill="none" className="text-[#8b949e]">
                <circle cx="11" cy="11" r="8" stroke="currentColor" strokeWidth="2" />
                <path d="M21 21l-4.35-4.35" stroke="currentColor" strokeWidth="2" strokeLinecap="round" />
              </svg>
            </div>
            <p className="text-[#8b949e] text-sm mb-2">No scans yet.</p>
            <p className="text-[#30363d] font-mono text-xs">
              Run: <span className="text-[#79c0ff]">reconai scan 10.10.11.21</span>
            </p>
          </div>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-sm">
              <thead>
                <tr className="border-b border-[#30363d]">
                  <th className="text-left py-3 px-4 text-xs font-mono uppercase tracking-wider text-[#8b949e]">
                    Target
                  </th>
                  <th className="text-left py-3 px-4 text-xs font-mono uppercase tracking-wider text-[#8b949e]">
                    Findings
                  </th>
                  <th className="text-left py-3 px-4 text-xs font-mono uppercase tracking-wider text-[#8b949e]">
                    Severity breakdown
                  </th>
                  <th className="text-left py-3 px-4 text-xs font-mono uppercase tracking-wider text-[#8b949e]">
                    Duration
                  </th>
                  <th className="text-left py-3 px-4 text-xs font-mono uppercase tracking-wider text-[#8b949e]">
                    Date
                  </th>
                  <th className="py-3 px-4" />
                </tr>
              </thead>
              <tbody>
                {scans.map((scan) => (
                  <tr
                    key={scan.id}
                    className="border-b border-[#30363d] hover:bg-[#1f2937]/40 transition-colors"
                  >
                    <td className="py-3 px-4">
                      <div className="flex flex-col gap-0.5">
                        <span className="font-mono text-[#e6edf3] font-medium text-sm">
                          {scan.target}
                        </span>
                        {scan.error_count > 0 && (
                          <span className="text-[10px] font-mono text-[#ff8800]">
                            {scan.error_count} error{scan.error_count !== 1 ? 's' : ''}
                          </span>
                        )}
                      </div>
                    </td>
                    <td className="py-3 px-4">
                      <span className="text-[#e6edf3] font-mono font-semibold">
                        {scan.findings_count}
                      </span>
                    </td>
                    <td className="py-3 px-4">
                      <div className="flex items-center gap-1.5 flex-wrap">
                        {scan.critical_count > 0 && (
                          <SeverityBadge severity="critical" size="sm" />
                        )}
                        {scan.high_count > 0 && (
                          <SeverityBadge severity="high" size="sm" />
                        )}
                        {scan.medium_count > 0 && (
                          <SeverityBadge severity="medium" size="sm" />
                        )}
                        {scan.low_count > 0 && (
                          <SeverityBadge severity="low" size="sm" />
                        )}
                        {scan.info_count > 0 && (
                          <SeverityBadge severity="info" size="sm" />
                        )}
                        {scan.findings_count === 0 && (
                          <span className="text-[#30363d] text-xs font-mono">none</span>
                        )}
                      </div>
                    </td>
                    <td className="py-3 px-4">
                      <span className="text-[#8b949e] font-mono text-sm">
                        {formatDuration(scan.duration_seconds)}
                      </span>
                    </td>
                    <td className="py-3 px-4">
                      <span className="text-[#8b949e] text-sm whitespace-nowrap">
                        {formatDate(scan.created_at)}
                      </span>
                    </td>
                    <td className="py-3 px-4">
                      <Link
                        href={`/scans/${scan.id}`}
                        className="inline-flex items-center gap-1 px-3 py-1.5 rounded text-xs font-mono bg-[#30363d]/50 hover:bg-[#30363d] text-[#e6edf3] transition-colors border border-[#30363d] hover:border-[#484f58]"
                      >
                        View
                        <span className="text-[#8b949e]">→</span>
                      </Link>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>
    </div>
  )
}


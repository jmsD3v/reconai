import Link from 'next/link'
import { notFound } from 'next/navigation'
import { supabase } from '@/lib/supabase'
import type { Finding, Scan } from '@/lib/types'
import { SeverityBadge } from '@/components/SeverityBadge'
import { StatsCard } from '@/components/StatsCard'
import { FilteredFindings } from './FilteredFindings'

async function getScan(id: string): Promise<Scan | null> {
  const { data, error } = await supabase
    .from('scans')
    .select('*')
    .eq('id', id)
    .single()

  if (error || !data) return null
  return data
}

async function getFindings(scanId: string): Promise<Finding[]> {
  const { data, error } = await supabase
    .from('findings')
    .select('*')
    .eq('scan_id', scanId)
    .order('found_at', { ascending: true })

  if (error || !data) return []
  return data
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

interface PageProps {
  params: { id: string }
}

export default async function ScanDetailPage({ params }: PageProps) {
  const [scan, findings] = await Promise.all([
    getScan(params.id),
    getFindings(params.id),
  ])

  if (!scan) notFound()

  const critical = findings.filter((f) => f.severity === 'critical').length
  const high = findings.filter((f) => f.severity === 'high').length
  const medium = findings.filter((f) => f.severity === 'medium').length
  const low = findings.filter((f) => f.severity === 'low').length
  const info = findings.filter((f) => f.severity === 'info').length

  return (
    <div className="space-y-8">
      {/* Back button */}
      <div>
        <Link
          href="/"
          className="inline-flex items-center gap-1.5 text-sm font-mono text-[#8b949e] hover:text-[#e6edf3] transition-colors"
        >
          <span>←</span>
          Back to dashboard
        </Link>
      </div>

      {/* Scan header */}
      <div className="bg-[#161b22] border border-[#30363d] rounded-lg p-6">
        <div className="flex flex-col sm:flex-row sm:items-start sm:justify-between gap-4">
          <div>
            <div className="flex items-center gap-3 mb-2">
              <h1 className="text-xl font-bold font-mono text-[#e6edf3]">
                {scan.target}
              </h1>
              {scan.error_count > 0 && (
                <span className="px-2 py-0.5 rounded text-xs font-mono bg-[#ff8800]/10 border border-[#ff8800]/30 text-[#ff8800]">
                  {scan.error_count} error{scan.error_count !== 1 ? 's' : ''}
                </span>
              )}
            </div>
            <div className="flex flex-wrap gap-4 text-sm text-[#8b949e] font-mono">
              <span>
                <span className="text-[#30363d]">Started:</span>{' '}
                <span className="text-[#e6edf3]">{formatDate(scan.started_at)}</span>
              </span>
              {scan.completed_at && (
                <span>
                  <span className="text-[#30363d]">Completed:</span>{' '}
                  <span className="text-[#e6edf3]">{formatDate(scan.completed_at)}</span>
                </span>
              )}
              <span>
                <span className="text-[#30363d]">Duration:</span>{' '}
                <span className="text-[#e6edf3]">{formatDuration(scan.duration_seconds)}</span>
              </span>
            </div>
          </div>
          <div className="text-xs font-mono text-[#8b949e] break-all max-w-xs">
            <span className="text-[#30363d]">ID:</span> {scan.id}
          </div>
        </div>
      </div>

      {/* Stats row */}
      <div className="grid grid-cols-3 sm:grid-cols-6 gap-3">
        <StatsCard label="Total" value={findings.length} />
        <StatsCard label="Critical" value={critical} accent="#ff4444" />
        <StatsCard label="High" value={high} accent="#ff8800" />
        <StatsCard label="Medium" value={medium} accent="#ffcc00" />
        <StatsCard label="Low" value={low} accent="#44aaff" />
        <StatsCard label="Info" value={info} accent="#888888" />
      </div>

      {/* AI Analysis */}
      {scan.ai_analysis && (
        <div className="bg-[#161b22] border border-[#8b5cf6]/40 rounded-lg overflow-hidden">
          <div className="px-4 py-3 border-b border-[#8b5cf6]/20 flex items-center gap-2 bg-[#8b5cf6]/5">
            <svg width="16" height="16" viewBox="0 0 16 16" fill="none" className="text-[#8b5cf6] flex-shrink-0">
              <path d="M8 1a7 7 0 100 14A7 7 0 008 1zM7 11V7h2v4H7zm0-6V3h2v2H7z" fill="currentColor" />
            </svg>
            <span className="text-sm font-mono font-semibold text-[#8b5cf6]">AI Analysis</span>
            <span className="ml-auto text-xs text-[#8b949e] font-mono">claude-sonnet</span>
          </div>
          <div className="px-5 py-4">
            <p className="text-sm text-[#e6edf3] leading-relaxed whitespace-pre-wrap">
              {scan.ai_analysis}
            </p>
          </div>
        </div>
      )}

      {/* Attack Paths */}
      {scan.ai_attack_paths && scan.ai_attack_paths.length > 0 && (
        <div className="bg-[#161b22] border border-[#ff4444]/30 rounded-lg overflow-hidden">
          <div className="px-4 py-3 border-b border-[#ff4444]/20 flex items-center gap-2 bg-[#ff4444]/5">
            <svg width="16" height="16" viewBox="0 0 16 16" fill="none" className="text-[#ff4444] flex-shrink-0">
              <path d="M8 2L2 12h12L8 2z" stroke="currentColor" strokeWidth="1.5" fill="none" />
              <path d="M8 6v4M8 11.5v.5" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" />
            </svg>
            <span className="text-sm font-mono font-semibold text-[#ff4444]">
              Attack Paths
            </span>
            <span className="ml-auto text-xs text-[#8b949e] font-mono">
              {scan.ai_attack_paths.length} path{scan.ai_attack_paths.length !== 1 ? 's' : ''}
            </span>
          </div>
          <ul className="px-5 py-4 space-y-2">
            {scan.ai_attack_paths.map((path, i) => (
              <li key={i} className="flex items-start gap-3 text-sm text-[#e6edf3]">
                <span className="flex-shrink-0 flex items-center justify-center w-5 h-5 rounded-full bg-[#ff4444]/15 text-[#ff4444] text-xs font-mono font-bold mt-0.5">
                  {i + 1}
                </span>
                <span className="leading-relaxed">{path}</span>
              </li>
            ))}
          </ul>
        </div>
      )}

      {/* Findings */}
      <div className="space-y-4">
        <div className="flex items-center justify-between">
          <h2 className="text-base font-mono font-semibold text-[#e6edf3]">Findings</h2>
          <span className="text-xs text-[#8b949e] font-mono">{findings.length} total</span>
        </div>

        <FilteredFindings findings={findings} />
      </div>
    </div>
  )
}

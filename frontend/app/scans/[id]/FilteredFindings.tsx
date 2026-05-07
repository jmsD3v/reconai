'use client'

import { useState } from 'react'
import type { Finding, Severity } from '@/lib/types'
import { FindingRow } from '@/components/FindingRow'

const SEVERITIES: { key: Severity | 'all'; label: string; color: string }[] = [
  { key: 'all', label: 'All', color: '#e6edf3' },
  { key: 'critical', label: 'Critical', color: '#ff4444' },
  { key: 'high', label: 'High', color: '#ff8800' },
  { key: 'medium', label: 'Medium', color: '#ffcc00' },
  { key: 'low', label: 'Low', color: '#44aaff' },
  { key: 'info', label: 'Info', color: '#888888' },
]

interface FilteredFindingsProps {
  findings: Finding[]
}

export function FilteredFindings({ findings }: FilteredFindingsProps) {
  const [active, setActive] = useState<Severity | 'all'>('all')

  const counts = findings.reduce<Record<string, number>>(
    (acc, f) => {
      acc[f.severity] = (acc[f.severity] ?? 0) + 1
      return acc
    },
    {}
  )

  const filtered = active === 'all' ? findings : findings.filter((f) => f.severity === active)

  return (
    <div className="space-y-4">
      {/* Filter tabs */}
      <div className="flex items-center gap-1 flex-wrap">
        {SEVERITIES.map((sev) => {
          const count = sev.key === 'all' ? findings.length : (counts[sev.key] ?? 0)
          const isActive = active === sev.key
          return (
            <button
              key={sev.key}
              onClick={() => setActive(sev.key)}
              className={`
                inline-flex items-center gap-1.5 px-3 py-1.5 rounded text-xs font-mono transition-colors
                ${isActive
                  ? 'text-[#e6edf3] bg-[#30363d] border border-[#484f58]'
                  : 'text-[#8b949e] bg-transparent border border-[#30363d] hover:border-[#484f58] hover:text-[#e6edf3]'
                }
              `}
            >
              {sev.key !== 'all' && (
                <span
                  className="w-2 h-2 rounded-full flex-shrink-0"
                  style={{ backgroundColor: sev.color }}
                />
              )}
              {sev.label}
              <span
                className="px-1 rounded-sm text-[10px]"
                style={isActive ? { color: sev.color } : { color: '#8b949e' }}
              >
                {count}
              </span>
            </button>
          )
        })}
      </div>

      {/* Table */}
      {filtered.length === 0 ? (
        <div className="bg-[#161b22] border border-[#30363d] rounded-lg px-6 py-12 text-center">
          <p className="text-[#8b949e] text-sm font-mono">
            No {active === 'all' ? '' : active} findings found.
          </p>
        </div>
      ) : (
        <div className="bg-[#161b22] border border-[#30363d] rounded-lg overflow-hidden">
          <table className="w-full text-sm">
            <thead>
              <tr className="border-b border-[#30363d]">
                <th className="text-left py-3 px-4 text-xs font-mono uppercase tracking-wider text-[#8b949e]">
                  Severity
                </th>
                <th className="text-left py-3 px-4 text-xs font-mono uppercase tracking-wider text-[#8b949e]">
                  Agent
                </th>
                <th className="text-left py-3 px-4 text-xs font-mono uppercase tracking-wider text-[#8b949e]">
                  Type
                </th>
                <th className="text-left py-3 px-4 text-xs font-mono uppercase tracking-wider text-[#8b949e]">
                  Title
                </th>
                <th className="text-left py-3 px-4 text-xs font-mono uppercase tracking-wider text-[#8b949e]">
                  MITRE
                </th>
                <th className="py-3 px-4 w-8" />
              </tr>
            </thead>
            <tbody>
              {filtered.map((finding) => (
                <FindingRow key={finding.id} finding={finding} />
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  )
}

'use client'

import { useState } from 'react'
import type { Finding } from '@/lib/types'
import { SeverityBadge } from './SeverityBadge'

interface FindingRowProps {
  finding: Finding
}

export function FindingRow({ finding }: FindingRowProps) {
  const [expanded, setExpanded] = useState(false)

  return (
    <>
      <tr
        className="border-b border-[#30363d] hover:bg-[#161b22]/60 cursor-pointer transition-colors"
        onClick={() => setExpanded((v) => !v)}
      >
        <td className="py-3 px-4 whitespace-nowrap">
          <SeverityBadge severity={finding.severity} />
        </td>
        <td className="py-3 px-4 text-[#8b949e] font-mono text-sm whitespace-nowrap">
          {finding.agent}
        </td>
        <td className="py-3 px-4 text-[#8b949e] font-mono text-sm whitespace-nowrap">
          {finding.type}
        </td>
        <td className="py-3 px-4 text-[#e6edf3] text-sm max-w-xs truncate">
          {finding.title}
        </td>
        <td className="py-3 px-4">
          {finding.mitre_techniques && finding.mitre_techniques.length > 0 ? (
            <div className="flex flex-wrap gap-1">
              {finding.mitre_techniques.map((t) => (
                <span
                  key={t}
                  className="inline-block px-1.5 py-0.5 rounded text-[10px] font-mono bg-[#8b5cf6]/10 border border-[#8b5cf6]/30 text-[#8b5cf6] whitespace-nowrap"
                >
                  {t}
                </span>
              ))}
            </div>
          ) : (
            <span className="text-[#30363d] text-sm">—</span>
          )}
        </td>
        <td className="py-3 px-4 text-[#30363d] text-sm">
          <span className={`transition-transform inline-block ${expanded ? 'rotate-90' : ''}`}>▶</span>
        </td>
      </tr>

      {expanded && (
        <tr className="border-b border-[#30363d] bg-[#0d1117]">
          <td colSpan={6} className="px-6 py-4">
            <div className="space-y-4">
              {/* Description */}
              {finding.description && (
                <div>
                  <p className="text-xs font-mono uppercase tracking-wider text-[#8b949e] mb-1">Description</p>
                  <p className="text-sm text-[#e6edf3] leading-relaxed">{finding.description}</p>
                </div>
              )}

              {/* Data JSON */}
              {finding.data && Object.keys(finding.data).length > 0 && (
                <div>
                  <p className="text-xs font-mono uppercase tracking-wider text-[#8b949e] mb-1">Data</p>
                  <pre className="text-xs font-mono text-[#79c0ff] bg-[#161b22] border border-[#30363d] rounded p-3 overflow-x-auto leading-relaxed">
                    {JSON.stringify(finding.data, null, 2)}
                  </pre>
                </div>
              )}

              {/* Raw */}
              {finding.raw && (
                <div>
                  <p className="text-xs font-mono uppercase tracking-wider text-[#8b949e] mb-1">Raw</p>
                  <pre className="text-xs font-mono text-[#8b949e] bg-[#161b22] border border-[#30363d] rounded p-3 overflow-x-auto leading-relaxed whitespace-pre-wrap">
                    {finding.raw}
                  </pre>
                </div>
              )}

              {/* Metadata */}
              <div className="flex gap-6 text-xs text-[#8b949e] font-mono border-t border-[#30363d] pt-3">
                <span>ID: <span className="text-[#e6edf3]">{finding.id}</span></span>
                <span>Found: <span className="text-[#e6edf3]">{new Date(finding.found_at).toLocaleString()}</span></span>
              </div>
            </div>
          </td>
        </tr>
      )}
    </>
  )
}

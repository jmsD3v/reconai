import type { Severity } from '@/lib/types'

interface SeverityBadgeProps {
  severity: Severity
  size?: 'sm' | 'md'
}

const severityConfig: Record<Severity, { label: string; color: string; bg: string; dot: string }> = {
  critical: {
    label: 'CRITICAL',
    color: 'text-[#ff4444]',
    bg: 'bg-[#ff4444]/10 border border-[#ff4444]/30',
    dot: 'bg-[#ff4444]',
  },
  high: {
    label: 'HIGH',
    color: 'text-[#ff8800]',
    bg: 'bg-[#ff8800]/10 border border-[#ff8800]/30',
    dot: 'bg-[#ff8800]',
  },
  medium: {
    label: 'MEDIUM',
    color: 'text-[#ffcc00]',
    bg: 'bg-[#ffcc00]/10 border border-[#ffcc00]/30',
    dot: 'bg-[#ffcc00]',
  },
  low: {
    label: 'LOW',
    color: 'text-[#44aaff]',
    bg: 'bg-[#44aaff]/10 border border-[#44aaff]/30',
    dot: 'bg-[#44aaff]',
  },
  info: {
    label: 'INFO',
    color: 'text-[#888888]',
    bg: 'bg-[#888888]/10 border border-[#888888]/30',
    dot: 'bg-[#888888]',
  },
}

export function SeverityBadge({ severity, size = 'md' }: SeverityBadgeProps) {
  const config = severityConfig[severity] ?? severityConfig.info
  const sizeClasses = size === 'sm'
    ? 'px-1.5 py-0.5 text-[10px] gap-1'
    : 'px-2 py-1 text-xs gap-1.5'

  return (
    <span
      className={`inline-flex items-center rounded font-mono font-semibold ${config.bg} ${config.color} ${sizeClasses}`}
    >
      <span className={`rounded-full flex-shrink-0 ${config.dot} ${size === 'sm' ? 'w-1.5 h-1.5' : 'w-2 h-2'}`} />
      {config.label}
    </span>
  )
}

export function SeverityDot({ severity }: { severity: Severity }) {
  const config = severityConfig[severity] ?? severityConfig.info
  return (
    <span
      className={`inline-block w-2 h-2 rounded-full flex-shrink-0 ${config.dot}`}
      title={severity}
    />
  )
}

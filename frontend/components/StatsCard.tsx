interface StatsCardProps {
  label: string
  value: number | string
  accent?: string
  sublabel?: string
}

export function StatsCard({ label, value, accent, sublabel }: StatsCardProps) {
  return (
    <div className="bg-[#161b22] border border-[#30363d] rounded-lg p-4 flex flex-col gap-1">
      <span className="text-[#8b949e] text-xs font-mono uppercase tracking-wider">{label}</span>
      <span
        className="text-3xl font-bold font-mono tabular-nums"
        style={accent ? { color: accent } : { color: '#e6edf3' }}
      >
        {value}
      </span>
      {sublabel && (
        <span className="text-[#8b949e] text-xs">{sublabel}</span>
      )}
    </div>
  )
}

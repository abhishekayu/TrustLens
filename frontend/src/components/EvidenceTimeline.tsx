interface EvidenceTimelineProps {
  signals: string | null
}

interface ParsedSignal {
  label: string
  detail: string
  severity: 'safe' | 'low' | 'medium' | 'high'
}

function parseSignals(raw: string): ParsedSignal[] {
  const lines = raw.split(/[;\n]/).map(s => s.trim()).filter(Boolean)
  return lines.map(line => {
    const severity = (() => {
      const lower = line.toLowerCase()
      if (lower.includes('safe') || lower.includes('no risk') || lower.includes('✓')) return 'safe' as const
      if (lower.includes('high') || lower.includes('critical') || lower.includes('phish') || lower.includes('threat')) return 'high' as const
      if (lower.includes('suspicious') || lower.includes('warning')) return 'medium' as const
      return 'low' as const
    })()

    const parts = line.split(':')
    return {
      label: parts[0]?.trim() || 'Signal',
      detail: parts.slice(1).join(':').trim() || line,
      severity,
    }
  })
}

const severityColors = {
  safe: 'bg-[#00ff41]',
  low: 'bg-[#ffff00]',
  medium: 'bg-[#ff8c00]',
  high: 'bg-[#ff0040]',
}

const severityBorder = {
  safe: 'border-[#00ff41]/15',
  low: 'border-[#ffff00]/15',
  medium: 'border-[#ff8c00]/15',
  high: 'border-[#ff0040]/15',
}

const severityBg = {
  safe: 'bg-[#00ff41]/[0.03]',
  low: 'bg-[#ffff00]/[0.03]',
  medium: 'bg-[#ff8c00]/[0.03]',
  high: 'bg-[#ff0040]/[0.03]',
}

export default function EvidenceTimeline({ signals }: EvidenceTimelineProps) {
  if (!signals) return null

  const parsed = parseSignals(signals)
  if (parsed.length === 0) return null

  return (
    <div className="space-y-2.5">
      <h3 className="font-mono text-[10px] font-semibold text-[#484f58] uppercase tracking-widest flex items-center gap-2">
        <span className="text-[#00ff41]/40">{'>'}</span> Evidence Timeline
      </h3>
      <div className="space-y-1.5">
        {parsed.map((signal, i) => (
          <div
            key={i}
            className={`flex items-start gap-3 p-2.5 rounded border ${severityBorder[signal.severity]} ${severityBg[signal.severity]} animate-fade-in`}
            style={{ animationDelay: `${i * 60}ms` }}
          >
            <div className="flex flex-col items-center mt-1.5">
              <div className={`w-2 h-2 rounded-full ${severityColors[signal.severity]}`} style={{ boxShadow: `0 0 6px currentColor` }} />
              {i < parsed.length - 1 && <div className="w-px h-5 bg-[#1b2838] mt-1" />}
            </div>
            <div className="flex-1 min-w-0">
              <p className="font-mono text-xs font-medium text-[#c9d1d9]">{signal.label}</p>
              <p className="font-mono text-[10px] text-[#484f58] mt-0.5">{signal.detail}</p>
            </div>
          </div>
        ))}
      </div>
    </div>
  )
}

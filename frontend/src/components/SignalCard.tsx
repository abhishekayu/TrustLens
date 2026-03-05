import { Shield, AlertTriangle, XOctagon, CheckCircle, type LucideIcon } from 'lucide-react'

interface SignalCardProps {
  title: string
  score: number | null
  evidence?: string
  icon?: LucideIcon
}

function getColor(score: number) {
  if (score >= 75) return { border: 'border-[#00ff41]/20', text: 'text-[#00ff41]', glow: 'glow-green', bg: 'bg-[#00ff41]/5' }
  if (score >= 50) return { border: 'border-[#ffff00]/20', text: 'text-[#ffff00]', glow: 'glow-yellow', bg: 'bg-[#ffff00]/5' }
  if (score >= 25) return { border: 'border-[#ff8c00]/20', text: 'text-[#ff8c00]', glow: '', bg: 'bg-[#ff8c00]/5' }
  return { border: 'border-[#ff0040]/20', text: 'text-[#ff0040]', glow: 'glow-red', bg: 'bg-[#ff0040]/5' }
}

function getIcon(score: number): LucideIcon {
  if (score >= 75) return CheckCircle
  if (score >= 50) return Shield
  if (score >= 25) return AlertTriangle
  return XOctagon
}

export default function SignalCard({ title, score, evidence, icon }: SignalCardProps) {
  if (score === null || score === undefined) return null

  const colors = getColor(score)
  const Icon = icon || getIcon(score)

  return (
    <div className={`rounded-lg border ${colors.border} ${colors.bg} p-3.5 h-[120px] flex flex-col animate-fade-in transition-all hover:border-opacity-40`}>
      <div className="flex items-start justify-between mb-1.5">
        <div className="flex items-center gap-2 min-w-0">
          <Icon className={`w-3.5 h-3.5 shrink-0 ${colors.text}`} />
          <h4 className="text-xs font-mono font-medium text-[#c9d1d9] truncate">{title}</h4>
        </div>
        <span className={`font-mono text-sm font-bold shrink-0 ml-2 ${colors.text} ${colors.glow}`}>{Math.round(score)}</span>
      </div>
      {evidence && (
        <p className="text-[11px] font-mono text-[#484f58] leading-relaxed mt-1 pl-5.5 line-clamp-3 overflow-hidden">{evidence}</p>
      )}
    </div>
  )
}

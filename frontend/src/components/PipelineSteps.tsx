import {
  CheckCircle2,
  XCircle,
  Loader2,
  Circle,
  SkipForward,
  ChevronDown,
  ChevronRight,
  Globe,
  ShieldCheck,
  Brain,
  Fingerprint,
  Search,
  Lock,
  Camera,
  AlertTriangle,
  Users,
  Gauge,
  Bug,
  CreditCard,
  Radar,
} from 'lucide-react'
import { useState } from 'react'
import type { PipelineStep } from '../services/api'

const STEP_ICONS: Record<string, React.ComponentType<{ className?: string }>> = {
  crawl: Globe,
  rules: ShieldCheck,
  brand: Fingerprint,
  behavioral: Search,
  domain_intel: Search,
  headers: Lock,
  ai: Brain,
  screenshot: Camera,
  threat_intel: AlertTriangle,
  community: Users,
  zeroday: Bug,
  scoring: Gauge,
  payment: CreditCard,
  tracker: Radar,
}

const STATUS_COLORS: Record<string, string> = {
  pending: 'text-[#484f58]',
  running: 'text-[#00ffff]',
  done: 'text-[#00ff41]',
  failed: 'text-[#ff0040]',
  skipped: 'text-[#484f58]/50',
}

function StatusIcon({ status }: { status: string }) {
  switch (status) {
    case 'done':
      return <CheckCircle2 className="w-3.5 h-3.5 text-[#00ff41] shrink-0" />
    case 'running':
      return <Loader2 className="w-3.5 h-3.5 text-[#00ffff] animate-spin shrink-0" />
    case 'failed':
      return <XCircle className="w-3.5 h-3.5 text-[#ff0040] shrink-0" />
    case 'skipped':
      return <SkipForward className="w-3.5 h-3.5 text-[#484f58]/50 shrink-0" />
    default:
      return <Circle className="w-3.5 h-3.5 text-[#484f58] shrink-0" />
  }
}

interface Props {
  steps: PipelineStep[]
  expanded?: boolean
}

export default function PipelineSteps({ steps, expanded = false }: Props) {
  const [open, setOpen] = useState(expanded)

  const doneCount = steps.filter(s => s.status === 'done').length
  const runningCount = steps.filter(s => s.status === 'running').length
  const failedCount = steps.filter(s => s.status === 'failed').length
  const total = steps.length

  const summaryParts: string[] = []
  if (doneCount > 0) summaryParts.push(`${doneCount} done`)
  if (runningCount > 0) summaryParts.push(`${runningCount} running`)
  if (failedCount > 0) summaryParts.push(`${failedCount} failed`)
  const summary = summaryParts.join(' · ') || 'Waiting…'

  return (
    <div className="terminal-card">
      {/* Header */}
      <button
        onClick={() => setOpen(o => !o)}
        className="w-full flex items-center justify-between px-4 py-2.5 hover:bg-white/[0.02] transition"
      >
        <div className="flex items-center gap-3">
          <span className="font-mono text-[10px] text-[#00ff41]/50">$</span>
          <h3 className="font-mono text-xs font-semibold text-[#c9d1d9] uppercase tracking-wider">
            Pipeline
          </h3>
          <span className="font-mono text-[10px] text-[#484f58]">
            {summary} ({doneCount}/{total})
          </span>
        </div>
        {open ? (
          <ChevronDown className="w-3.5 h-3.5 text-[#484f58]" />
        ) : (
          <ChevronRight className="w-3.5 h-3.5 text-[#484f58]" />
        )}
      </button>

      {/* Progress bar */}
      <div className="h-px bg-[#1b2838]">
        <div
          className="h-full transition-all duration-500 ease-out"
          style={{
            width: `${total > 0 ? (doneCount / total) * 100 : 0}%`,
            background: 'linear-gradient(90deg, #00ff41, #00ffff)',
            boxShadow: '0 0 8px rgba(0,255,65,0.3)',
          }}
        />
      </div>

      {/* Steps list */}
      {open && (
        <div className="divide-y divide-[#1b2838]/60">
          {steps.map(step => {
            const Icon = STEP_ICONS[step.name] || ShieldCheck
            return (
              <div
                key={step.name}
                className={`flex items-start gap-3 px-4 py-2 transition font-mono ${
                  step.status === 'running'
                    ? 'bg-[#00ffff]/[0.03]'
                    : step.status === 'failed'
                      ? 'bg-[#ff0040]/[0.03]'
                      : ''
                }`}
              >
                <Icon className={`w-3.5 h-3.5 mt-0.5 shrink-0 ${STATUS_COLORS[step.status] || 'text-[#484f58]'}`} />
                <div className="flex-1 min-w-0">
                  <p
                    className={`text-xs font-medium ${
                      step.status === 'running'
                        ? 'text-[#00ffff]'
                        : step.status === 'done'
                          ? 'text-[#c9d1d9]'
                          : step.status === 'failed'
                            ? 'text-[#ff0040]'
                            : 'text-[#484f58]'
                    }`}
                  >
                    {step.label}
                  </p>
                  {step.detail && (
                    <p className="text-[10px] text-[#484f58] mt-0.5 truncate" title={step.detail}>
                      {step.detail}
                    </p>
                  )}
                </div>
                <StatusIcon status={step.status} />
              </div>
            )
          })}
        </div>
      )}
    </div>
  )
}

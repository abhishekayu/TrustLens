import { useState, useEffect, type FormEvent } from 'react'
import { useNavigate } from 'react-router-dom'
import { Terminal, Search, Layers, FileSearch, Lock, ArrowRight, Loader2, ChevronRight, Shield, Scan } from 'lucide-react'
import { submitAnalysis } from '../services/api'

const features = [
  {
    icon: Layers,
    title: '15+ Parallel Engines',
    desc: 'Domain intel, behavioral analysis, security headers, brand impersonation, download threats — all run simultaneously in real time.',
    tag: 'CORE',
  },
  {
    icon: FileSearch,
    title: 'Explainable by Design',
    desc: 'Every signal, score & verdict backed by transparent evidence. Full deep-dive audit trail — zero black boxes.',
    tag: 'TRUST',
  },
  {
    icon: Lock,
    title: 'Self-Hosted & Private',
    desc: 'Runs entirely on your machine. No data leaves your environment. Open-source, auditable, and free.',
    tag: 'PRIVACY',
  },
]

const asciiLines = [
  '╔══════════════════════════════════════════════════════════════╗',
  '║  ████████╗██████╗ ██╗   ██╗███████╗████████╗██╗     ███████╗║',
  '║  ╚══██╔══╝██╔══██╗██║   ██║██╔════╝╚══██╔══╝██║     ██╔════╝║',
  '║     ██║   ██████╔╝██║   ██║███████╗   ██║   ██║     █████╗  ║',
  '║     ██║   ██╔══██╗██║   ██║╚════██║   ██║   ██║     ██╔══╝  ║',
  '║     ██║   ██║  ██║╚██████╔╝███████║   ██║   ███████╗███████╗║',
  '║     ╚═╝   ╚═╝  ╚═╝ ╚═════╝ ╚══════╝   ╚═╝   ╚══════╝╚══════╝║',
  '╚══════════════════════════════════════════════════════════════╝',
]

export default function ScanPage() {
  const [url, setUrl] = useState('')
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const [typed, setTyped] = useState('')
  const navigate = useNavigate()

  // Typing effect for the subtitle
  const subtitle = 'Explainable AI-Powered URL Trust Intelligence Engine'
  useEffect(() => {
    let i = 0
    const timer = setInterval(() => {
      setTyped(subtitle.slice(0, i + 1))
      i++
      if (i >= subtitle.length) clearInterval(timer)
    }, 35)
    return () => clearInterval(timer)
  }, [])

  const handleSubmit = async (e: FormEvent) => {
    e.preventDefault()
    if (!url.trim()) return

    setLoading(true)
    setError(null)

    try {
      let normalised = url.trim()
      if (!/^https?:\/\//i.test(normalised)) normalised = `https://${normalised}`

      const res = await submitAnalysis(normalised)
      navigate(`/results/${res.analysis_id}`)
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Submission failed')
      setLoading(false)
    }
  }

  return (
    <div className="max-w-4xl mx-auto px-4 py-12 animate-fade-in">
      {/* ASCII Art Hero */}
      <div className="text-center mb-10">
        <div className="hidden sm:block mb-6 overflow-x-auto">
          <pre className="text-[#00ff41] glow-green text-[8px] sm:text-[10px] leading-tight font-mono inline-block animate-flicker">
            {asciiLines.join('\n')}
          </pre>
        </div>
        <div className="sm:hidden mb-6">
          <div className="inline-flex items-center justify-center w-14 h-14 rounded-lg border border-[#00ff41]/20 bg-[#00ff41]/5 animate-pulse-glow">
            <Shield className="w-7 h-7 text-[#00ff41]" />
          </div>
        </div>
        <h1 className="font-mono text-2xl sm:text-3xl font-bold text-white mb-3 tracking-tight">
          <span className="text-[#00ff41] glow-green">TRUSTLENS</span>{' '}
          <span className="text-[#00ffff] glow-cyan">AI</span>
        </h1>
        <p className="font-mono text-sm text-[#484f58] h-6">
          <span className="text-[#00ff41]/50">{'> '}</span>
          {typed}
          <span className="inline-block w-2 h-4 bg-[#00ff41] ml-0.5 animate-[terminal-blink_1s_step-end_infinite]" />
        </p>
      </div>

      {/* Terminal Search Form */}
      <div className="terminal-card animate-slide-up mb-10">
        <div className="terminal-card-header">
          <span>trustlens://scan</span>
          <span className="ml-auto text-[#00ff41]/50">ready</span>
        </div>
        <div className="terminal-card-body">
          <form onSubmit={handleSubmit}>
            <div className="flex items-center gap-2 mb-3">
              <span className="text-[#00ff41] font-mono text-sm glow-green">$</span>
              <span className="text-[#484f58] font-mono text-sm">scan</span>
            </div>
            <div className="flex gap-2">
              <div className="relative flex-1">
                <ChevronRight className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-[#00ff41]/40" />
                <input
                  type="text"
                  value={url}
                  onChange={e => setUrl(e.target.value)}
                  placeholder="https://target-url.com"
                  className="terminal-input w-full pl-9 pr-4 py-3 text-sm"
                  disabled={loading}
                  autoFocus
                />
              </div>
              <button
                type="submit"
                disabled={loading || !url.trim()}
                className="terminal-btn px-5 py-3 flex items-center gap-2 text-sm whitespace-nowrap"
              >
                {loading ? (
                  <>
                    <Loader2 className="w-4 h-4 animate-spin" />
                    <span>SCANNING</span>
                  </>
                ) : (
                  <>
                    <Scan className="w-4 h-4" />
                    <span>EXECUTE</span>
                  </>
                )}
              </button>
            </div>
            {error && (
              <div className="mt-3 font-mono text-xs text-[#ff0040] bg-[#ff0040]/5 border border-[#ff0040]/20 rounded px-3 py-2 glow-red">
                <span className="text-[#ff0040]/60">ERROR: </span>{error}
              </div>
            )}
          </form>
        </div>
      </div>

      {/* Feature Grid */}
      <div className="grid grid-cols-1 sm:grid-cols-3 gap-3 mt-6">
        {features.map(({ icon: Icon, title, desc, tag }, i) => (
          <div
            key={title}
            className="terminal-card group hover:border-[#00ff41]/20 transition-all animate-fade-in cursor-default"
            style={{ animationDelay: `${i * 100 + 300}ms`, opacity: 0 }}
          >
            <div className="p-4">
              <div className="flex items-center justify-between mb-3">
                <div className="w-8 h-8 rounded border border-[#1b2838] bg-[#0a0e17] flex items-center justify-center group-hover:border-[#00ff41]/20 transition">
                  <Icon className="w-4 h-4 text-[#00ffff]" />
                </div>
                <span className="font-mono text-[9px] text-[#00ff41]/40 border border-[#00ff41]/10 rounded px-1.5 py-0.5">
                  {tag}
                </span>
              </div>
              <h3 className="font-mono font-semibold text-sm text-[#c9d1d9] mb-1.5">{title}</h3>
              <p className="text-xs text-[#484f58] leading-relaxed">{desc}</p>
            </div>
          </div>
        ))}
      </div>

      {/* Trust Badge */}
      <div className="text-center mt-14 font-mono text-[10px] text-[#484f58]/60">
        <p>
          <span className="text-[#00ff41]/30">{'[ '}</span>
          OPEN-SOURCE • SELF-HOSTABLE • PRIVACY-FIRST
          <span className="text-[#00ff41]/30">{' ]'}</span>
        </p>
      </div>
    </div>
  )
}

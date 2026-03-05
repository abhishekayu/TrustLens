import { useState, type FormEvent } from 'react'
import { Users, Send, Search, CheckCircle, AlertTriangle, XOctagon, Loader2, ChevronRight } from 'lucide-react'
import { getCommunityConsensus, submitCommunityReport, type CommunityConsensus } from '../services/api'

type Verdict = 'safe' | 'suspicious' | 'phishing'

const verdictConfig: Record<Verdict, { color: string; border: string; icon: typeof CheckCircle; glow: string }> = {
  safe: { color: 'text-[#00ff41]', border: 'border-[#00ff41]/20 bg-[#00ff41]/5', icon: CheckCircle, glow: 'glow-green' },
  suspicious: { color: 'text-[#ffff00]', border: 'border-[#ffff00]/20 bg-[#ffff00]/5', icon: AlertTriangle, glow: 'glow-yellow' },
  phishing: { color: 'text-[#ff0040]', border: 'border-[#ff0040]/20 bg-[#ff0040]/5', icon: XOctagon, glow: 'glow-red' },
}

export default function CommunityPage() {
  const [lookupUrl, setLookupUrl] = useState('')
  const [consensus, setConsensus] = useState<CommunityConsensus | null>(null)
  const [lookupLoading, setLookupLoading] = useState(false)
  const [lookupError, setLookupError] = useState<string | null>(null)

  const [reportUrl, setReportUrl] = useState('')
  const [verdict, setVerdict] = useState<Verdict>('suspicious')
  const [comment, setComment] = useState('')
  const [reportLoading, setReportLoading] = useState(false)
  const [reportSuccess, setReportSuccess] = useState(false)
  const [reportError, setReportError] = useState<string | null>(null)

  const handleLookup = async (e: FormEvent) => {
    e.preventDefault()
    if (!lookupUrl.trim()) return
    setLookupLoading(true)
    setLookupError(null)
    setConsensus(null)
    try {
      const data = await getCommunityConsensus(lookupUrl.trim())
      setConsensus(data)
    } catch (err) {
      setLookupError(err instanceof Error ? err.message : 'Lookup failed')
    } finally {
      setLookupLoading(false)
    }
  }

  const handleReport = async (e: FormEvent) => {
    e.preventDefault()
    if (!reportUrl.trim()) return
    setReportLoading(true)
    setReportError(null)
    setReportSuccess(false)
    try {
      await submitCommunityReport(reportUrl.trim(), verdict, comment || undefined)
      setReportSuccess(true)
      setReportUrl('')
      setComment('')
    } catch (err) {
      setReportError(err instanceof Error ? err.message : 'Report failed')
    } finally {
      setReportLoading(false)
    }
  }

  return (
    <div className="max-w-4xl mx-auto px-4 py-10 animate-fade-in">
      <div className="text-center mb-10">
        <div className="inline-flex items-center justify-center w-12 h-12 rounded-lg border border-[#00ffff]/20 bg-[#00ffff]/5 mb-4">
          <Users className="w-6 h-6 text-[#00ffff]" />
        </div>
        <h1 className="font-mono text-xl font-bold text-white mb-2">
          <span className="text-[#00ffff] glow-cyan">COMMUNITY</span> INTELLIGENCE
        </h1>
        <p className="font-mono text-xs text-[#484f58]">
          Look up community consensus on a URL or submit your own report.
        </p>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-5">
        {/* Lookup */}
        <div className="terminal-card">
          <div className="terminal-card-header">
            <Search className="w-3 h-3 text-[#00ffff]" />
            <span>LOOK UP URL</span>
          </div>
          <div className="terminal-card-body">
            <form onSubmit={handleLookup} className="space-y-3">
              <div className="relative">
                <ChevronRight className="absolute left-3 top-1/2 -translate-y-1/2 w-3.5 h-3.5 text-[#00ff41]/40" />
                <input
                  type="text"
                  value={lookupUrl}
                  onChange={e => setLookupUrl(e.target.value)}
                  placeholder="https://example.com"
                  className="terminal-input w-full pl-8 pr-4 py-2.5 text-xs"
                />
              </div>
              <button
                type="submit"
                disabled={lookupLoading || !lookupUrl.trim()}
                className="terminal-btn-cyan terminal-btn w-full px-4 py-2.5 flex items-center justify-center gap-2 text-xs"
              >
                {lookupLoading ? <Loader2 className="w-3.5 h-3.5 animate-spin" /> : <Search className="w-3.5 h-3.5" />}
                LOOK UP
              </button>
            </form>

            {lookupError && (
              <p className="mt-3 font-mono text-[10px] text-[#ff0040]">
                <span className="text-[#ff0040]/50">ERROR: </span>{lookupError}
              </p>
            )}

            {consensus && (
              <div className="mt-4 space-y-1.5">
                {[
                  { label: 'Domain', value: consensus.consensus.url_or_domain },
                  { label: 'Total reports', value: consensus.consensus.total_reports },
                  { label: 'Safe / Suspicious / Phish', value: `${consensus.consensus.safe_reports} / ${consensus.consensus.scam_reports} / ${consensus.consensus.phishing_reports}` },
                  { label: 'Crowd risk', value: consensus.consensus.crowd_risk_score },
                  { label: 'Confidence', value: `${Math.round(consensus.consensus.consensus_confidence * 100)}%` },
                ].map(row => (
                  <div key={row.label} className="flex items-center justify-between font-mono text-[11px]">
                    <span className="text-[#484f58]">{row.label}</span>
                    <span className="text-[#c9d1d9] font-medium">{row.value}</span>
                  </div>
                ))}
              </div>
            )}
          </div>
        </div>

        {/* Report */}
        <div className="terminal-card">
          <div className="terminal-card-header">
            <Send className="w-3 h-3 text-[#00ffff]" />
            <span>SUBMIT REPORT</span>
          </div>
          <div className="terminal-card-body">
            <form onSubmit={handleReport} className="space-y-3">
              <div className="relative">
                <ChevronRight className="absolute left-3 top-1/2 -translate-y-1/2 w-3.5 h-3.5 text-[#00ff41]/40" />
                <input
                  type="text"
                  value={reportUrl}
                  onChange={e => setReportUrl(e.target.value)}
                  placeholder="https://suspicious-site.com"
                  className="terminal-input w-full pl-8 pr-4 py-2.5 text-xs"
                />
              </div>
              <div>
                <label className="block font-mono text-[10px] text-[#484f58] uppercase tracking-wider mb-2">Verdict</label>
                <div className="flex gap-2">
                  {(Object.keys(verdictConfig) as Verdict[]).map(v => {
                    const cfg = verdictConfig[v]
                    const Icon = cfg.icon
                    const active = verdict === v
                    return (
                      <button
                        key={v}
                        type="button"
                        onClick={() => setVerdict(v)}
                        className={`flex-1 flex items-center justify-center gap-1.5 px-2 py-2 rounded border font-mono text-[10px] font-medium capitalize transition ${
                          active ? cfg.border + ' ' + cfg.color + ' ' + cfg.glow : 'border-[#1b2838] text-[#484f58] hover:border-[#2d3748]'
                        }`}
                      >
                        <Icon className="w-3 h-3" />
                        {v}
                      </button>
                    )
                  })}
                </div>
              </div>
              <textarea
                value={comment}
                onChange={e => setComment(e.target.value)}
                placeholder="Optional comment..."
                rows={3}
                className="terminal-input w-full px-3 py-2.5 text-xs resize-none"
              />
              <button
                type="submit"
                disabled={reportLoading || !reportUrl.trim()}
                className="terminal-btn w-full px-4 py-2.5 flex items-center justify-center gap-2 text-xs"
              >
                {reportLoading ? <Loader2 className="w-3.5 h-3.5 animate-spin" /> : <Send className="w-3.5 h-3.5" />}
                SUBMIT
              </button>
            </form>

            {reportError && (
              <p className="mt-3 font-mono text-[10px] text-[#ff0040]">
                <span className="text-[#ff0040]/50">ERROR: </span>{reportError}
              </p>
            )}
            {reportSuccess && (
              <p className="mt-3 font-mono text-[10px] text-[#00ff41] flex items-center gap-1 glow-green">
                <CheckCircle className="w-3.5 h-3.5" /> Report submitted successfully.
              </p>
            )}
          </div>
        </div>
      </div>
    </div>
  )
}

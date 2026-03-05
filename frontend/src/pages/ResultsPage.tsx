import { useParams, Link } from 'react-router-dom'
import { ArrowLeft, ExternalLink, Clock, AlertCircle, Brain, Shield, Eye } from 'lucide-react'
import { useAnalysisPolling } from '../hooks/useAnalysisPolling'
import ScoreGauge from '../components/ScoreGauge'
import SignalCard from '../components/SignalCard'
import PipelineSteps from '../components/PipelineSteps'
import DeepDive from '../components/DeepDive'

export default function ResultsPage() {
  const { id } = useParams<{ id: string }>()
  const { result, error, loading } = useAnalysisPolling(id ?? null)

  /* ---- Loading state ---- */
  if (loading && !result) {
    return (
      <div className="max-w-4xl mx-auto px-4 py-24 text-center animate-fade-in">
        <div className="scanning-pulse inline-flex items-center justify-center w-20 h-20 rounded-full border border-[#00ff41]/20 bg-[#00ff41]/5 mb-6">
          <Clock className="w-8 h-8 text-[#00ff41] animate-spin" style={{ animationDuration: '3s' }} />
        </div>
        <h2 className="font-mono text-lg font-semibold text-[#00ff41] glow-green mb-2">SCANNING TARGET...</h2>
        <p className="font-mono text-xs text-[#484f58] mb-6">
          Crawling page • Extracting signals • Consulting AI • Computing trust score
        </p>
        <div className="inline-flex items-center gap-2 font-mono text-[10px] text-[#484f58]">
          <span className="w-1.5 h-1.5 rounded-full bg-[#00ff41] animate-pulse" />
          <span>Pipeline active</span>
        </div>
      </div>
    )
  }

  /* ---- Error / pending poll ---- */
  if (error) {
    return (
      <div className="max-w-4xl mx-auto px-4 py-24 text-center animate-fade-in">
        <AlertCircle className="w-12 h-12 text-[#ff0040] mx-auto mb-4" />
        <h2 className="font-mono text-lg font-semibold text-white mb-2">ANALYSIS FAILED</h2>
        <p className="font-mono text-xs text-[#484f58] mb-6">{error}</p>
        <Link to="/" className="font-mono text-xs text-[#00ff41] hover:text-[#00ff41]/80 transition">
          &larr; NEW SCAN
        </Link>
      </div>
    )
  }

  if (!result) return null

  /* ---- Pending/In-progress with partial data ---- */
  if (result.status !== 'completed' && result.status !== 'failed') {
    const steps = result.pipeline_steps ?? []
    return (
      <div className="max-w-4xl mx-auto px-4 py-10 animate-fade-in">
        <Link to="/" className="inline-flex items-center gap-1 font-mono text-xs text-[#484f58] hover:text-[#00ff41] transition mb-6">
          <ArrowLeft className="w-3.5 h-3.5" /> NEW SCAN
        </Link>

        {/* URL banner */}
        <div className="terminal-card mb-5">
          <div className="terminal-card-header">
            <span>target</span>
          </div>
          <div className="px-4 py-2.5">
            <span className="font-mono text-xs text-[#00ffff]">{result.url}</span>
          </div>
        </div>

        <div className="text-center mb-6">
          <div className="scanning-pulse inline-flex items-center justify-center w-14 h-14 rounded-full border border-[#00ff41]/20 bg-[#00ff41]/5 mb-3">
            <Clock className="w-6 h-6 text-[#00ff41] animate-spin" style={{ animationDuration: '3s' }} />
          </div>
          <h2 className="font-mono text-sm font-semibold text-[#00ff41] glow-green mb-1">SCANNING...</h2>
          <p className="font-mono text-[10px] text-[#484f58] uppercase tracking-widest">{result.status.replace('_', ' ')}</p>
        </div>

        {steps.length > 0 && <PipelineSteps steps={steps} expanded />}
      </div>
    )
  }

  /* ---- Failed result ---- */
  if (result.status === 'failed') {
    const failedSteps = result.pipeline_steps ?? []
    return (
      <div className="max-w-4xl mx-auto px-4 py-10 animate-fade-in">
        <Link to="/" className="inline-flex items-center gap-1 font-mono text-xs text-[#484f58] hover:text-[#00ff41] transition mb-6">
          <ArrowLeft className="w-3.5 h-3.5" /> NEW SCAN
        </Link>
        <div className="text-center mb-6">
          <AlertCircle className="w-12 h-12 text-[#ff0040] mx-auto mb-4" />
          <h2 className="font-mono text-lg font-semibold text-white mb-2">ANALYSIS FAILED</h2>
          <p className="font-mono text-xs text-[#484f58] mb-2">{result.url}</p>
          <p className="font-mono text-xs text-[#ff0040]">{result.error || 'Unknown error'}</p>
        </div>
        {failedSteps.length > 0 && <PipelineSteps steps={failedSteps} expanded />}
      </div>
    )
  }

  /* ---- Completed result ---- */
  const ts = result.trust_score

  const signals = ts
    ? ts.components.map(c => ({
        title: c.component.replace(/_/g, ' '),
        score: c.raw_score,
        evidence: c.signals?.join('; ') || undefined,
      }))
    : []

  if (ts) {
    // Build top-4 key findings for Rule-Based Score
    const ruleKeys = ts.components
      .filter(c => c.component !== 'ai_deception_classifier')
      .flatMap(c => c.signals)
      .filter(Boolean)
      .slice(0, 4)
      .join('; ')

    // Build top-4 key findings for AI Advisory Score
    const aiComp = ts.components.find(c => c.component === 'ai_deception_classifier')
    const aiKeys = aiComp?.signals?.filter(Boolean).slice(0, 4).join('; ') || undefined

    signals.unshift(
      { title: 'Rule‑Based Score', score: ts.rule_score, evidence: ruleKeys || 'All rule checks passed' },
      { title: 'AI Advisory Score', score: ts.ai_confidence * 100, evidence: aiKeys || 'AI analysis complete' },
    )
  }

  return (
    <div className="max-w-5xl mx-auto px-4 py-8 animate-fade-in">
      {/* Back */}
      <Link to="/" className="inline-flex items-center gap-1.5 font-mono text-xs text-[#484f58] hover:text-[#00ff41] transition mb-6">
        <ArrowLeft className="w-3.5 h-3.5" /> NEW SCAN
      </Link>

      {/* URL banner */}
      <div className="terminal-card mb-6">
        <div className="terminal-card-header">
          <span>target://analysis</span>
          <span className="ml-auto text-[#00ff41]/50">complete</span>
        </div>
        <div className="px-4 py-2.5 flex items-center justify-between">
          <span className="font-mono text-xs text-[#00ffff] flex-1 truncate">{result.url}</span>
          <a
            href={result.url}
            target="_blank"
            rel="noreferrer noopener"
            className="text-[#484f58] hover:text-[#00ffff] transition ml-3"
          >
            <ExternalLink className="w-3.5 h-3.5" />
          </a>
        </div>
      </div>

      {/* Score + signals grid */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-5 mb-8">
        {/* Score gauge */}
        <div className="terminal-card flex flex-col items-center justify-center p-6">
          <ScoreGauge score={ts?.overall_score ?? null} size={190} />
          <p className="font-mono text-[10px] text-[#484f58] mt-3 text-center uppercase tracking-widest">
            {ts?.risk_category && (
              <span>{ts.risk_category}</span>
            )}
          </p>
        </div>

        {/* Signal cards */}
        <div className="lg:col-span-2 grid grid-cols-1 sm:grid-cols-2 gap-2.5">
          {signals.map(s => (
            <SignalCard key={s.title} title={s.title} score={s.score} evidence={s.evidence} />
          ))}
        </div>
      </div>

      {/* AI explanation */}
      {ts?.ai_explanation && (
        <div className="terminal-card mb-6">
          <div className="terminal-card-header">
            <Brain className="w-3.5 h-3.5 text-[#00ffff]" />
            <span>AI THREAT ASSESSMENT</span>
          </div>
          <div className="terminal-card-body">
            <div className="font-mono text-xs text-[#c9d1d9] leading-relaxed whitespace-pre-line">{ts.ai_explanation}</div>

            {/* URL Perspective summary */}
            {result.deep_dive?.ai_analysis?.url_perspective && (
              <div className="mt-4 pt-4 border-t border-[#1b2838]">
                <div className="grid grid-cols-1 sm:grid-cols-2 gap-2.5">
                  {result.deep_dive.ai_analysis.url_perspective.purpose && (
                    <div className="rounded border border-[#1b2838] bg-[#0a0e17] p-3">
                      <p className="font-mono text-[10px] text-[#484f58] mb-1 flex items-center gap-1"><Eye className="w-3 h-3" /> PURPOSE</p>
                      <p className="font-mono text-xs text-[#c9d1d9]">{result.deep_dive.ai_analysis.url_perspective.purpose}</p>
                    </div>
                  )}
                  {result.deep_dive.ai_analysis.url_perspective.content_category && (
                    <div className="rounded border border-[#1b2838] bg-[#0a0e17] p-3">
                      <p className="font-mono text-[10px] text-[#484f58] mb-1 flex items-center gap-1"><Shield className="w-3 h-3" /> CATEGORY</p>
                      <p className="font-mono text-xs text-[#c9d1d9]">{result.deep_dive.ai_analysis.url_perspective.content_category}</p>
                    </div>
                  )}
                </div>
                {result.deep_dive.ai_analysis.url_perspective.overall_assessment && (
                  <p className="mt-2.5 font-mono text-[11px] text-[#484f58] bg-[#0a0e17] rounded border border-[#1b2838] p-3">
                    {result.deep_dive.ai_analysis.url_perspective.overall_assessment}
                  </p>
                )}
              </div>
            )}
          </div>
        </div>
      )}

      {/* Pipeline steps */}
      {result.pipeline_steps && result.pipeline_steps.length > 0 && (
        <div className="mb-6">
          <PipelineSteps steps={result.pipeline_steps} />
        </div>
      )}

      {/* Deep Dive — full transparency panel */}
      {result.deep_dive && (
        <div className="mb-6">
          <DeepDive data={result.deep_dive} evidenceSignals={ts?.explanation ?? null} />
        </div>
      )}

      {/* Metadata */}
      <div className="grid grid-cols-2 sm:grid-cols-4 gap-3 text-xs">
        {result.analysis_id && <Stat label="ANALYSIS ID" value={result.analysis_id.slice(0, 8)} />}
        {ts && <Stat label="RISK LEVEL" value={ts.risk_level} />}
        {ts && <Stat label="CONFIDENCE" value={`${Math.round(ts.confidence * 100)}%`} />}
        {result.submitted_at && <Stat label="SCANNED" value={new Date(result.submitted_at).toLocaleString()} />}
      </div>
    </div>
  )
}

function Stat({ label, value }: { label: string; value: string }) {
  return (
    <div className="rounded border border-[#1b2838] bg-[#0d1117] p-3">
      <p className="font-mono text-[10px] text-[#484f58] mb-0.5 uppercase tracking-wider">{label}</p>
      <p className="font-mono text-xs text-[#c9d1d9] font-medium truncate">{value}</p>
    </div>
  )
}

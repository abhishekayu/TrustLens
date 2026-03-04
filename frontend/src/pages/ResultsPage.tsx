import { useParams, Link } from 'react-router-dom'
import { ArrowLeft, ExternalLink, Clock, AlertCircle } from 'lucide-react'
import { useAnalysisPolling } from '../hooks/useAnalysisPolling'
import ScoreGauge from '../components/ScoreGauge'
import SignalCard from '../components/SignalCard'
import EvidenceTimeline from '../components/EvidenceTimeline'
import PipelineSteps from '../components/PipelineSteps'
import DeepDive from '../components/DeepDive'

export default function ResultsPage() {
  const { id } = useParams<{ id: string }>()
  const { result, error, loading } = useAnalysisPolling(id ?? null)

  /* ---- Loading state ---- */
  if (loading && !result) {
    return (
      <div className="max-w-4xl mx-auto px-4 py-24 text-center animate-fade-in">
        <div className="scanning-pulse inline-flex items-center justify-center w-20 h-20 rounded-full bg-sky-500/10 mb-6">
          <Clock className="w-8 h-8 text-sky-400 animate-spin" style={{ animationDuration: '3s' }} />
        </div>
        <h2 className="text-xl font-semibold text-white mb-2">Analyzing URL…</h2>
        <p className="text-gray-400 text-sm mb-6">
          Crawling page, extracting signals, consulting AI, computing trust score.
        </p>
      </div>
    )
  }

  /* ---- Error / pending poll ---- */
  if (error) {
    return (
      <div className="max-w-4xl mx-auto px-4 py-24 text-center animate-fade-in">
        <AlertCircle className="w-12 h-12 text-red-400 mx-auto mb-4" />
        <h2 className="text-xl font-semibold text-white mb-2">Analysis Failed</h2>
        <p className="text-gray-400 text-sm mb-6">{error}</p>
        <Link to="/" className="text-sky-400 hover:text-sky-300 text-sm font-medium">
          &larr; Try another URL
        </Link>
      </div>
    )
  }

  if (!result) return null

  /* ---- Pending/In-progress with partial data ---- */
  if (result.status !== 'completed' && result.status !== 'failed') {
    const steps = result.pipeline_steps ?? []
    return (
      <div className="max-w-4xl mx-auto px-4 py-12 animate-fade-in">
        <Link to="/" className="inline-flex items-center gap-1 text-sm text-gray-400 hover:text-white transition mb-8">
          <ArrowLeft className="w-4 h-4" /> New scan
        </Link>

        {/* URL banner */}
        <div className="flex items-center gap-3 bg-gray-900 border border-gray-800 rounded-xl px-5 py-3 mb-6">
          <span className="text-sm text-gray-400 flex-1 truncate">{result.url}</span>
        </div>

        <div className="text-center mb-8">
          <div className="scanning-pulse inline-flex items-center justify-center w-16 h-16 rounded-full bg-sky-500/10 mb-4">
            <Clock className="w-7 h-7 text-sky-400 animate-spin" style={{ animationDuration: '3s' }} />
          </div>
          <h2 className="text-lg font-semibold text-white mb-1">Scanning…</h2>
          <p className="text-gray-500 text-xs uppercase tracking-wide">{result.status.replace('_', ' ')}</p>
        </div>

        {steps.length > 0 && <PipelineSteps steps={steps} expanded />}
      </div>
    )
  }

  /* ---- Failed result ---- */
  if (result.status === 'failed') {
    const failedSteps = result.pipeline_steps ?? []
    return (
      <div className="max-w-4xl mx-auto px-4 py-12 animate-fade-in">
        <Link to="/" className="inline-flex items-center gap-1 text-sm text-gray-400 hover:text-white transition mb-8">
          <ArrowLeft className="w-4 h-4" /> New scan
        </Link>
        <div className="text-center mb-8">
          <AlertCircle className="w-12 h-12 text-red-400 mx-auto mb-4" />
          <h2 className="text-xl font-semibold text-white mb-2">Analysis Failed</h2>
          <p className="text-gray-400 text-sm mb-2">{result.url}</p>
          <p className="text-red-400 text-sm">{result.error || 'Unknown error'}</p>
        </div>
        {failedSteps.length > 0 && <PipelineSteps steps={failedSteps} expanded />}
      </div>
    )
  }

  /* ---- Completed result ---- */
  const ts = result.trust_score

  const signals = ts
    ? ts.components.map(c => ({
        title: c.name,
        score: c.score,
        evidence: c.evidence?.join('; ') || undefined,
      }))
    : []

  // Also add top-level rule & AI scores as signal cards
  if (ts) {
    signals.unshift(
      { title: 'Rule‑Based Score', score: ts.rule_score, evidence: undefined },
      { title: 'AI Advisory Score', score: ts.ai_confidence * 100, evidence: undefined },
    )
  }

  return (
    <div className="max-w-5xl mx-auto px-4 py-10 animate-fade-in">
      {/* Back */}
      <Link to="/" className="inline-flex items-center gap-1 text-sm text-gray-400 hover:text-white transition mb-8">
        <ArrowLeft className="w-4 h-4" /> New scan
      </Link>

      {/* URL banner */}
      <div className="flex items-center gap-3 bg-gray-900 border border-gray-800 rounded-xl px-5 py-3 mb-8">
        <span className="text-sm text-gray-400 flex-1 truncate">{result.url}</span>
        <a
          href={result.url}
          target="_blank"
          rel="noreferrer noopener"
          className="text-gray-500 hover:text-sky-400 transition"
        >
          <ExternalLink className="w-4 h-4" />
        </a>
      </div>

      {/* Score + signals grid */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-8 mb-10">
        {/* Score gauge */}
        <div className="flex flex-col items-center justify-center bg-gray-900/60 border border-gray-800 rounded-2xl p-8">
          <ScoreGauge score={ts?.overall_score ?? null} size={200} />
          <p className="text-xs text-gray-500 mt-4 text-center">
            {ts?.risk_category && (
              <span className="uppercase tracking-widest font-semibold">{ts.risk_category}</span>
            )}
          </p>
        </div>

        {/* Signal cards */}
        <div className="lg:col-span-2 grid grid-cols-1 sm:grid-cols-2 gap-3">
          {signals.map(s => (
            <SignalCard key={s.title} title={s.title} score={s.score} evidence={s.evidence} />
          ))}
        </div>
      </div>

      {/* AI explanation */}
      {ts?.ai_explanation && (
        <div className="bg-gray-900/60 border border-gray-800 rounded-xl p-6 mb-8">
          <h3 className="text-sm font-semibold text-gray-300 uppercase tracking-wider mb-3">AI Explanation</h3>
          <p className="text-gray-300 text-sm leading-relaxed whitespace-pre-line">{ts.ai_explanation}</p>
        </div>
      )}

      {/* Pipeline steps */}
      {result.pipeline_steps && result.pipeline_steps.length > 0 && (
        <div className="mb-8">
          <PipelineSteps steps={result.pipeline_steps} />
        </div>
      )}

      {/* Deep Dive — full transparency panel */}
      {result.deep_dive && (
        <div className="mb-8">
          <DeepDive data={result.deep_dive} analysisId={result.analysis_id} />
        </div>
      )}

      {/* Explanation */}
      {ts?.explanation && (
        <div className="bg-gray-900/60 border border-gray-800 rounded-xl p-6 mb-8">
          <EvidenceTimeline signals={ts.explanation} />
        </div>
      )}

      {/* Metadata */}
      <div className="grid grid-cols-2 sm:grid-cols-4 gap-4 text-xs text-gray-500">
        {result.analysis_id && <Stat label="Analysis ID" value={result.analysis_id.slice(0, 8)} />}
        {ts && <Stat label="Risk Level" value={ts.risk_level} />}
        {ts && <Stat label="Confidence" value={`${Math.round(ts.confidence * 100)}%`} />}
        {result.submitted_at && <Stat label="Scanned" value={new Date(result.submitted_at).toLocaleString()} />}
      </div>
    </div>
  )
}

function Stat({ label, value }: { label: string; value: string }) {
  return (
    <div className="bg-gray-900/40 border border-gray-800 rounded-lg p-3">
      <p className="text-gray-500 mb-0.5">{label}</p>
      <p className="text-gray-300 font-medium truncate">{value}</p>
    </div>
  )
}

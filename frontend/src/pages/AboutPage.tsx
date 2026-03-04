import { Shield, Brain, Scale, Lock, Eye, Zap, BookOpen } from 'lucide-react'

const sections = [
  {
    icon: Scale,
    title: '70 / 30 Hybrid Scoring',
    body: `TrustLens uses a hard-coded 70 / 30 split: 70 % of the final trust score comes from deterministic, rule-based analysis (URL heuristics, brand impersonation detection, behavioral analysis, domain intelligence, security headers). The remaining 30 % comes from an AI advisory opinion — but only after passing through a 4-stage calibration pipeline that limits overconfidence.`,
  },
  {
    icon: Brain,
    title: 'AI as Advisor, Not Judge',
    body: `The AI model (Gemini, OpenAI, Anthropic, or Grok) reads extracted page content and provides a risk assessment. Its output is treated as one signal among many — never the final word. A raw 99 % AI confidence becomes ~18 % after calibration. This ensures no single model failure can dominate the score.`,
  },
  {
    icon: Lock,
    title: 'Anti-Hallucination Layers',
    body: `Five defense layers prevent AI fabrication: input sanitization and truncation, prompt fence markers with explicit rules, JSON schema validation on output, range clamping, evidence cross-referencing against observed facts, and consistency checking across signals. If the AI output is invalid, the system falls back to rules-only scoring.`,
  },
  {
    icon: Eye,
    title: 'Screenshot Similarity',
    body: `TrustLens takes a screenshot of the target page and compares it against a database of known legitimate sites using perceptual hashing (pHash). A high visual similarity to a brand like PayPal combined with a different domain triggers a supplementary -15 score penalty — catching sophisticated clone sites.`,
  },
  {
    icon: Zap,
    title: 'Zero-Day Suspicion',
    body: `For brand-new domains and pages with no reputation history, a composite anomaly score evaluates unusual patterns across multiple signals. This catches threats too new for any blocklist — without relying on known IOCs.`,
  },
  {
    icon: Shield,
    title: 'Full Transparency',
    body: `Every analysis includes a complete transparency report: rule breakdown, AI raw vs calibrated scores, calibration step trace, evidence list, which signals fired, and a human-readable explanation. Nothing is a black box.`,
  },
]

export default function AboutPage() {
  return (
    <div className="max-w-4xl mx-auto px-4 py-12 animate-fade-in">
      <div className="text-center mb-14">
        <h1 className="text-3xl font-bold text-white mb-3">How TrustLens AI Works</h1>
        <p className="text-gray-400 max-w-2xl mx-auto">
          An explainable, self-hostable URL trust engine that combines deterministic rules
          with AI reasoning — while keeping AI on a tight leash.
        </p>
      </div>

      <div className="space-y-6">
        {sections.map(({ icon: Icon, title, body }, i) => (
          <div
            key={title}
            className="bg-gray-900/60 border border-gray-800 rounded-xl p-6 flex gap-5 animate-fade-in hover:border-gray-700 transition"
            style={{ animationDelay: `${i * 80}ms` }}
          >
            <div className="flex-shrink-0 w-10 h-10 rounded-lg bg-sky-500/10 flex items-center justify-center mt-0.5">
              <Icon className="w-5 h-5 text-sky-400" />
            </div>
            <div>
              <h3 className="text-lg font-semibold text-white mb-2">{title}</h3>
              <p className="text-sm text-gray-400 leading-relaxed">{body}</p>
            </div>
          </div>
        ))}
      </div>

      {/* Documentation links */}
      <div className="mt-14 bg-gray-900/60 border border-gray-800 rounded-xl p-6">
        <h2 className="text-lg font-semibold text-white mb-4 flex items-center gap-2">
          <BookOpen className="w-5 h-5 text-sky-400" /> Documentation
        </h2>
        <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
          {[
            { label: 'Scoring Methodology', href: 'https://github.com/abhishekayu/TrustLens/blob/main/docs/scoring-methodology.md' },
            { label: 'AI Trust Explanation', href: 'https://github.com/abhishekayu/TrustLens/blob/main/docs/ai-trust-explanation.md' },
            { label: 'Security Model', href: 'https://github.com/abhishekayu/TrustLens/blob/main/docs/security-model.md' },
            { label: 'Anti-Hallucination', href: 'https://github.com/abhishekayu/TrustLens/blob/main/docs/anti-hallucination.md' },
          ].map(doc => (
            <a
              key={doc.label}
              href={doc.href}
              target="_blank"
              rel="noreferrer"
              className="flex items-center gap-2 px-4 py-3 rounded-lg border border-gray-700 hover:border-sky-500/40 hover:bg-sky-500/5 text-sm text-gray-300 hover:text-white transition"
            >
              <BookOpen className="w-4 h-4 text-gray-500" />
              {doc.label}
            </a>
          ))}
        </div>
      </div>

      <p className="text-center text-xs text-gray-600 mt-12">
        TrustLens AI is open-source under the MIT License.
      </p>
    </div>
  )
}

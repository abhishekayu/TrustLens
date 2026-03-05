import {
  Shield,
  Globe,
  Lock,
  Unlock,
  Brain,
  Fingerprint,
  AlertTriangle,
  CheckCircle2,
  XCircle,
  Clock,
  ExternalLink,
  Server,
  FileText,
  Bug,
  Users,
  ChevronDown,
  ChevronRight,
  Eye,
  Search,
  Info,
  CreditCard,
  Radar,
  Wallet,
  Camera,
  Image,
} from 'lucide-react'
import { useState } from 'react'
import type { DeepDiveData } from '../services/api'
import EvidenceTimeline from './EvidenceTimeline'

interface Props {
  data: DeepDiveData
  analysisId?: string
  evidenceSignals?: string | null
}

/* ─── Section Descriptions (info button content) ─────────────────────────── */

const SECTION_INFO: Record<string, string> = {
  'AI Deception Classifier': 'Uses a large language model (Gemini, OpenAI, etc.) to analyze page content for social engineering, impersonation, and deception patterns. AI contributes only 30% of the final score — rules always override.',
  'Brand Impersonation Analysis': 'Compares the domain name and page content against 20+ known brands using Levenshtein distance and keyword matching. Detects typosquatting and lookalike domains that imitate real brands.',
  'Browser Crawl & Page Info': 'A sandboxed Chromium browser visits the URL, captures HTTP status, forms, scripts, cookies, redirects, meta tags, and takes a screenshot. All data is extracted for the analysis engines.',
  'Domain Intelligence': 'Performs RDAP/WHOIS lookup for domain age, registrar, and registration dates. Checks for suspicious TLDs (e.g. .tk, .xyz). Younger domains score lower.',
  'Security Headers': 'Checks 7 security headers: HTTPS, HSTS, CSP, X-Frame-Options, X-Content-Type-Options, Referrer-Policy, and Permissions-Policy. Each header contributes to a 100-point security posture score.',
  'Payment Detection': 'Scans for payment forms, credit card fields, cryptocurrency wallet addresses, and payment gateway scripts (Stripe, PayPal, etc.). Flags suspicious payment patterns.',
  'Tracker & Malware Detection': 'Identifies analytics trackers, advertising pixels, fingerprinting scripts, crypto miners, spyware, and known malware domains in the page\'s scripts and resources.',
  'Download & Permission Threats': 'Detects dangerous file download links (.exe, .ps1, .apk), auto-download triggers, browser permission requests (camera, mic, clipboard), and notification spam patterns.',
  'Screenshot / Visual Clone Detection': 'Generates a perceptual hash (pHash/dHash) of the page screenshot and compares it against known brand screenshots to detect pixel-level visual clones used in phishing.',
  'Zero-Day Suspicion Scoring': 'Composite anomaly detection scoring language tricks (homoglyphs, invisible Unicode), structural obfuscation (eval, base64), behavioral anomalies (redirect chains), and domain novelty.',
  'Threat Intelligence Feed Lookup': 'Checks the URL against configured threat intelligence feeds and known malicious URL databases for previously reported threats.',
  'Community Consensus': 'Aggregates user-submitted reports (phishing, safe, scam) for this URL to build a crowd-sourced risk signal.',
  'Heuristic Rule Signals': 'Deterministic rules that check SSL usage, suspicious forms (password fields, cross-origin actions), URL patterns (IP hostnames, @ symbol), page content (urgency language, hidden iframes), redirects, and security headers.',
  'Behavioral Signals': 'Analyzes runtime behavior: JavaScript redirects, anti-analysis tricks (disabled right-click, F12 blocking), countdown timers, auto-submit forms, clipboard manipulation, and code obfuscation.',
  'Page Screenshot (Live Capture)': 'A live viewport screenshot captured by the sandboxed Chromium browser during crawl. Stored in-memory only — never saved to disk.',
}

/* ─── Small helpers ───────────────────────────────────────────────────────── */

function Badge({ children, variant = 'neutral' }: { children: React.ReactNode; variant?: 'good' | 'bad' | 'warn' | 'neutral' }) {
  const colors = {
    good: 'bg-[#00ff41]/8 text-[#00ff41] border-[#00ff41]/20',
    bad: 'bg-[#ff0040]/8 text-[#ff0040] border-[#ff0040]/20',
    warn: 'bg-[#ff8c00]/8 text-[#ff8c00] border-[#ff8c00]/20',
    neutral: 'bg-white/3 text-[#484f58] border-[#1b2838]',
  }
  return (
    <span className={`inline-flex items-center gap-1 px-2 py-0.5 rounded text-[10px] font-mono font-medium border ${colors[variant]}`}>
      {children}
    </span>
  )
}

function HeaderCheck({ label, ok }: { label: string; ok: boolean }) {
  return (
    <div className="flex items-center gap-2 font-mono text-[10px]">
      {ok ? <CheckCircle2 className="w-3 h-3 text-[#00ff41]" /> : <XCircle className="w-3 h-3 text-[#ff0040]" />}
      <span className={ok ? 'text-[#c9d1d9]' : 'text-[#ff0040]/80'}>{label}</span>
    </div>
  )
}

function Section({ title, icon: Icon, children, defaultOpen = true, statusBadge }: {
  title: string
  icon: React.ComponentType<{ className?: string }>
  children: React.ReactNode
  defaultOpen?: boolean
  statusBadge?: React.ReactNode
}) {
  const [open, setOpen] = useState(defaultOpen)
  const [showInfo, setShowInfo] = useState(false)
  const infoText = SECTION_INFO[title.replace(/\s*\(\d+\)$/, '')]  // strip "(N)" suffix for rule/behavioral counts
  return (
    <div className="terminal-card">
      <button
        onClick={() => setOpen(o => !o)}
        className="w-full flex items-center gap-3 px-4 py-2.5 hover:bg-white/[0.02] transition"
      >
        <Icon className="w-3.5 h-3.5 text-[#00ffff] shrink-0" />
        <span className="font-mono text-[10px] font-semibold text-[#c9d1d9] flex-1 text-left uppercase tracking-wider">{title}</span>
        {infoText && (
          <span
            role="button"
            onClick={e => { e.stopPropagation(); setShowInfo(s => !s) }}
            className="w-4 h-4 rounded-full border border-[#1b2838] bg-[#0a0e17] flex items-center justify-center hover:border-[#00ffff]/30 transition shrink-0 cursor-help"
            title="What is this?"
          >
            <Info className="w-2.5 h-2.5 text-[#484f58]" />
          </span>
        )}
        {statusBadge && <span className="mr-2">{statusBadge}</span>}
        {open ? <ChevronDown className="w-3.5 h-3.5 text-[#484f58]" /> : <ChevronRight className="w-3.5 h-3.5 text-[#484f58]" />}
      </button>
      {showInfo && infoText && (
        <div className="px-4 py-2.5 bg-[#00ffff]/[0.03] border-t border-[#00ffff]/10">
          <p className="font-mono text-[10px] text-[#00ffff]/70 leading-relaxed flex items-start gap-2">
            <Info className="w-3 h-3 mt-0.5 shrink-0 text-[#00ffff]/50" />
            {infoText}
          </p>
        </div>
      )}
      {open && <div className="p-4 space-y-2.5 border-t border-[#1b2838] bg-[#0a0e17]/40">{children}</div>}
    </div>
  )
}

function Row({ label, value, mono = false }: { label: string; value: React.ReactNode; mono?: boolean }) {
  return (
    <div className="flex items-start gap-3 font-mono text-[10px]">
      <span className="text-[#484f58] w-32 shrink-0 pt-0.5">{label}</span>
      <span className={`text-[#c9d1d9] flex-1 break-all ${mono ? '' : ''}`}>{value}</span>
    </div>
  )
}

function ScoreMeter({ score, max = 100, label }: { score: number; max?: number; label?: string }) {
  const pct = Math.round((score / max) * 100)
  const color = pct >= 75 ? 'bg-[#00ff41]' : pct >= 50 ? 'bg-[#ffff00]' : 'bg-[#ff0040]'
  const shadow = pct >= 75 ? 'shadow-[0_0_6px_rgba(0,255,65,0.3)]' : pct >= 50 ? 'shadow-[0_0_6px_rgba(255,255,0,0.3)]' : 'shadow-[0_0_6px_rgba(255,0,64,0.3)]'
  return (
    <div className="flex items-center gap-2 font-mono text-[10px]">
      {label && <span className="text-[#484f58] w-20 shrink-0">{label}</span>}
      <div className="flex-1 h-1 bg-[#1b2838] rounded-full overflow-hidden">
        <div className={`h-full ${color} ${shadow} rounded-full transition-all`} style={{ width: `${pct}%` }} />
      </div>
      <span className="text-[#484f58] text-[10px] w-12 text-right">{score.toFixed(0)}/{max}</span>
    </div>
  )
}

function EmptyState({ message }: { message: string }) {
  return (
    <div className="flex items-center gap-2 font-mono text-[10px] text-[#484f58] py-2">
      <Info className="w-3 h-3 shrink-0" />
      <span>{message}</span>
    </div>
  )
}

/* ─── Main Component ──────────────────────────────────────────────────────── */

export default function DeepDive({ data, evidenceSignals }: Props) {
  const [screenshotOpen, setScreenshotOpen] = useState(false)

  return (
    <div className="space-y-2.5">
      <h3 className="font-mono text-[10px] font-semibold text-[#484f58] uppercase tracking-widest mb-1 flex items-center gap-2">
        <span className="text-[#00ff41]/40">{'>'}</span>
        <Eye className="w-3.5 h-3.5 text-[#00ffff]" />
        Deep Dive — Full Transparency
      </h3>

      {/* ── Evidence Timeline ─────────────────────────────────── */}
      {evidenceSignals && (
        <div className="terminal-card">
          <div className="terminal-card-body">
            <EvidenceTimeline signals={evidenceSignals} />
          </div>
        </div>
      )}

      {/* ── Page Screenshot (in-memory, not stored) ───────────── */}
      {data.crawl?.screenshot_base64 && (
        <Section title="Page Screenshot (Live Capture)" icon={Camera} defaultOpen={true}>
          <div className="space-y-2">
            <p className="font-mono text-[10px] text-[#484f58]">
              Captured in-memory by sandboxed Chromium. Never saved to disk.
            </p>
            <div
              className="relative rounded overflow-hidden border border-[#1b2838] cursor-pointer group"
              onClick={() => setScreenshotOpen(!screenshotOpen)}
            >
              <img
                src={data.crawl.screenshot_base64}
                alt="Page screenshot captured during crawl"
                className={`w-full transition-all duration-300 ${screenshotOpen ? 'max-h-[800px]' : 'max-h-48'} object-cover object-top`}
              />
              {!screenshotOpen && (
                <div className="absolute inset-0 bg-gradient-to-b from-transparent via-transparent to-[#0a0e17]/90 flex items-end justify-center pb-3">
                  <span className="font-mono text-[10px] text-[#c9d1d9] flex items-center gap-1 bg-[#0d1117]/80 px-3 py-1.5 rounded border border-[#1b2838]">
                    <Image className="w-3 h-3 text-[#00ffff]" /> Click to expand
                  </span>
                </div>
              )}
            </div>
            {screenshotOpen && (
              <button
                onClick={() => setScreenshotOpen(false)}
                className="font-mono text-[10px] text-[#00ffff] hover:underline"
              >
                [ collapse ]
              </button>
            )}
          </div>
        </Section>
      )}

      {/* ── AI Deception Classifier ─────────────────────────── */}
      <Section
        title="AI Deception Classifier"
        icon={Brain}
        statusBadge={
          data.ai_analysis?.available
            ? <Badge variant="good">Active</Badge>
            : <Badge variant="warn">Unavailable</Badge>
        }
      >
        {data.ai_analysis ? (
          <>
            <div className="flex items-center gap-3 mb-3">
              <Badge variant={data.ai_analysis.available ? 'good' : 'warn'}>
                {data.ai_analysis.available ? 'Active' : 'Unavailable'}
              </Badge>
              <span className="font-mono text-[10px] text-[#484f58]">
                Provider: <span className="text-[#c9d1d9] font-semibold">{data.ai_analysis.provider.toUpperCase()}</span>
              </span>
              <span className="font-mono text-[10px] text-[#484f58]">
                Model: <span className="text-[#00ffff]">{data.ai_analysis.model}</span>
              </span>
            </div>

            {data.ai_analysis.available ? (
              <>
                <Row label="Intent" value={
                  <Badge variant={data.ai_analysis.intent === 'legitimate' ? 'good' : data.ai_analysis.intent === 'unknown' ? 'neutral' : 'bad'}>
                    {data.ai_analysis.intent}
                  </Badge>
                } />
                <Row label="Confidence" value={`${(data.ai_analysis.intent_confidence * 100).toFixed(0)}%`} />
                <ScoreMeter score={100 - data.ai_analysis.risk_score} label="Trust Score" />

                {data.ai_analysis.deception_indicators.length > 0 && (
                  <div className="mt-2">
                    <p className="text-[10px] text-[#484f58] mb-1">Deception Indicators:</p>
                    {data.ai_analysis.deception_indicators.map((d, i) => (
                      <div key={i} className="font-mono text-[10px] text-[#ff0040] flex items-start gap-1.5">
                        <XCircle className="w-3 h-3 mt-0.5 shrink-0" /> {d}
                      </div>
                    ))}
                  </div>
                )}

                {data.ai_analysis.legitimacy_indicators.length > 0 && (
                  <div className="mt-2">
                    <p className="text-[10px] text-[#484f58] mb-1">Legitimacy Indicators:</p>
                    {data.ai_analysis.legitimacy_indicators.map((l, i) => (
                      <div key={i} className="font-mono text-[10px] text-[#00ff41] flex items-start gap-1.5">
                        <CheckCircle2 className="w-3 h-3 mt-0.5 shrink-0" /> {l}
                      </div>
                    ))}
                  </div>
                )}

                {data.ai_analysis.social_engineering_tactics.length > 0 && (
                  <div className="mt-2">
                    <p className="text-[10px] text-[#484f58] mb-1">Social Engineering Tactics:</p>
                    {data.ai_analysis.social_engineering_tactics.map((t, i) => (
                      <div key={i} className="font-mono text-[10px] text-[#ffff00] flex items-start gap-1.5">
                        <AlertTriangle className="w-3 h-3 mt-0.5 shrink-0" /> {t}
                      </div>
                    ))}
                  </div>
                )}

                {data.ai_analysis.classifier && (
                  <div className="mt-3 pt-3 border-t border-[#1b2838]">
                    <p className="font-mono text-[10px] font-semibold text-[#484f58] mb-2">Classifier Breakdown</p>
                    <div className="space-y-1">
                      <ScoreMeter score={data.ai_analysis.classifier.impersonation * 100} label="Impersonation" />
                      <ScoreMeter score={data.ai_analysis.classifier.credential_harvesting * 100} label="Cred Harvest" />
                      <ScoreMeter score={data.ai_analysis.classifier.urgency_manipulation * 100} label="Urgency" />
                      <ScoreMeter score={data.ai_analysis.classifier.fear_tactics * 100} label="Fear" />
                      <ScoreMeter score={data.ai_analysis.classifier.payment_demand * 100} label="Payment" />
                      <ScoreMeter score={(data.ai_analysis.classifier.data_collection ?? 0) * 100} label="Data Collect" />
                      <ScoreMeter score={data.ai_analysis.classifier.deception_confidence * 100} label="Deception" />
                    </div>
                  </div>
                )}

                {/* URL Perspective */}
                {data.ai_analysis.url_perspective && (
                  <div className="mt-3 pt-3 border-t border-[#1b2838]">
                    <p className="font-mono text-[10px] font-semibold text-[#484f58] mb-2 flex items-center gap-1.5">
                      <Globe className="w-3.5 h-3.5 text-[#00ffff]" />
                      AI URL Perspective
                    </p>
                    <div className="space-y-2">
                      {data.ai_analysis.url_perspective.purpose && (
                        <Row label="Purpose" value={data.ai_analysis.url_perspective.purpose} />
                      )}
                      {data.ai_analysis.url_perspective.target_audience && (
                        <Row label="Target Audience" value={data.ai_analysis.url_perspective.target_audience} />
                      )}
                      {data.ai_analysis.url_perspective.content_category && (
                        <Row label="Content Category" value={
                          <Badge variant="neutral">{data.ai_analysis.url_perspective.content_category}</Badge>
                        } />
                      )}
                      {data.ai_analysis.url_perspective.technology_stack && data.ai_analysis.url_perspective.technology_stack.length > 0 && (
                        <Row label="Tech Stack" value={
                          <div className="flex flex-wrap gap-1">
                            {data.ai_analysis.url_perspective.technology_stack.map((t: string, i: number) => (
                              <Badge key={i} variant="neutral">{t}</Badge>
                            ))}
                          </div>
                        } />
                      )}
                      {data.ai_analysis.url_perspective.privacy_concerns && data.ai_analysis.url_perspective.privacy_concerns.length > 0 && (
                        <div className="mt-1">
                          <p className="text-[10px] text-[#484f58] mb-1">Privacy Concerns:</p>
                          {data.ai_analysis.url_perspective.privacy_concerns.map((c: string, i: number) => (
                            <div key={i} className="font-mono text-[10px] text-[#ffff00] flex items-start gap-1.5">
                              <AlertTriangle className="w-3 h-3 mt-0.5 shrink-0" /> {c}
                            </div>
                          ))}
                        </div>
                      )}
                      {data.ai_analysis.url_perspective.overall_assessment && (
                        <div className="mt-2 font-mono text-[10px] text-[#484f58] bg-[#0d1117] rounded-lg p-2 border border-[#1b2838]">
                          {data.ai_analysis.url_perspective.overall_assessment}
                        </div>
                      )}
                    </div>
                  </div>
                )}

                {data.ai_analysis.explanation && (
                  <div className="mt-3 font-mono text-[10px] text-[#484f58] whitespace-pre-line bg-[#0d1117] rounded-lg p-3 border border-[#1b2838]">
                    <p className="text-[10px] text-[#484f58] mb-1 font-semibold">AI Explanation:</p>
                    {data.ai_analysis.explanation}
                  </div>
                )}
              </>
            ) : (
              <div className="font-mono text-[10px] text-[#484f58] bg-[#0d1117] rounded-lg p-3 border border-[#1b2838]">
                AI classifier was unavailable for this analysis — trust score relies on rule-based heuristics only (70% weight).
                <br /><br />
                To enable AI analysis, ensure <span className="text-[#00ffff] font-semibold">{data.ai_analysis.provider}</span> (<span className="font-mono text-[#00ffff]">{data.ai_analysis.model}</span>) is running and accessible.
              </div>
            )}
          </>
        ) : (
          <EmptyState message="AI analysis configuration not available" />
        )}
      </Section>

      {/* ── Brand Impersonation ───────────────────────────────── */}
      <Section
        title="Brand Impersonation Analysis"
        icon={Fingerprint}
        statusBadge={
          data.brand_matches.length > 0
            ? data.brand_matches.some(bm => bm.impersonation_probability >= 0.6)
              ? <Badge variant="bad">Impersonation Detected</Badge>
              : data.brand_matches.some(bm => bm.is_official)
                ? <Badge variant="good">Official</Badge>
                : <Badge variant="good">Checked</Badge>
            : <Badge variant="neutral">No Matches</Badge>
        }
      >
        {data.brand_matches.length > 0 ? (
          data.brand_matches.map((bm, i) => (
            <div key={i} className={`p-3 rounded-lg border ${bm.is_official ? 'border-emerald-500/30 bg-[#00ff41]/5' : bm.impersonation_probability >= 0.6 ? 'border-red-500/30 bg-[#ff0040]/5' : 'border-[#1b2838] bg-[#0d1117]'}`}>
              <div className="flex items-center justify-between mb-2">
                <span className="font-mono text-[10px] font-semibold text-[#c9d1d9]">{bm.brand_name}</span>
                {bm.is_official ? (
                  <Badge variant="good">Official Domain</Badge>
                ) : bm.impersonation_probability >= 0.6 ? (
                  <Badge variant="bad">Likely Impersonation</Badge>
                ) : bm.domain_similarity >= 0.5 ? (
                  <Badge variant="warn">Suspicious</Badge>
                ) : (
                  <Badge variant="neutral">Low Risk</Badge>
                )}
              </div>
              {!bm.is_official && (
                <div className="space-y-1">
                  <ScoreMeter score={bm.domain_similarity * 100} label="Domain Sim" />
                  <ScoreMeter score={bm.content_similarity * 100} label="Content Sim" />
                  <ScoreMeter score={bm.impersonation_probability * 100} label="Impersonation" />
                  {bm.matched_features.length > 0 && (
                    <div className="flex flex-wrap gap-1 mt-2">
                      {bm.matched_features.map((f, j) => (
                        <Badge key={j} variant="warn">{f}</Badge>
                      ))}
                    </div>
                  )}
                </div>
              )}
            </div>
          ))
        ) : (
          <EmptyState message="No brand matches detected — page does not resemble any monitored brands" />
        )}
      </Section>

      {/* ── Browser Crawl & Page Info ─────────────────────────── */}
      <Section
        title="Browser Crawl & Page Info"
        icon={Globe}
        statusBadge={data.crawl ? <Badge variant="good">Completed</Badge> : <Badge variant="warn">No Data</Badge>}
      >
        {data.crawl ? (
          <>
            <Row label="Final URL" value={
              <a href={data.crawl.final_url} target="_blank" rel="noreferrer" className="text-[#00ffff] hover:underline inline-flex items-center gap-1">
                {data.crawl.final_url} <ExternalLink className="w-3 h-3" />
              </a>
            } />
            <Row label="HTTP Status" value={
              <Badge variant={data.crawl.status_code >= 200 && data.crawl.status_code < 400 ? 'good' : 'warn'}>
                {data.crawl.status_code}
              </Badge>
            } />
            <Row label="Load Time" value={`${data.crawl.load_time_ms} ms`} />
            <Row label="Page Title" value={data.crawl.page_title || '—'} />
            <Row label="Forms" value={data.crawl.forms_count.toString()} />
            <Row label="External Links" value={data.crawl.external_links_count.toString()} />
            <Row label="Scripts" value={data.crawl.scripts_count.toString()} />
            <Row label="Cookies" value={data.crawl.cookies_count.toString()} />

            {/* SSL Info */}
            {data.crawl.ssl_info && (
              <div className="mt-3 pt-3 border-t border-[#1b2838]">
                <p className="font-mono text-[10px] font-semibold text-[#484f58] mb-2 flex items-center gap-1.5">
                  {data.crawl.ssl_info.valid ? <Lock className="w-3.5 h-3.5 text-[#00ff41]" /> : <Unlock className="w-3.5 h-3.5 text-[#ff0040]" />}
                  SSL / TLS Certificate
                </p>
                <Row label="Protocol" value={String(data.crawl.ssl_info.protocol || '—')} mono />
                <Row label="Issuer" value={String(data.crawl.ssl_info.issuer || '—')} />
                <Row label="Subject" value={String(data.crawl.ssl_info.subject || '—')} />
                <Row label="Valid" value={
                  <Badge variant={data.crawl.ssl_info.valid ? 'good' : 'bad'}>
                    {data.crawl.ssl_info.valid ? 'Yes' : 'No'}
                  </Badge>
                } />
                {!!data.crawl.ssl_info.cert_error_ignored && (
                  <div className="mt-1 text-[10px] text-[#ffff00]">
                    ⚠ Certificate error was ignored during crawl (possible invalid cert)
                  </div>
                )}
              </div>
            )}

            {/* Redirect Chain */}
            {data.crawl.redirect_chain.length > 0 && (
              <div className="mt-3 pt-3 border-t border-[#1b2838]">
                <p className="font-mono text-[10px] font-semibold text-[#484f58] mb-2">Redirect Chain ({data.crawl.redirect_chain.length} hops)</p>
                <div className="space-y-1">
                  {data.crawl.redirect_chain.map((hop, i) => (
                    <div key={i} className="flex items-center gap-2 text-[10px] font-mono text-[#484f58]">
                      <Badge variant={hop.status_code >= 300 && hop.status_code < 400 ? 'warn' : 'neutral'}>{hop.status_code}</Badge>
                      <span className="truncate">{hop.url}</span>
                    </div>
                  ))}
                </div>
              </div>
            )}

            {/* Meta Tags */}
            {Object.keys(data.crawl.meta_tags).length > 0 && (
              <div className="mt-3 pt-3 border-t border-[#1b2838]">
                <p className="font-mono text-[10px] font-semibold text-[#484f58] mb-2">Meta Tags</p>
                <div className="space-y-1">
                  {Object.entries(data.crawl.meta_tags).slice(0, 10).map(([k, v]) => (
                    <Row key={k} label={k} value={v.slice(0, 120)} />
                  ))}
                </div>
              </div>
            )}

            {data.crawl.errors.length > 0 && (
              <div className="mt-2 font-mono text-[10px] text-[#ff0040]">
                Errors: {data.crawl.errors.join('; ')}
              </div>
            )}
          </>
        ) : (
          <EmptyState message="Crawl data not yet available" />
        )}
      </Section>

      {/* ── Domain Intelligence ───────────────────────────────── */}
      <Section
        title="Domain Intelligence"
        icon={Server}
        statusBadge={data.domain_intel ? <Badge variant="good">Analyzed</Badge> : <Badge variant="neutral">N/A</Badge>}
      >
        {data.domain_intel ? (
          <>
            <Row label="Domain" value={data.domain_intel.domain} mono />
            <Row label="Registered Domain" value={data.domain_intel.registered_domain} mono />
            <Row label="TLD" value={
              <span className="flex items-center gap-2">
                .{data.domain_intel.tld}
                {data.domain_intel.is_suspicious_tld && <Badge variant="bad">Suspicious TLD</Badge>}
              </span>
            } />
            <Row label="Domain Age" value={
              data.domain_intel.domain_age_days !== null
                ? `${data.domain_intel.domain_age_days} days (${Math.round(data.domain_intel.domain_age_days / 365 * 10) / 10} years)`
                : 'Unknown'
            } />
            <Row label="Registrar" value={data.domain_intel.registrar || 'Unknown'} />
            <Row label="Registered" value={data.domain_intel.registration_date || 'Unknown'} />
            <Row label="Expires" value={data.domain_intel.expiration_date || 'Unknown'} />

            <div className="mt-2 space-y-1">
              <ScoreMeter score={data.domain_intel.age_score} label="Age Score" />
              <ScoreMeter score={data.domain_intel.tld_score} label="TLD Score" />
              <ScoreMeter score={data.domain_intel.domain_score} label="Overall" />
            </div>

            {/* DNS Records */}
            {Object.keys(data.domain_intel.dns_records).length > 0 && (
              <div className="mt-3 pt-3 border-t border-[#1b2838]">
                <p className="font-mono text-[10px] font-semibold text-[#484f58] mb-2">DNS Records</p>
                {Object.entries(data.domain_intel.dns_records).map(([type, records]) => (
                  <Row key={type} label={type} value={records.length > 0 ? records.join(', ') : '—'} mono />
                ))}
              </div>
            )}

            {data.domain_intel.signals.length > 0 && (
              <div className="mt-3 pt-3 border-t border-[#1b2838] space-y-1">
                {data.domain_intel.signals.map((s, i) => (
                  <div key={i} className="flex items-start gap-2 font-mono text-[10px] text-[#ffff00]">
                    <AlertTriangle className="w-3.5 h-3.5 mt-0.5 shrink-0" />
                    {s}
                  </div>
                ))}
              </div>
            )}
          </>
        ) : (
          <EmptyState message="Domain intelligence was not performed for this analysis" />
        )}
      </Section>

      {/* ── Security Headers ──────────────────────────────────── */}
      <Section
        title="Security Headers"
        icon={Shield}
        statusBadge={
          data.security_headers
            ? <Badge variant={data.security_headers.header_score >= 70 ? 'good' : data.security_headers.header_score >= 40 ? 'warn' : 'bad'}>
                Score: {data.security_headers.header_score.toFixed(0)}
              </Badge>
            : <Badge variant="neutral">N/A</Badge>
        }
      >
        {data.security_headers ? (
          <>
            <div className="grid grid-cols-2 gap-2">
              <HeaderCheck label="HTTPS" ok={data.security_headers.is_https} />
              <HeaderCheck label="HSTS" ok={data.security_headers.has_hsts} />
              <HeaderCheck label="CSP" ok={data.security_headers.has_csp} />
              <HeaderCheck label="X-Frame-Options" ok={data.security_headers.has_x_frame_options} />
              <HeaderCheck label="X-Content-Type-Options" ok={data.security_headers.has_x_content_type_options} />
              <HeaderCheck label="Referrer-Policy" ok={data.security_headers.has_referrer_policy} />
              <HeaderCheck label="Permissions-Policy" ok={data.security_headers.has_permissions_policy} />
            </div>
            <ScoreMeter score={data.security_headers.header_score} label="Score" />
            {data.security_headers.missing_headers.length > 0 && (
              <div className="font-mono text-[10px] text-[#ffff00] mt-1">
                Missing: {data.security_headers.missing_headers.join(', ')}
              </div>
            )}
          </>
        ) : (
          <EmptyState message="Security headers were not analyzed" />
        )}
      </Section>

      {/* ── Payment Detection ─────────────────────────────────── */}
      <Section
        title="Payment Detection"
        icon={CreditCard}
        defaultOpen={data.payment_detection?.has_payment_form ?? false}
        statusBadge={
          data.payment_detection
            ? data.payment_detection.has_payment_form
              ? <Badge variant={data.payment_detection.risk_level === 'high' || data.payment_detection.risk_level === 'critical' ? 'bad' : data.payment_detection.risk_level === 'medium' ? 'warn' : 'good'}>
                  {data.payment_detection.risk_level.toUpperCase()}
                </Badge>
              : <Badge variant="good">No Payment Forms</Badge>
            : <Badge variant="neutral">N/A</Badge>
        }
      >
        {data.payment_detection ? (
          <>
            <Row label="Payment Form" value={
              <Badge variant={data.payment_detection.has_payment_form ? 'warn' : 'good'}>
                {data.payment_detection.has_payment_form ? 'Detected' : 'None'}
              </Badge>
            } />
            <ScoreMeter score={data.payment_detection.payment_security_score} label="Security" />
            <Row label="Risk Level" value={
              <Badge variant={data.payment_detection.risk_level === 'high' || data.payment_detection.risk_level === 'critical' ? 'bad' : data.payment_detection.risk_level === 'medium' ? 'warn' : 'good'}>
                {data.payment_detection.risk_level}
              </Badge>
            } />

            {data.payment_detection.payment_gateways_detected.length > 0 && (
              <div className="mt-2">
                <p className="text-[10px] text-[#484f58] mb-1">Payment Gateways Detected:</p>
                <div className="flex flex-wrap gap-1">
                  {data.payment_detection.payment_gateways_detected.map((g: string, i: number) => (
                    <Badge key={i} variant="neutral">{g}</Badge>
                  ))}
                </div>
              </div>
            )}

            {data.payment_detection.payment_form_fields.length > 0 && (
              <div className="mt-2">
                <p className="text-[10px] text-[#484f58] mb-1">Payment Form Fields:</p>
                <div className="flex flex-wrap gap-1">
                  {data.payment_detection.payment_form_fields.map((f: string, i: number) => (
                    <Badge key={i} variant="warn">{f}</Badge>
                  ))}
                </div>
              </div>
            )}

            {data.payment_detection.crypto_addresses.length > 0 && (
              <div className="mt-2">
                <p className="text-[10px] text-[#484f58] mb-1">Cryptocurrency Addresses:</p>
                {data.payment_detection.crypto_addresses.map((addr, i) => (
                  <div key={i} className="font-mono text-[10px] text-[#ff0040] flex items-start gap-1.5">
                    <Wallet className="w-3 h-3 mt-0.5 shrink-0" />
                    <span className="text-[#ffff00]">[{addr.type}]</span> {addr.address}
                  </div>
                ))}
              </div>
            )}

            {data.payment_detection.suspicious_payment_patterns.length > 0 && (
              <div className="mt-2">
                <p className="text-[10px] text-[#484f58] mb-1">Suspicious Patterns:</p>
                {data.payment_detection.suspicious_payment_patterns.map((p: string, i: number) => (
                  <div key={i} className="font-mono text-[10px] text-[#ff0040] flex items-start gap-1.5">
                    <AlertTriangle className="w-3 h-3 mt-0.5 shrink-0" /> {p}
                  </div>
                ))}
              </div>
            )}

            {data.payment_detection.legitimate_payment_indicators.length > 0 && (
              <div className="mt-2">
                <p className="text-[10px] text-[#484f58] mb-1">Legitimate Indicators:</p>
                {data.payment_detection.legitimate_payment_indicators.map((l: string, i: number) => (
                  <div key={i} className="font-mono text-[10px] text-[#00ff41] flex items-start gap-1.5">
                    <CheckCircle2 className="w-3 h-3 mt-0.5 shrink-0" /> {l}
                  </div>
                ))}
              </div>
            )}

            {data.payment_detection.signals && data.payment_detection.signals.length > 0 && (
              <div className="mt-3 pt-3 border-t border-[#1b2838] space-y-1">
                {data.payment_detection.signals.map((s: string, i: number) => (
                  <div key={i} className="font-mono text-[10px] text-[#484f58] flex items-start gap-1.5">
                    <Info className="w-3 h-3 mt-0.5 shrink-0 text-[#484f58]" /> {s}
                  </div>
                ))}
              </div>
            )}
          </>
        ) : (
          <EmptyState message="Payment detection was not performed for this analysis" />
        )}
      </Section>

      {/* ── Tracker & Malware Detection ───────────────────────── */}
      <Section
        title="Tracker & Malware Detection"
        icon={Radar}
        defaultOpen={(data.tracker_detection?.total_trackers ?? 0) > 0}
        statusBadge={
          data.tracker_detection
            ? data.tracker_detection.total_trackers > 0
              ? <Badge variant={data.tracker_detection.risk_level === 'high' || data.tracker_detection.risk_level === 'critical' ? 'bad' : data.tracker_detection.risk_level === 'medium' ? 'warn' : 'good'}>
                  {data.tracker_detection.total_trackers} Found
                </Badge>
              : <Badge variant="good">Clean</Badge>
            : <Badge variant="neutral">N/A</Badge>
        }
      >
        {data.tracker_detection ? (
          <>
            <Row label="Total Trackers" value={data.tracker_detection.total_trackers.toString()} />
            <ScoreMeter score={data.tracker_detection.privacy_score} label="Privacy" />
            <Row label="Risk Level" value={
              <Badge variant={data.tracker_detection.risk_level === 'high' || data.tracker_detection.risk_level === 'critical' ? 'bad' : data.tracker_detection.risk_level === 'medium' ? 'warn' : 'good'}>
                {data.tracker_detection.risk_level}
              </Badge>
            } />

            {/* Category Breakdown */}
            <div className="mt-3 pt-3 border-t border-[#1b2838]">
              <p className="font-mono text-[10px] font-semibold text-[#484f58] mb-2">Category Breakdown</p>
              <div className="grid grid-cols-2 gap-2">
                <div className="flex items-center gap-2 font-mono text-[10px]">
                  <span className="text-[#484f58] w-20">Analytics</span>
                  <Badge variant={(data.tracker_detection.analytics_trackers?.length ?? 0) > 0 ? 'warn' : 'good'}>
                    {data.tracker_detection.analytics_trackers?.length ?? 0}
                  </Badge>
                </div>
                <div className="flex items-center gap-2 font-mono text-[10px]">
                  <span className="text-[#484f58] w-20">Advertising</span>
                  <Badge variant={(data.tracker_detection.advertising_trackers?.length ?? 0) > 0 ? 'warn' : 'good'}>
                    {data.tracker_detection.advertising_trackers?.length ?? 0}
                  </Badge>
                </div>
                <div className="flex items-center gap-2 font-mono text-[10px]">
                  <span className="text-[#484f58] w-20">Fingerprint</span>
                  <Badge variant={(data.tracker_detection.fingerprinting_scripts?.length ?? 0) > 0 ? 'bad' : 'good'}>
                    {data.tracker_detection.fingerprinting_scripts?.length ?? 0}
                  </Badge>
                </div>
                <div className="flex items-center gap-2 font-mono text-[10px]">
                  <span className="text-[#484f58] w-20">Malware</span>
                  <Badge variant={(data.tracker_detection.malware_scripts?.length ?? 0) > 0 ? 'bad' : 'good'}>
                    {data.tracker_detection.malware_scripts?.length ?? 0}
                  </Badge>
                </div>
                <div className="flex items-center gap-2 font-mono text-[10px]">
                  <span className="text-[#484f58] w-20">Mining</span>
                  <Badge variant={(data.tracker_detection.mining_scripts?.length ?? 0) > 0 ? 'bad' : 'good'}>
                    {data.tracker_detection.mining_scripts?.length ?? 0}
                  </Badge>
                </div>
                <div className="flex items-center gap-2 font-mono text-[10px]">
                  <span className="text-[#484f58] w-20">Spyware</span>
                  <Badge variant={(data.tracker_detection.known_spyware?.length ?? 0) > 0 ? 'bad' : 'good'}>
                    {data.tracker_detection.known_spyware?.length ?? 0}
                  </Badge>
                </div>
              </div>
            </div>

            {/* Suspicious Scripts */}
            {(data.tracker_detection.suspicious_scripts?.length ?? 0) > 0 && (
              <div className="mt-2">
                <Row label="Suspicious Scripts" value={
                  <Badge variant="bad">{data.tracker_detection.suspicious_scripts?.length ?? 0}</Badge>
                } />
              </div>
            )}

            {/* Detailed Tracker List */}
            {data.tracker_detection.trackers && data.tracker_detection.trackers.length > 0 && (
              <div className="mt-3 pt-3 border-t border-[#1b2838]">
                <p className="font-mono text-[10px] font-semibold text-[#484f58] mb-2">Detected Trackers</p>
                <div className="space-y-2 max-h-64 overflow-y-auto">
                  {data.tracker_detection.trackers.map((t, i) => (
                    <div key={i} className="p-2 rounded-lg bg-[#0d1117] border border-[#1b2838]">
                      <div className="flex items-center justify-between mb-1">
                        <span className="font-mono text-[10px] font-semibold text-[#c9d1d9]">{t.name}</span>
                        <div className="flex items-center gap-1">
                          <Badge variant="neutral">{t.category}</Badge>
                          <Badge variant={t.severity === 'high' || t.severity === 'critical' ? 'bad' : t.severity === 'medium' ? 'warn' : 'neutral'}>
                            {t.severity}
                          </Badge>
                        </div>
                      </div>
                      {t.description && <p className="text-[10px] text-[#484f58]">{t.description}</p>}
                      {t.url && <p className="text-[10px] text-[#484f58] font-mono truncate mt-0.5">{t.url}</p>}
                    </div>
                  ))}
                </div>
              </div>
            )}

            {data.tracker_detection.signals && data.tracker_detection.signals.length > 0 && (
              <div className="mt-3 pt-3 border-t border-[#1b2838] space-y-1">
                {data.tracker_detection.signals.map((s: string, i: number) => (
                  <div key={i} className="font-mono text-[10px] text-[#484f58] flex items-start gap-1.5">
                    <Info className="w-3 h-3 mt-0.5 shrink-0 text-[#484f58]" /> {s}
                  </div>
                ))}
              </div>
            )}
          </>
        ) : (
          <EmptyState message="Tracker and malware detection was not performed for this analysis" />
        )}
      </Section>

      {/* ── Download & Permission Threat Detection ────────────── */}
      <Section
        title="Download & Permission Threats"
        icon={Shield}
        defaultOpen={
          (data.download_threat?.has_auto_download ?? false) ||
          (data.download_threat?.dangerous_file_types?.length ?? 0) > 0 ||
          (data.download_threat?.permissions_requested?.length ?? 0) > 0
        }
        statusBadge={
          data.download_threat
            ? data.download_threat.risk_level === 'critical' || data.download_threat.risk_level === 'high'
              ? <Badge variant="bad">{data.download_threat.risk_level.toUpperCase()}</Badge>
              : data.download_threat.risk_level === 'medium'
                ? <Badge variant="warn">MEDIUM</Badge>
                : <Badge variant="good">Safe</Badge>
            : <Badge variant="neutral">N/A</Badge>
        }
      >
        {data.download_threat ? (
          <>
            <Row label="Auto-Download" value={
              <Badge variant={data.download_threat.has_auto_download ? 'bad' : 'good'}>
                {data.download_threat.has_auto_download ? 'DETECTED' : 'None'}
              </Badge>
            } />
            <ScoreMeter score={data.download_threat.safety_score} label="Safety" />
            <Row label="Risk Level" value={
              <Badge variant={data.download_threat.risk_level === 'high' || data.download_threat.risk_level === 'critical' ? 'bad' : data.download_threat.risk_level === 'medium' ? 'warn' : 'good'}>
                {data.download_threat.risk_level}
              </Badge>
            } />

            {/* Dangerous File Types */}
            {data.download_threat.dangerous_file_types.length > 0 && (
              <div className="mt-2">
                <p className="text-[10px] text-[#484f58] mb-1">Dangerous File Types Found:</p>
                <div className="flex flex-wrap gap-1">
                  {data.download_threat.dangerous_file_types.map((f: string, i: number) => (
                    <Badge key={i} variant={f.includes('HIGH') ? 'bad' : 'warn'}>{f}</Badge>
                  ))}
                </div>
              </div>
            )}

            {/* Download Links */}
            {data.download_threat.download_links.length > 0 && (
              <div className="mt-2">
                <p className="text-[10px] text-[#484f58] mb-1">Download Links Detected:</p>
                {data.download_threat.download_links.map((link: string, i: number) => (
                  <div key={i} className="font-mono text-[10px] text-[#ff0040] truncate flex items-start gap-1.5">
                    <AlertTriangle className="w-3 h-3 mt-0.5 shrink-0" /> {link}
                  </div>
                ))}
              </div>
            )}

            {/* Auto-Download Triggers */}
            {data.download_threat.auto_download_triggers.length > 0 && (
              <div className="mt-2">
                <p className="text-[10px] text-[#484f58] mb-1">Auto-Download Triggers:</p>
                {data.download_threat.auto_download_triggers.map((t: string, i: number) => (
                  <div key={i} className="font-mono text-[10px] text-[#ff0040] flex items-start gap-1.5">
                    <AlertTriangle className="w-3 h-3 mt-0.5 shrink-0" /> {t}
                  </div>
                ))}
              </div>
            )}

            {/* Permissions Requested */}
            {data.download_threat.permissions_requested.length > 0 && (
              <div className="mt-3 pt-3 border-t border-[#1b2838]">
                <p className="font-mono text-[10px] font-semibold text-[#484f58] mb-2">Browser Permissions Requested</p>
                <div className="space-y-1.5">
                  {data.download_threat.permission_details.map((p, i) => (
                    <div key={i} className="flex items-center justify-between font-mono text-[10px]">
                      <span className="text-[#c9d1d9] flex items-center gap-1.5">
                        <Lock className="w-3 h-3" /> {p.label}
                      </span>
                      <Badge variant={p.risk === 'high' ? 'bad' : p.risk === 'medium' ? 'warn' : 'neutral'}>
                        {p.risk}
                      </Badge>
                    </div>
                  ))}
                </div>
              </div>
            )}

            {/* Notification Spam */}
            {data.download_threat.notification_spam_detected && (
              <div className="mt-2">
                <Row label="Notification Spam" value={
                  <Badge variant="bad">DETECTED</Badge>
                } />
              </div>
            )}

            {/* PUP Indicators */}
            {data.download_threat.pup_indicators.length > 0 && (
              <div className="mt-2">
                <p className="text-[10px] text-[#484f58] mb-1">Potentially Unwanted Program (PUP) Indicators:</p>
                <div className="flex flex-wrap gap-1">
                  {data.download_threat.pup_indicators.map((p: string, i: number) => (
                    <Badge key={i} variant="warn">{p}</Badge>
                  ))}
                </div>
              </div>
            )}

            {data.download_threat.signals && data.download_threat.signals.length > 0 && (
              <div className="mt-3 pt-3 border-t border-[#1b2838] space-y-1">
                {data.download_threat.signals.map((s: string, i: number) => (
                  <div key={i} className="font-mono text-[10px] text-[#484f58] flex items-start gap-1.5">
                    <Info className="w-3 h-3 mt-0.5 shrink-0 text-[#484f58]" /> {s}
                  </div>
                ))}
              </div>
            )}
          </>
        ) : (
          <EmptyState message="Download & permission threat detection was not performed for this analysis" />
        )}
      </Section>

      {/* ── Screenshot Similarity ─────────────────────────────── */}
      <Section
        title="Screenshot / Visual Clone Detection"
        icon={Search}
        defaultOpen={data.screenshot_similarity?.is_visual_clone ?? false}
        statusBadge={
          data.screenshot_similarity
            ? data.screenshot_similarity.is_visual_clone
              ? <Badge variant="bad">Clone Detected!</Badge>
              : <Badge variant="good">No Clone</Badge>
            : <Badge variant="neutral">N/A</Badge>
        }
      >
        {data.screenshot_similarity ? (
          <>
            <Row label="Visual Clone" value={
              <Badge variant={data.screenshot_similarity.is_visual_clone ? 'bad' : 'good'}>
                {data.screenshot_similarity.is_visual_clone ? 'YES — Visual Clone Detected' : 'No clone detected'}
              </Badge>
            } />
            {data.screenshot_similarity.closest_brand && (
              <Row label="Closest Brand" value={data.screenshot_similarity.closest_brand} />
            )}
            <ScoreMeter score={data.screenshot_similarity.similarity_score * 100} label="Similarity" />
            {data.screenshot_similarity.phash && (
              <Row label="pHash" value={data.screenshot_similarity.phash} mono />
            )}
            {data.screenshot_similarity.dhash && (
              <Row label="dHash" value={data.screenshot_similarity.dhash} mono />
            )}
            {data.screenshot_similarity.matched_screenshots.length > 0 && (
              <div className="mt-2">
                <p className="text-[10px] text-[#484f58] mb-1">Matched Screenshots:</p>
                {data.screenshot_similarity.matched_screenshots.map((m, i) => (
                  <div key={i} className="font-mono text-[10px] text-[#ffff00]">{m}</div>
                ))}
              </div>
            )}
            {data.screenshot_similarity.signals.length > 0 && (
              <div className="mt-2 space-y-1">
                {data.screenshot_similarity.signals.map((s, i) => (
                  <div key={i} className="font-mono text-[10px] text-[#484f58] flex items-start gap-1.5">
                    <Info className="w-3 h-3 mt-0.5 shrink-0 text-[#484f58]" /> {s}
                  </div>
                ))}
              </div>
            )}

          </>
        ) : (
          <div className="space-y-2">
            <EmptyState message="Screenshot similarity analysis was not performed. This requires the Pillow and imagehash Python packages." />
            <div className="text-[10px] text-[#484f58] bg-[#0d1117] rounded-lg p-2 font-mono border border-[#1b2838]">
              pip install Pillow imagehash
            </div>
          </div>
        )}
      </Section>

      {/* ── Zero-Day ──────────────────────────────────────────── */}
      <Section
        title="Zero-Day Suspicion Scoring"
        icon={Bug}
        defaultOpen={data.zeroday_suspicion?.is_potential_zeroday ?? false}
        statusBadge={
          data.zeroday_suspicion
            ? data.zeroday_suspicion.is_potential_zeroday
              ? <Badge variant="bad">Potential Zero-Day!</Badge>
              : <Badge variant="good">Score: {data.zeroday_suspicion.suspicion_score.toFixed(0)}/100</Badge>
            : <Badge variant="neutral">N/A</Badge>
        }
      >
        {data.zeroday_suspicion ? (
          <>
            <Row label="Suspicion Score" value={`${data.zeroday_suspicion.suspicion_score.toFixed(1)} / 100`} />
            <Row label="Potential Zero-Day" value={
              <Badge variant={data.zeroday_suspicion.is_potential_zeroday ? 'bad' : 'good'}>
                {data.zeroday_suspicion.is_potential_zeroday ? 'YES' : 'No'}
              </Badge>
            } />

            <div className="mt-2 space-y-1">
              <ScoreMeter score={(data.zeroday_suspicion.language_anomaly_score ?? 0) * 100} label="Language" />
              <ScoreMeter score={(data.zeroday_suspicion.structural_anomaly_score ?? 0) * 100} label="Structure" />
              <ScoreMeter score={(data.zeroday_suspicion.behavioral_anomaly_score ?? 0) * 100} label="Behavioral" />
              <ScoreMeter score={(data.zeroday_suspicion.domain_novelty_score ?? 0) * 100} label="Novelty" />
            </div>

            {data.zeroday_suspicion.anomaly_signals.length > 0 && (
              <div className="mt-3 pt-3 border-t border-[#1b2838] space-y-1">
                <p className="text-[10px] text-[#484f58] mb-1">Anomaly Signals:</p>
                {data.zeroday_suspicion.anomaly_signals.map((s, i) => (
                  <div key={i} className="font-mono text-[10px] text-[#ffff00] flex items-start gap-1.5">
                    <AlertTriangle className="w-3 h-3 mt-0.5 shrink-0" /> {s}
                  </div>
                ))}
              </div>
            )}
          </>
        ) : (
          <EmptyState message="Zero-day suspicion analysis was not performed" />
        )}
      </Section>

      {/* ── Threat Intel ──────────────────────────────────────── */}
      <Section
        title="Threat Intelligence Feed Lookup"
        icon={AlertTriangle}
        defaultOpen={data.threat_intel?.is_known_threat ?? false}
        statusBadge={
          data.threat_intel
            ? data.threat_intel.is_known_threat
              ? <Badge variant="bad">Known Threat!</Badge>
              : <Badge variant="good">Clean</Badge>
            : <Badge variant="neutral">Checked</Badge>
        }
      >
        {data.threat_intel ? (
          <>
            <Row label="Known Threat" value={
              <Badge variant={data.threat_intel.is_known_threat ? 'bad' : 'good'}>
                {data.threat_intel.is_known_threat ? `YES — found in ${data.threat_intel.feed_count} feeds` : 'Not found in any threat feeds'}
              </Badge>
            } />
            {data.threat_intel.highest_confidence > 0 && (
              <Row label="Highest Confidence" value={`${(data.threat_intel.highest_confidence * 100).toFixed(0)}%`} />
            )}
            {data.threat_intel.threat_types.length > 0 && (
              <Row label="Threat Types" value={
                <div className="flex flex-wrap gap-1">
                  {data.threat_intel.threat_types.map((t, i) => (
                    <Badge key={i} variant="bad">{t}</Badge>
                  ))}
                </div>
              } />
            )}
            {data.threat_intel.signals.length > 0 && (
              <div className="mt-2 space-y-1">
                {data.threat_intel.signals.map((s, i) => (
                  <div key={i} className="font-mono text-[10px] text-[#484f58] flex items-start gap-1.5">
                    <Info className="w-3 h-3 mt-0.5 shrink-0 text-[#484f58]" /> {s}
                  </div>
                ))}
              </div>
            )}
          </>
        ) : (
          <EmptyState message="URL was looked up against threat intelligence feeds — no matches found. Configure threat feeds in .env to expand coverage." />
        )}
      </Section>

      {/* ── Community ─────────────────────────────────────────── */}
      <Section
        title="Community Consensus"
        icon={Users}
        defaultOpen={(data.community_consensus?.total_reports ?? 0) > 0}
        statusBadge={
          data.community_consensus
            ? data.community_consensus.total_reports > 0
              ? <Badge variant="warn">{data.community_consensus.total_reports} Reports</Badge>
              : <Badge variant="good">No Reports</Badge>
            : <Badge variant="neutral">Checked</Badge>
        }
      >
        {data.community_consensus ? (
          <>
            <Row label="Total Reports" value={data.community_consensus.total_reports.toString()} />
            <ScoreMeter score={data.community_consensus.crowd_risk_score} label="Crowd Risk" />
            {data.community_consensus.total_reports > 0 && (
              <>
                <Row label="Phishing Reports" value={(data.community_consensus.phishing_reports ?? 0).toString()} />
                <Row label="Safe Reports" value={(data.community_consensus.safe_reports ?? 0).toString()} />
                <Row label="Scam Reports" value={(data.community_consensus.scam_reports ?? 0).toString()} />
                <Row label="Confidence" value={`${((data.community_consensus.consensus_confidence ?? 0) * 100).toFixed(0)}%`} />
              </>
            )}
          </>
        ) : (
          <EmptyState message="Community consensus data was collected — no reports exist for this URL yet. Users can submit reports via the community API." />
        )}
      </Section>

      {/* ── Rule Signals ──────────────────────────────────────── */}
      <Section
        title={`Heuristic Rule Signals (${data.rule_signals.length})`}
        icon={FileText}
        statusBadge={
          data.rule_signals.length > 0
            ? <Badge variant={data.rule_signals.some(r => r.severity === 'high' || r.severity === 'critical') ? 'bad' : 'warn'}>
                {data.rule_signals.length} signals
              </Badge>
            : <Badge variant="good">Clean</Badge>
        }
      >
        {data.rule_signals.length > 0 ? (
          <div className="space-y-2">
            {data.rule_signals.map((rs, i) => (
              <div key={i} className="p-2 rounded-lg bg-[#0d1117] border border-[#1b2838]">
                <div className="flex items-center justify-between mb-1">
                  <span className="font-mono text-[10px] font-semibold text-[#c9d1d9]">{rs.rule_name}</span>
                  <Badge variant={rs.severity === 'high' || rs.severity === 'critical' ? 'bad' : rs.severity === 'medium' ? 'warn' : 'neutral'}>
                    {rs.severity}
                  </Badge>
                </div>
                <p className="text-[10px] text-[#484f58]">{rs.description}</p>
                {rs.evidence && <p className="text-[10px] text-[#484f58] mt-0.5 font-mono">{rs.evidence}</p>}
                <p className="text-[10px] text-[#ff0040] mt-0.5">Impact: -{rs.score_impact} points</p>
              </div>
            ))}
          </div>
        ) : (
          <EmptyState message="No heuristic rule violations detected — all checks passed" />
        )}
      </Section>

      {/* ── Behavioral Signals ────────────────────────────────── */}
      <Section
        title={`Behavioral Signals (${data.behavioral_signals.length})`}
        icon={Clock}
        statusBadge={
          data.behavioral_signals.length > 0
            ? <Badge variant="warn">{data.behavioral_signals.length} signals</Badge>
            : <Badge variant="good">Clean</Badge>
        }
      >
        {data.behavioral_signals.length > 0 ? (
          <div className="space-y-2">
            {data.behavioral_signals.map((bs, i) => (
              <div key={i} className="p-2 rounded-lg bg-[#0d1117] border border-[#1b2838]">
                <div className="flex items-center justify-between mb-1">
                  <span className="font-mono text-[10px] font-semibold text-[#c9d1d9]">{bs.signal_type}</span>
                  <Badge variant={bs.severity === 'high' || bs.severity === 'critical' ? 'bad' : 'warn'}>{bs.severity}</Badge>
                </div>
                <p className="text-[10px] text-[#484f58]">{bs.description}</p>
                {bs.evidence && <p className="text-[10px] text-[#484f58] mt-0.5 font-mono">{bs.evidence}</p>}
              </div>
            ))}
          </div>
        ) : (
          <EmptyState message="No suspicious behavioral patterns detected (redirects, popups, etc.)" />
        )}
      </Section>
    </div>
  )
}

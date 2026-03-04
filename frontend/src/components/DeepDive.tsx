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
  Camera,
  ChevronDown,
  ChevronRight,
  Eye,
  Search,
  Info,
  Image,
} from 'lucide-react'
import { useState } from 'react'
import type { DeepDiveData } from '../services/api'

interface Props {
  data: DeepDiveData
  analysisId?: string
}

/* ─── Small helpers ───────────────────────────────────────────────────────── */

function Badge({ children, variant = 'neutral' }: { children: React.ReactNode; variant?: 'good' | 'bad' | 'warn' | 'neutral' }) {
  const colors = {
    good: 'bg-emerald-500/10 text-emerald-400 border-emerald-500/20',
    bad: 'bg-red-500/10 text-red-400 border-red-500/20',
    warn: 'bg-amber-500/10 text-amber-400 border-amber-500/20',
    neutral: 'bg-gray-500/10 text-gray-400 border-gray-500/20',
  }
  return (
    <span className={`inline-flex items-center gap-1 px-2 py-0.5 rounded-full text-[11px] font-medium border ${colors[variant]}`}>
      {children}
    </span>
  )
}

function HeaderCheck({ label, ok }: { label: string; ok: boolean }) {
  return (
    <div className="flex items-center gap-2 text-xs">
      {ok ? <CheckCircle2 className="w-3.5 h-3.5 text-emerald-400" /> : <XCircle className="w-3.5 h-3.5 text-red-400" />}
      <span className={ok ? 'text-gray-300' : 'text-red-300'}>{label}</span>
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
  return (
    <div className="border border-gray-800 rounded-xl overflow-hidden">
      <button
        onClick={() => setOpen(o => !o)}
        className="w-full flex items-center gap-3 px-4 py-3 bg-gray-900/60 hover:bg-gray-800/40 transition"
      >
        <Icon className="w-4 h-4 text-sky-400 shrink-0" />
        <span className="text-sm font-semibold text-gray-300 flex-1 text-left">{title}</span>
        {statusBadge && <span className="mr-2">{statusBadge}</span>}
        {open ? <ChevronDown className="w-4 h-4 text-gray-500" /> : <ChevronRight className="w-4 h-4 text-gray-500" />}
      </button>
      {open && <div className="p-4 space-y-3 bg-gray-950/40">{children}</div>}
    </div>
  )
}

function Row({ label, value, mono = false }: { label: string; value: React.ReactNode; mono?: boolean }) {
  return (
    <div className="flex items-start gap-3 text-xs">
      <span className="text-gray-500 w-32 shrink-0 pt-0.5">{label}</span>
      <span className={`text-gray-300 flex-1 break-all ${mono ? 'font-mono' : ''}`}>{value}</span>
    </div>
  )
}

function ScoreMeter({ score, max = 100, label }: { score: number; max?: number; label?: string }) {
  const pct = Math.round((score / max) * 100)
  const color = pct >= 75 ? 'bg-emerald-400' : pct >= 50 ? 'bg-amber-400' : 'bg-red-400'
  return (
    <div className="flex items-center gap-2 text-xs">
      {label && <span className="text-gray-500 w-20 shrink-0">{label}</span>}
      <div className="flex-1 h-1.5 bg-gray-800 rounded-full overflow-hidden">
        <div className={`h-full ${color} rounded-full transition-all`} style={{ width: `${pct}%` }} />
      </div>
      <span className="text-gray-400 text-[11px] font-mono w-12 text-right">{score.toFixed(0)}/{max}</span>
    </div>
  )
}

function EmptyState({ message }: { message: string }) {
  return (
    <div className="flex items-center gap-2 text-xs text-gray-500 py-2">
      <Info className="w-3.5 h-3.5 shrink-0" />
      <span>{message}</span>
    </div>
  )
}

/* ─── Main Component ──────────────────────────────────────────────────────── */

export default function DeepDive({ data, analysisId }: Props) {
  const [screenshotOpen, setScreenshotOpen] = useState(false)

  return (
    <div className="space-y-3">
      <h3 className="text-sm font-semibold text-gray-400 uppercase tracking-wider mb-1 flex items-center gap-2">
        <Eye className="w-4 h-4" />
        Full Transparency — Deep Dive
      </h3>

      {/* ── Page Screenshot ───────────────────────────────────── */}
      {data.crawl?.screenshot_url && (
        <Section title="Page Screenshot (Captured During Crawl)" icon={Camera} defaultOpen={true}>
          <div className="space-y-2">
            <p className="text-[11px] text-gray-500">
              This screenshot was captured by TrustLens's sandboxed Chromium browser during analysis.
            </p>
            <div
              className="relative rounded-lg overflow-hidden border border-gray-700 cursor-pointer group"
              onClick={() => setScreenshotOpen(!screenshotOpen)}
            >
              <img
                src={data.crawl.screenshot_url}
                alt="Page screenshot captured during crawl"
                className={`w-full transition-all duration-300 ${screenshotOpen ? 'max-h-[800px]' : 'max-h-48'} object-cover object-top`}
              />
              {!screenshotOpen && (
                <div className="absolute inset-0 bg-gradient-to-b from-transparent via-transparent to-gray-950/90 flex items-end justify-center pb-3">
                  <span className="text-xs text-gray-300 flex items-center gap-1 bg-gray-800/80 px-3 py-1.5 rounded-full border border-gray-700">
                    <Image className="w-3 h-3" /> Click to expand full screenshot
                  </span>
                </div>
              )}
            </div>
            {screenshotOpen && (
              <button
                onClick={() => setScreenshotOpen(false)}
                className="text-xs text-sky-400 hover:underline"
              >
                Collapse screenshot
              </button>
            )}
          </div>
        </Section>
      )}

      {/* ── Crawl ─────────────────────────────────────────────── */}
      <Section
        title="Browser Crawl & Page Info"
        icon={Globe}
        statusBadge={data.crawl ? <Badge variant="good">Completed</Badge> : <Badge variant="warn">No Data</Badge>}
      >
        {data.crawl ? (
          <>
            <Row label="Final URL" value={
              <a href={data.crawl.final_url} target="_blank" rel="noreferrer" className="text-sky-400 hover:underline inline-flex items-center gap-1">
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
              <div className="mt-3 pt-3 border-t border-gray-800">
                <p className="text-xs font-semibold text-gray-400 mb-2 flex items-center gap-1.5">
                  {data.crawl.ssl_info.valid ? <Lock className="w-3.5 h-3.5 text-emerald-400" /> : <Unlock className="w-3.5 h-3.5 text-red-400" />}
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
                  <div className="mt-1 text-[11px] text-amber-400">
                    ⚠ Certificate error was ignored during crawl (possible invalid cert)
                  </div>
                )}
              </div>
            )}

            {/* Redirect Chain */}
            {data.crawl.redirect_chain.length > 0 && (
              <div className="mt-3 pt-3 border-t border-gray-800">
                <p className="text-xs font-semibold text-gray-400 mb-2">Redirect Chain ({data.crawl.redirect_chain.length} hops)</p>
                <div className="space-y-1">
                  {data.crawl.redirect_chain.map((hop, i) => (
                    <div key={i} className="flex items-center gap-2 text-[11px] font-mono text-gray-400">
                      <Badge variant={hop.status_code >= 300 && hop.status_code < 400 ? 'warn' : 'neutral'}>{hop.status_code}</Badge>
                      <span className="truncate">{hop.url}</span>
                    </div>
                  ))}
                </div>
              </div>
            )}

            {/* Meta Tags */}
            {Object.keys(data.crawl.meta_tags).length > 0 && (
              <div className="mt-3 pt-3 border-t border-gray-800">
                <p className="text-xs font-semibold text-gray-400 mb-2">Meta Tags</p>
                <div className="space-y-1">
                  {Object.entries(data.crawl.meta_tags).slice(0, 10).map(([k, v]) => (
                    <Row key={k} label={k} value={v.slice(0, 120)} />
                  ))}
                </div>
              </div>
            )}

            {data.crawl.errors.length > 0 && (
              <div className="mt-2 text-xs text-red-400">
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
              <div className="mt-3 pt-3 border-t border-gray-800">
                <p className="text-xs font-semibold text-gray-400 mb-2">DNS Records</p>
                {Object.entries(data.domain_intel.dns_records).map(([type, records]) => (
                  <Row key={type} label={type} value={records.length > 0 ? records.join(', ') : '—'} mono />
                ))}
              </div>
            )}

            {data.domain_intel.signals.length > 0 && (
              <div className="mt-3 pt-3 border-t border-gray-800 space-y-1">
                {data.domain_intel.signals.map((s, i) => (
                  <div key={i} className="flex items-start gap-2 text-xs text-amber-400">
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
            <div key={i} className={`p-3 rounded-lg border ${bm.is_official ? 'border-emerald-500/30 bg-emerald-500/5' : bm.impersonation_probability >= 0.6 ? 'border-red-500/30 bg-red-500/5' : 'border-gray-800 bg-gray-900/40'}`}>
              <div className="flex items-center justify-between mb-2">
                <span className="text-sm font-semibold text-gray-200">{bm.brand_name}</span>
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
              <div className="text-xs text-amber-400 mt-1">
                Missing: {data.security_headers.missing_headers.join(', ')}
              </div>
            )}
          </>
        ) : (
          <EmptyState message="Security headers were not analyzed" />
        )}
      </Section>

      {/* ── AI Analysis ───────────────────────────────────────── */}
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
              <span className="text-xs text-gray-400">
                Provider: <span className="text-gray-200 font-semibold">{data.ai_analysis.provider.toUpperCase()}</span>
              </span>
              <span className="text-xs text-gray-400">
                Model: <span className="text-sky-400 font-mono">{data.ai_analysis.model}</span>
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
                    <p className="text-[11px] text-gray-500 mb-1">Deception Indicators:</p>
                    {data.ai_analysis.deception_indicators.map((d, i) => (
                      <div key={i} className="text-xs text-red-400 flex items-start gap-1.5">
                        <XCircle className="w-3 h-3 mt-0.5 shrink-0" /> {d}
                      </div>
                    ))}
                  </div>
                )}

                {data.ai_analysis.legitimacy_indicators.length > 0 && (
                  <div className="mt-2">
                    <p className="text-[11px] text-gray-500 mb-1">Legitimacy Indicators:</p>
                    {data.ai_analysis.legitimacy_indicators.map((l, i) => (
                      <div key={i} className="text-xs text-emerald-400 flex items-start gap-1.5">
                        <CheckCircle2 className="w-3 h-3 mt-0.5 shrink-0" /> {l}
                      </div>
                    ))}
                  </div>
                )}

                {data.ai_analysis.social_engineering_tactics.length > 0 && (
                  <div className="mt-2">
                    <p className="text-[11px] text-gray-500 mb-1">Social Engineering Tactics:</p>
                    {data.ai_analysis.social_engineering_tactics.map((t, i) => (
                      <div key={i} className="text-xs text-amber-400 flex items-start gap-1.5">
                        <AlertTriangle className="w-3 h-3 mt-0.5 shrink-0" /> {t}
                      </div>
                    ))}
                  </div>
                )}

                {data.ai_analysis.classifier && (
                  <div className="mt-3 pt-3 border-t border-gray-800">
                    <p className="text-xs font-semibold text-gray-400 mb-2">Classifier Breakdown</p>
                    <div className="space-y-1">
                      <ScoreMeter score={data.ai_analysis.classifier.impersonation * 100} label="Impersonation" />
                      <ScoreMeter score={data.ai_analysis.classifier.credential_harvesting * 100} label="Cred Harvest" />
                      <ScoreMeter score={data.ai_analysis.classifier.urgency_manipulation * 100} label="Urgency" />
                      <ScoreMeter score={data.ai_analysis.classifier.fear_tactics * 100} label="Fear" />
                      <ScoreMeter score={data.ai_analysis.classifier.payment_demand * 100} label="Payment" />
                      <ScoreMeter score={data.ai_analysis.classifier.deception_confidence * 100} label="Deception" />
                    </div>
                  </div>
                )}

                {data.ai_analysis.explanation && (
                  <div className="mt-3 text-xs text-gray-400 whitespace-pre-line bg-gray-900/60 rounded-lg p-3 border border-gray-800">
                    {data.ai_analysis.explanation}
                  </div>
                )}
              </>
            ) : (
              <div className="text-xs text-gray-500 bg-gray-900/40 rounded-lg p-3 border border-gray-800">
                AI classifier was unavailable for this analysis — trust score relies on rule-based heuristics only (70% weight).
                <br /><br />
                To enable AI analysis, ensure <span className="text-sky-400 font-semibold">{data.ai_analysis.provider}</span> (<span className="font-mono text-sky-400">{data.ai_analysis.model}</span>) is running and accessible.
              </div>
            )}
          </>
        ) : (
          <EmptyState message="AI analysis configuration not available" />
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
                <p className="text-[11px] text-gray-500 mb-1">Matched Screenshots:</p>
                {data.screenshot_similarity.matched_screenshots.map((m, i) => (
                  <div key={i} className="text-xs text-amber-400">{m}</div>
                ))}
              </div>
            )}
            {data.screenshot_similarity.signals.length > 0 && (
              <div className="mt-2 space-y-1">
                {data.screenshot_similarity.signals.map((s, i) => (
                  <div key={i} className="text-xs text-gray-400 flex items-start gap-1.5">
                    <Info className="w-3 h-3 mt-0.5 shrink-0 text-gray-500" /> {s}
                  </div>
                ))}
              </div>
            )}

            {/* Show the screenshot if available */}
            {data.crawl?.screenshot_url && (
              <div className="mt-3 pt-3 border-t border-gray-800">
                <p className="text-xs font-semibold text-gray-400 mb-2">Captured Screenshot</p>
                <img
                  src={data.crawl.screenshot_url}
                  alt="Analyzed screenshot"
                  className="w-full max-h-40 object-cover object-top rounded-lg border border-gray-700"
                />
              </div>
            )}
          </>
        ) : (
          <div className="space-y-2">
            <EmptyState message="Screenshot similarity analysis was not performed. This requires the Pillow and imagehash Python packages." />
            <div className="text-[11px] text-gray-600 bg-gray-900/40 rounded-lg p-2 font-mono border border-gray-800">
              pip install Pillow imagehash
            </div>
            {data.crawl?.screenshot_url && (
              <div className="mt-2">
                <p className="text-xs text-gray-500 mb-1">The crawl screenshot was still captured:</p>
                <img
                  src={data.crawl.screenshot_url}
                  alt="Captured screenshot"
                  className="w-full max-h-40 object-cover object-top rounded-lg border border-gray-700"
                />
              </div>
            )}
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
              <div className="mt-3 pt-3 border-t border-gray-800 space-y-1">
                <p className="text-[11px] text-gray-500 mb-1">Anomaly Signals:</p>
                {data.zeroday_suspicion.anomaly_signals.map((s, i) => (
                  <div key={i} className="text-xs text-amber-400 flex items-start gap-1.5">
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
                  <div key={i} className="text-xs text-gray-400 flex items-start gap-1.5">
                    <Info className="w-3 h-3 mt-0.5 shrink-0 text-gray-500" /> {s}
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
              <div key={i} className="p-2 rounded-lg bg-gray-900/60 border border-gray-800">
                <div className="flex items-center justify-between mb-1">
                  <span className="text-xs font-semibold text-gray-300">{rs.rule_name}</span>
                  <Badge variant={rs.severity === 'high' || rs.severity === 'critical' ? 'bad' : rs.severity === 'medium' ? 'warn' : 'neutral'}>
                    {rs.severity}
                  </Badge>
                </div>
                <p className="text-[11px] text-gray-400">{rs.description}</p>
                {rs.evidence && <p className="text-[11px] text-gray-500 mt-0.5 font-mono">{rs.evidence}</p>}
                <p className="text-[11px] text-red-400 mt-0.5">Impact: -{rs.score_impact} points</p>
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
              <div key={i} className="p-2 rounded-lg bg-gray-900/60 border border-gray-800">
                <div className="flex items-center justify-between mb-1">
                  <span className="text-xs font-semibold text-gray-300">{bs.signal_type}</span>
                  <Badge variant={bs.severity === 'high' || bs.severity === 'critical' ? 'bad' : 'warn'}>{bs.severity}</Badge>
                </div>
                <p className="text-[11px] text-gray-400">{bs.description}</p>
                {bs.evidence && <p className="text-[11px] text-gray-500 mt-0.5 font-mono">{bs.evidence}</p>}
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

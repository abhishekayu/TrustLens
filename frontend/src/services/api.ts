const API_BASE = '/api/v1'

export interface AnalysisSubmitResponse {
  analysis_id: string
  status: string
  url: string
  submitted_at: string
}

export interface ComponentScore {
  component: string
  raw_score: number
  weight: number
  weighted_score: number
  confidence: number
  signals: string[]
}

export interface TrustScoreResult {
  overall_score: number
  risk_level: string
  risk_category: string
  confidence: number
  rule_score: number
  ai_confidence: number
  components: ComponentScore[]
  explanation: string
  ai_explanation: string
}

export interface PipelineStep {
  name: string
  label: string
  status: 'pending' | 'running' | 'done' | 'failed' | 'skipped'
  detail: string | null
}

export interface AnalysisResult {
  analysis_id: string
  status: string
  url: string
  submitted_at: string
  completed_at: string | null
  trust_score: TrustScoreResult | null
  pipeline_steps: PipelineStep[]
  deep_dive: DeepDiveData | null
  error: string | null
}

// ── Deep Dive Types ─────────────────────────────────────────────────────────

export interface CrawlDetails {
  final_url: string
  status_code: number
  load_time_ms: number
  page_title: string
  redirect_chain: { url: string; status_code: number }[]
  ssl_info: Record<string, unknown> | null
  forms_count: number
  external_links_count: number
  scripts_count: number
  meta_tags: Record<string, string>
  cookies_count: number
  screenshot_path: string | null
  screenshot_url: string | null
  screenshot_base64: string | null
  errors: string[]
}

export interface DomainIntelSummary {
  domain: string
  registered_domain: string
  tld: string
  is_suspicious_tld: boolean
  domain_age_days: number | null
  registrar: string
  registration_date: string | null
  expiration_date: string | null
  dns_records: Record<string, string[]>
  age_score: number
  tld_score: number
  domain_score: number
  signals: string[]
}

export interface BrandMatchSummary {
  brand_name: string
  similarity_score: number
  domain_similarity: number
  content_similarity: number
  impersonation_probability: number
  is_official: boolean
  matched_features: string[]
}

export interface SecurityHeadersSummary {
  is_https: boolean
  has_hsts: boolean
  has_csp: boolean
  has_x_frame_options: boolean
  has_x_content_type_options: boolean
  has_referrer_policy: boolean
  has_permissions_policy: boolean
  missing_headers: string[]
  header_score: number
  signals: string[]
}

export interface AIClassifierResult {
  impersonation: number
  credential_harvesting: number
  urgency_manipulation: number
  fear_tactics: number
  payment_demand: number
  data_collection: number
  deception_confidence: number
  reasoning: string
}

export interface URLPerspective {
  purpose: string
  target_audience: string
  content_category: string
  technology_stack: string[]
  privacy_concerns: string[]
  overall_assessment: string
}

export interface AIAnalysisSummary {
  provider: string
  model: string
  deception_indicators: string[]
  legitimacy_indicators: string[]
  social_engineering_tactics: string[]
  intent: string
  intent_confidence: number
  risk_score: number
  explanation: string
  classifier: AIClassifierResult | null
  url_perspective: URLPerspective | null
  available: boolean
}

export interface ZeroDaySuspicion {
  suspicion_score: number
  anomaly_signals: string[]
  language_anomaly_score: number
  structural_anomaly_score: number
  behavioral_anomaly_score: number
  domain_novelty_score: number
  is_potential_zeroday: boolean
}

export interface ScreenshotSimilarityResult {
  phash: string
  dhash: string
  closest_brand: string | null
  closest_brand_distance: number
  similarity_score: number
  is_visual_clone: boolean
  matched_screenshots: string[]
  signals: string[]
}

export interface ThreatIntelResult {
  is_known_threat: boolean
  highest_confidence: number
  feed_count: number
  threat_types: string[]
  signals: string[]
}

export interface BehavioralSignal {
  signal_type: string
  description: string
  severity: string
  evidence: string
  score_impact: number
}

export interface RuleSignal {
  rule_id: string
  rule_name: string
  category: string
  severity: string
  description: string
  evidence: string
  score_impact: number
}

export interface PaymentDetection {
  has_payment_form: boolean
  payment_gateways_detected: string[]
  payment_form_fields: string[]
  crypto_addresses: { type: string; address: string }[]
  suspicious_payment_patterns: string[]
  legitimate_payment_indicators: string[]
  payment_security_score: number
  risk_level: string
  signals: string[]
}

export interface TrackerInfo {
  name: string
  category: string
  url: string
  severity: string
  description: string
}

export interface TrackerDetection {
  total_trackers: number
  trackers: TrackerInfo[]
  categories: Record<string, number>
  analytics_trackers: string[]
  advertising_trackers: string[]
  fingerprinting_scripts: string[]
  malware_scripts: string[]
  mining_scripts: string[]
  suspicious_scripts: string[]
  known_spyware: string[]
  privacy_score: number
  risk_level: string
  signals: string[]
}

export interface DownloadThreat {
  has_auto_download: boolean
  download_links: string[]
  dangerous_file_types: string[]
  auto_download_triggers: string[]
  permissions_requested: string[]
  permission_details: { permission: string; label: string; risk: string }[]
  notification_spam_detected: boolean
  pup_indicators: string[]
  safety_score: number
  risk_level: string
  signals: string[]
}

export interface DeepDiveData {
  crawl: CrawlDetails | null
  domain_intel: DomainIntelSummary | null
  brand_matches: BrandMatchSummary[]
  security_headers: SecurityHeadersSummary | null
  ai_analysis: AIAnalysisSummary | null
  screenshot_similarity: ScreenshotSimilarityResult | null
  zeroday_suspicion: ZeroDaySuspicion | null
  threat_intel: ThreatIntelResult | null
  community_consensus: { url_or_domain: string; total_reports: number; phishing_reports: number; safe_reports: number; scam_reports: number; crowd_risk_score: number; consensus_confidence: number; last_report_at: string | null } | null
  payment_detection: PaymentDetection | null
  tracker_detection: TrackerDetection | null
  download_threat: DownloadThreat | null
  behavioral_signals: BehavioralSignal[]
  rule_signals: RuleSignal[]
}

export interface TransparencyReport {
  analysis_id: string
  url: string
  trust_score: number
  risk_category: string
  signals_summary: string
  scoring_methodology: string
  ai_analysis: unknown | null
  rule_breakdown: unknown | null
  brand_analysis: unknown | null
  behavioral_analysis: unknown | null
  domain_intelligence: unknown | null
  security_headers: unknown | null
  screenshot_similarity: unknown | null
  zeroday_suspicion: unknown | null
  threat_intel: unknown | null
  community_consensus: unknown | null
  generated_at: string
}

export interface CommunityConsensusInner {
  url_or_domain: string
  total_reports: number
  phishing_reports: number
  safe_reports: number
  scam_reports: number
  crowd_risk_score: number
  consensus_confidence: number
  last_report_at: string | null
}

export interface CommunityConsensus {
  url: string
  consensus: CommunityConsensusInner
}

export interface HealthResponse {
  status: string
  version: string
  ai_provider: string
  database: string
  metrics?: Record<string, unknown>
}

// ── API Functions ──────────────────────────────────────────────────────────

export async function submitAnalysis(
  url: string,
  options?: Record<string, boolean>,
): Promise<AnalysisSubmitResponse> {
  const res = await fetch(`${API_BASE}/analyze`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ url, options: options ?? {} }),
  })
  if (!res.ok) {
    const err = await res.json().catch(() => ({ detail: res.statusText }))
    throw new Error(err.detail || 'Failed to submit analysis')
  }
  return res.json()
}

export async function getAnalysis(id: string): Promise<AnalysisResult> {
  const res = await fetch(`${API_BASE}/analysis/${id}`)
  if (!res.ok) {
    const err = await res.json().catch(() => ({ detail: res.statusText }))
    throw new Error(err.detail || 'Failed to fetch analysis')
  }
  return res.json()
}

export async function getTransparencyReport(id: string): Promise<TransparencyReport> {
  const res = await fetch(`${API_BASE}/analysis/${id}/report`)
  if (!res.ok) {
    const err = await res.json().catch(() => ({ detail: res.statusText }))
    throw new Error(err.detail || 'Failed to fetch report')
  }
  return res.json()
}

export async function getCommunityConsensus(url: string): Promise<CommunityConsensus> {
  const res = await fetch(`${API_BASE}/community/consensus?url=${encodeURIComponent(url)}`)
  if (!res.ok) {
    const err = await res.json().catch(() => ({ detail: res.statusText }))
    throw new Error(err.detail || 'Failed to fetch consensus')
  }
  return res.json()
}

export async function submitCommunityReport(
  url: string,
  reportType: string,
  description?: string,
): Promise<unknown> {
  const res = await fetch(`${API_BASE}/community/report`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ url, report_type: reportType, description }),
  })
  if (!res.ok) {
    const err = await res.json().catch(() => ({ detail: res.statusText }))
    throw new Error(err.detail || 'Failed to submit report')
  }
  return res.json()
}

export async function getHealth(): Promise<HealthResponse> {
  const res = await fetch('/health')
  if (!res.ok) throw new Error('Health check failed')
  return res.json()
}

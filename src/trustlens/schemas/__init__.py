"""
API request / response schemas (Pydantic v2).

Separated from domain models so the public contract is independent of internals.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any, Optional

from pydantic import BaseModel, Field, HttpUrl

from trustlens.models import (
    AIClassifierResult,
    AnalysisStatus,
    APITier,
    BehavioralSignal,
    BrandMatch,
    CommunityConsensus,
    ComponentScore,
    DomainIntelligence,
    IntentCategory,
    LogoDetectionResult,
    RiskCategory,
    RiskLevel,
    RuleSignal,
    ScreenshotSimilarityResult,
    SecurityHeaderResult,
    ThreatIntelResult,
    ZeroDaySuspicionResult,
)


# ── Requests ─────────────────────────────────────────────────────────────────


class AnalyzeURLRequest(BaseModel):
    """POST /api/v1/analyze"""

    url: HttpUrl
    callback_url: Optional[HttpUrl] = None
    tags: list[str] = Field(default_factory=list, max_length=10)
    options: AnalysisOptions = Field(default_factory=lambda: AnalysisOptions())


class AnalysisOptions(BaseModel):
    """Fine-tune which analysis components run."""

    enable_ai: bool = True
    enable_screenshot: bool = True
    enable_brand_check: bool = True
    enable_behavioral: bool = True
    enable_domain_intel: bool = True
    enable_threat_intel: bool = True
    enable_community: bool = True
    enable_zeroday: bool = True
    custom_brands: list[str] = Field(default_factory=list)


class BatchAnalyzeRequest(BaseModel):
    """POST /api/v1/analyze/batch"""

    urls: list[HttpUrl] = Field(..., min_length=1, max_length=50)
    options: AnalysisOptions = Field(default_factory=lambda: AnalysisOptions())


class CommunityReportRequest(BaseModel):
    """POST /api/v1/community/report"""

    url: HttpUrl
    report_type: str = "phishing"        # phishing, scam, malware, safe
    description: str = ""
    evidence_urls: list[str] = Field(default_factory=list, max_length=10)


class APIKeyRegisterRequest(BaseModel):
    """POST /api/v1/keys/register"""

    owner: str = ""
    tier: APITier = APITier.FREE


class BrandMonitorRequest(BaseModel):
    """POST /api/v1/enterprise/monitors"""

    brand_name: str
    official_domains: list[str] = Field(..., min_length=1)
    keywords: list[str] = Field(default_factory=list)
    logo_hashes: list[str] = Field(default_factory=list)
    alert_threshold: float = Field(default=0.7, ge=0.0, le=1.0)
    alert_webhook: str = ""
    scan_interval_hours: int = Field(default=24, ge=1, le=168)


# ── Responses ────────────────────────────────────────────────────────────────


class TrustScoreResponse(BaseModel):
    overall_score: float
    risk_level: RiskLevel
    risk_category: RiskCategory
    confidence: float
    rule_score: float
    ai_confidence: float
    components: list[ComponentScore]
    explanation: str
    ai_explanation: str


class AIInsightResponse(BaseModel):
    deception_indicators: list[str]
    legitimacy_indicators: list[str]
    social_engineering_tactics: list[str]
    intent: IntentCategory
    intent_confidence: float
    classifier: Optional[AIClassifierResult]
    explanation: str


class TransparencyReport(BaseModel):
    """Full explainability report – the core differentiator."""

    analysis_id: str
    url: str
    submitted_at: datetime
    completed_at: Optional[datetime]
    status: AnalysisStatus

    trust_score: Optional[TrustScoreResponse]
    domain_intelligence: Optional[DomainIntelligence]
    rule_signals: list[RuleSignal]
    ai_insights: Optional[AIInsightResponse]
    brand_matches: list[BrandMatch]
    behavioral_signals: list[BehavioralSignal]
    security_headers: Optional[SecurityHeaderResult]

    # New Phase 5 fields
    screenshot_similarity: Optional[ScreenshotSimilarityResult] = None
    logo_detection: Optional[LogoDetectionResult] = None
    zeroday_suspicion: Optional[ZeroDaySuspicionResult] = None
    community_consensus: Optional[CommunityConsensus] = None
    threat_intel: Optional[ThreatIntelResult] = None

    redirect_chain: list[dict[str, Any]] = Field(default_factory=list)
    page_title: str = ""
    final_url: str = ""
    ssl_valid: Optional[bool] = None
    screenshot_url: Optional[str] = None

    methodology: str = Field(
        default=(
            "TrustLens uses a weighted hybrid scoring system combining "
            "rule-based heuristic signals (70%) and AI deception confidence "
            "(30%). Rule signals include domain intelligence, brand impersonation, "
            "behavioral redirect analysis, security headers, and content analysis. "
            "AI provides advisory signals only – it never directly determines "
            "the final risk level. Categories: Safe (75-100), Low Risk (50-74), "
            "Suspicious (25-49), High Risk (0-24). Additional signals from "
            "screenshot similarity, threat intelligence feeds, community reports, "
            "and zero-day suspicion scoring further enrich the analysis."
        )
    )


class PipelineStep(BaseModel):
    """A single step in the analysis pipeline."""
    name: str
    label: str
    status: str  # "pending" | "running" | "done" | "failed" | "skipped"
    detail: Optional[str] = None


class CrawlDetails(BaseModel):
    """Crawl metadata surfaced to the frontend for full transparency."""
    final_url: str = ""
    status_code: int = 0
    load_time_ms: int = 0
    page_title: str = ""
    redirect_chain: list[dict[str, Any]] = Field(default_factory=list)
    ssl_info: Optional[dict[str, Any]] = None
    forms_count: int = 0
    external_links_count: int = 0
    scripts_count: int = 0
    meta_tags: dict[str, str] = Field(default_factory=dict)
    cookies_count: int = 0
    screenshot_path: Optional[str] = None
    screenshot_url: Optional[str] = None
    errors: list[str] = Field(default_factory=list)


class DomainIntelSummary(BaseModel):
    """Domain intelligence details for the frontend."""
    domain: str = ""
    registered_domain: str = ""
    tld: str = ""
    is_suspicious_tld: bool = False
    domain_age_days: Optional[int] = None
    registrar: str = ""
    registration_date: Optional[str] = None
    expiration_date: Optional[str] = None
    dns_records: dict[str, list[str]] = Field(default_factory=dict)
    age_score: float = 100.0
    tld_score: float = 100.0
    domain_score: float = 100.0
    signals: list[str] = Field(default_factory=list)


class BrandMatchSummary(BaseModel):
    """Brand impersonation match details for the frontend."""
    brand_name: str
    similarity_score: float
    domain_similarity: float = 0.0
    content_similarity: float = 0.0
    impersonation_probability: float = 0.0
    is_official: bool = False
    matched_features: list[str] = Field(default_factory=list)


class SecurityHeadersSummary(BaseModel):
    """Security headers analysis for the frontend."""
    is_https: bool = False
    has_hsts: bool = False
    has_csp: bool = False
    has_x_frame_options: bool = False
    has_x_content_type_options: bool = False
    has_referrer_policy: bool = False
    has_permissions_policy: bool = False
    missing_headers: list[str] = Field(default_factory=list)
    header_score: float = 100.0
    signals: list[str] = Field(default_factory=list)


class AIAnalysisSummary(BaseModel):
    """AI analysis details for the frontend."""
    provider: str = ""
    model: str = ""
    deception_indicators: list[str] = Field(default_factory=list)
    legitimacy_indicators: list[str] = Field(default_factory=list)
    social_engineering_tactics: list[str] = Field(default_factory=list)
    intent: str = "unknown"
    intent_confidence: float = 0.0
    risk_score: float = 0.0
    explanation: str = ""
    classifier: Optional[AIClassifierResult] = None
    available: bool = False


class DeepDiveData(BaseModel):
    """Full transparency data for the deep-dive UI panel."""
    crawl: Optional[CrawlDetails] = None
    domain_intel: Optional[DomainIntelSummary] = None
    brand_matches: list[BrandMatchSummary] = Field(default_factory=list)
    security_headers: Optional[SecurityHeadersSummary] = None
    ai_analysis: Optional[AIAnalysisSummary] = None
    screenshot_similarity: Optional[ScreenshotSimilarityResult] = None
    zeroday_suspicion: Optional[ZeroDaySuspicionResult] = None
    threat_intel: Optional[ThreatIntelResult] = None
    community_consensus: Optional[CommunityConsensus] = None
    behavioral_signals: list[BehavioralSignal] = Field(default_factory=list)
    rule_signals: list[RuleSignal] = Field(default_factory=list)


class AnalysisStatusResponse(BaseModel):
    analysis_id: str
    status: AnalysisStatus
    url: str
    submitted_at: datetime
    completed_at: Optional[datetime] = None
    trust_score: Optional[TrustScoreResponse] = None
    error: Optional[str] = None
    pipeline_steps: list[PipelineStep] = Field(default_factory=list)
    deep_dive: Optional[DeepDiveData] = None


class BatchStatusResponse(BaseModel):
    batch_id: str
    total: int
    completed: int
    analyses: list[AnalysisStatusResponse]


class CommunityReportResponse(BaseModel):
    """Response after submitting a community report."""
    report_id: str
    url: str
    report_type: str
    trust_weight: float
    message: str = "Report submitted successfully"


class CommunityConsensusResponse(BaseModel):
    """Community consensus for a URL."""
    url: str
    consensus: CommunityConsensus


class APIKeyResponse(BaseModel):
    """Response after creating an API key."""
    api_key: str                     # raw key (shown only once)
    tier: APITier
    rate_limit: int
    rate_window: int
    scopes: list[str]
    message: str = "Store this key securely – it cannot be retrieved again."


class ThreatIntelStatsResponse(BaseModel):
    """Threat intelligence feed statistics."""
    feeds: dict[str, int]
    total_entries: int


class HealthResponse(BaseModel):
    status: str = "ok"
    version: str = "0.1.0"
    ai_provider: str
    db_connected: bool
    queue_stats: dict[str, int] = Field(default_factory=dict)
    metrics: dict[str, Any] = Field(default_factory=dict)

"""
Analysis endpoints – submit URLs for trust analysis.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from pathlib import Path

from fastapi import APIRouter, Depends, HTTPException, status
from fastapi.responses import FileResponse

from trustlens.core import get_settings
from trustlens.core.logging import get_logger
from trustlens.models import AnalysisStatus, URLAnalysis
from trustlens.schemas import (
    AIAnalysisSummary,
    AnalysisStatusResponse,
    AnalyzeURLRequest,
    BatchAnalyzeRequest,
    BatchStatusResponse,
    BrandMatchSummary,
    CrawlDetails,
    DeepDiveData,
    DomainIntelSummary,
    PipelineStep,
    SecurityHeadersSummary,
    TrustScoreResponse,
)
from trustlens.api.deps import (
    get_analysis_repo,
    get_orchestrator,
    get_task_queue,
)
from trustlens.db import AnalysisRepository
from trustlens.services.orchestrator import AnalysisOrchestrator
from trustlens.services.queue import AsyncTaskQueue

logger = get_logger(__name__)

router = APIRouter(prefix="/api/v1", tags=["analysis"])


# ── Submit single URL ────────────────────────────────────────────────────────


@router.post(
    "/analyze",
    response_model=AnalysisStatusResponse,
    status_code=status.HTTP_202_ACCEPTED,
    summary="Submit a URL for trust analysis",
)
async def submit_analysis(
    request: AnalyzeURLRequest,
    orchestrator: AnalysisOrchestrator = Depends(get_orchestrator),
    repo: AnalysisRepository = Depends(get_analysis_repo),
    queue: AsyncTaskQueue = Depends(get_task_queue),
):
    """
    Submit a URL for asynchronous trust analysis.

    Returns immediately with an analysis ID. Poll ``GET /api/v1/analysis/{id}``
    for results.
    """
    url_str = str(request.url)
    analysis = URLAnalysis(url=url_str)

    # Persist initial record
    await repo.create(analysis)

    logger.info("api.analyze.submitted", analysis_id=analysis.id, url=url_str)

    # Enqueue the analysis task
    async def _run():
        await orchestrator.analyze(
            analysis,
            enable_ai=request.options.enable_ai,
            enable_domain_intel=request.options.enable_domain_intel,
        )

    await queue.submit(_run())

    return AnalysisStatusResponse(
        analysis_id=analysis.id,
        status=AnalysisStatus.PENDING,
        url=url_str,
        submitted_at=analysis.submitted_at,
    )


# ── Get analysis status/result ───────────────────────────────────────────────


@router.get(
    "/analysis/{analysis_id}",
    response_model=AnalysisStatusResponse,
    summary="Get analysis status and results",
)
async def get_analysis(
    analysis_id: str,
    repo: AnalysisRepository = Depends(get_analysis_repo),
):
    """Retrieve the current status and results of an analysis."""
    analysis = await repo.get_by_id(analysis_id)
    if analysis is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Analysis {analysis_id} not found",
        )

    trust_score_resp = None
    if analysis.trust_score is not None:
        ts = analysis.trust_score
        trust_score_resp = TrustScoreResponse(
            overall_score=ts.overall_score,
            risk_level=ts.risk_level,
            risk_category=ts.risk_category,
            confidence=ts.confidence,
            rule_score=ts.rule_score,
            ai_confidence=ts.ai_confidence,
            components=ts.component_scores,
            explanation=ts.explanation,
            ai_explanation=ts.ai_explanation,
        )

    # ── Build pipeline steps for the frontend ────────────────
    pipeline_steps = _build_pipeline_steps(analysis)

    # ── Build deep dive data ─────────────────────────────────
    deep_dive = _build_deep_dive(analysis)

    return AnalysisStatusResponse(
        analysis_id=analysis.id,
        status=analysis.status,
        url=analysis.url,
        submitted_at=analysis.submitted_at,
        completed_at=analysis.completed_at,
        trust_score=trust_score_resp,
        error=analysis.error,
        pipeline_steps=pipeline_steps,
        deep_dive=deep_dive,
    )


# ── Screenshot serving ───────────────────────────────────────────────────────


@router.get(
    "/analysis/{analysis_id}/screenshot",
    summary="Get the crawl screenshot for an analysis",
)
async def get_screenshot(
    analysis_id: str,
    repo: AnalysisRepository = Depends(get_analysis_repo),
):
    """Return the screenshot image captured during crawl."""
    analysis = await repo.get_by_id(analysis_id)
    if analysis is None:
        raise HTTPException(status_code=404, detail="Analysis not found")

    screenshot_path = None
    if analysis.crawl_result and analysis.crawl_result.screenshot_path:
        screenshot_path = analysis.crawl_result.screenshot_path

    if not screenshot_path or not Path(screenshot_path).exists():
        raise HTTPException(status_code=404, detail="Screenshot not available")

    return FileResponse(
        screenshot_path,
        media_type="image/png",
        filename=f"screenshot-{analysis_id}.png",
    )


# ── Batch submit ─────────────────────────────────────────────────────────────


@router.post(
    "/analyze/batch",
    response_model=BatchStatusResponse,
    status_code=status.HTTP_202_ACCEPTED,
    summary="Submit multiple URLs for batch analysis",
)
async def submit_batch(
    request: BatchAnalyzeRequest,
    orchestrator: AnalysisOrchestrator = Depends(get_orchestrator),
    repo: AnalysisRepository = Depends(get_analysis_repo),
    queue: AsyncTaskQueue = Depends(get_task_queue),
):
    """Submit a batch of URLs. Returns a batch ID with individual analysis IDs."""
    batch_id = uuid.uuid4().hex[:12]
    analyses: list[AnalysisStatusResponse] = []

    for raw_url in request.urls:
        url_str = str(raw_url)
        analysis = URLAnalysis(url=url_str)
        await repo.create(analysis)

        async def _make_task(a=analysis):
            await orchestrator.analyze(
                a,
                enable_ai=request.options.enable_ai,
                enable_domain_intel=request.options.enable_domain_intel,
            )

        await queue.submit(_make_task())

        analyses.append(
            AnalysisStatusResponse(
                analysis_id=analysis.id,
                status=AnalysisStatus.PENDING,
                url=url_str,
                submitted_at=analysis.submitted_at,
            )
        )

    logger.info("api.batch.submitted", batch_id=batch_id, count=len(analyses))

    return BatchStatusResponse(
        batch_id=batch_id,
        total=len(analyses),
        completed=0,
        analyses=analyses,
    )


# ── Helpers ──────────────────────────────────────────────────────────────────


def _build_pipeline_steps(analysis: URLAnalysis) -> list[PipelineStep]:
    """
    Build the pipeline step list from analysis state so the frontend
    can show real-time progress and, once done, what each component found.
    """
    st = analysis.status
    is_done = st in (AnalysisStatus.COMPLETED, AnalysisStatus.FAILED)
    is_analyzing = st in (AnalysisStatus.ANALYZING, AnalysisStatus.SCORING, AnalysisStatus.COMPLETED)
    is_scoring = st in (AnalysisStatus.SCORING, AnalysisStatus.COMPLETED)

    # 1. Crawl
    crawl_status = "pending"
    crawl_detail = None
    if analysis.crawl_result is not None:
        if analysis.crawl_result.errors and analysis.crawl_result.status_code == 0:
            crawl_status = "failed"
            crawl_detail = "; ".join(analysis.crawl_result.errors[:2])
        else:
            crawl_status = "done"
            crawl_detail = (
                f"HTTP {analysis.crawl_result.status_code} · "
                f"{analysis.crawl_result.load_time_ms}ms · "
                f"title: {(analysis.crawl_result.page_title or 'N/A')[:60]}"
            )
    elif st == AnalysisStatus.CRAWLING:
        crawl_status = "running"
        crawl_detail = "Fetching page in sandbox browser…"
    elif st == AnalysisStatus.FAILED and analysis.error and "Crawl" in analysis.error:
        crawl_status = "failed"
        crawl_detail = analysis.error[:120]

    steps: list[PipelineStep] = [
        PipelineStep(name="crawl", label="Browser Crawl", status=crawl_status, detail=crawl_detail),
    ]

    # 2. Analysis components – only if crawl succeeded
    component_defs = [
        ("rules", "Rule Engine (Heuristics)", analysis.rule_signals),
        ("brand", "Brand Impersonation Check", analysis.brand_matches),
        ("behavioral", "Behavioral Analysis", analysis.behavioral_signals),
        ("domain_intel", "Domain Intelligence", analysis.domain_intel),
        ("headers", "Security Headers", analysis.security_headers),
        ("ai", "AI Deception Classifier", analysis.ai_result),
        ("screenshot", "Screenshot Similarity", analysis.screenshot_similarity),
        ("threat_intel", "Threat Intel Feed Lookup", analysis.threat_intel),
        ("community", "Community Consensus", analysis.community_consensus),
    ]

    for name, label, result in component_defs:
        if crawl_status == "failed":
            comp_status = "skipped"
            comp_detail = "Skipped (crawl failed)"
        elif is_analyzing or is_done:
            if result is not None:
                comp_status = "done"
                comp_detail = _summarise_component(name, result)
            else:
                comp_status = "done"
                comp_detail = "No findings / unavailable"
        elif st == AnalysisStatus.ANALYZING:
            comp_status = "running"
            comp_detail = "Running…"
        else:
            comp_status = "pending"
            comp_detail = None

        steps.append(PipelineStep(name=name, label=label, status=comp_status, detail=comp_detail))

    # 3. Zero-Day Suspicion
    if crawl_status != "failed":
        zd = analysis.zeroday_suspicion
        if zd is not None:
            zd_detail = f"Score: {zd.suspicion_score}/100" + (" — POTENTIAL ZERO-DAY" if zd.is_potential_zeroday else " — normal")
            steps.append(PipelineStep(name="zeroday", label="Zero-Day Suspicion", status="done", detail=zd_detail))
        elif is_done:
            steps.append(PipelineStep(name="zeroday", label="Zero-Day Suspicion", status="done", detail="No anomalies"))
        else:
            steps.append(PipelineStep(name="zeroday", label="Zero-Day Suspicion", status="pending", detail=None))

    # 4. Scoring
    if crawl_status == "failed":
        sc_status, sc_detail = "skipped", "Skipped (crawl failed)"
    elif is_scoring or is_done:
        if analysis.trust_score:
            sc_status = "done"
            sc_detail = (
                f"Score: {analysis.trust_score.overall_score}/100 "
                f"({analysis.trust_score.risk_category.value}) — "
                f"Rule: {analysis.trust_score.rule_score:.0f} · AI: {analysis.trust_score.ai_confidence:.0%}"
            )
        else:
            sc_status = "done"
            sc_detail = "Scored"
    elif st == AnalysisStatus.SCORING:
        sc_status = "running"
        sc_detail = "Computing 70/30 hybrid score…"
    else:
        sc_status = "pending"
        sc_detail = None

    steps.append(PipelineStep(name="scoring", label="70/30 Hybrid Scoring", status=sc_status, detail=sc_detail))

    return steps


def _summarise_component(name: str, result) -> str:
    """Create a concise one-line summary of a component result for the pipeline UI."""
    try:
        if name == "rules":
            if isinstance(result, list):
                count = len(result)
                high = sum(1 for s in result if hasattr(s, 'severity') and s.severity.value in ('high', 'critical'))
                if count == 0:
                    return "No rule violations detected"
                return f"{count} signals ({high} high severity)"
            return "Checked"
        elif name == "brand":
            if isinstance(result, list):
                matches = [m for m in result if hasattr(m, 'similarity_score') and m.similarity_score > 0.3]
                if not matches:
                    return "No brand impersonation detected"
                top = max(matches, key=lambda m: m.similarity_score)
                return f"Closest: {top.brand_name} ({top.similarity_score:.0%} similarity)"
            return "Checked"
        elif name == "behavioral":
            if isinstance(result, list):
                if not result:
                    return "No suspicious behavior"
                return f"{len(result)} behavioral signals"
            return "Checked"
        elif name == "domain_intel":
            if hasattr(result, 'signals') and result.signals:
                return "; ".join(s[:60] for s in result.signals[:2])
            return "Domain looks normal"
        elif name == "headers":
            if hasattr(result, 'signals') and result.signals:
                return "; ".join(s[:60] for s in result.signals[:2])
            return "Headers checked"
        elif name == "ai":
            if hasattr(result, 'confidence'):
                return f"Confidence: {result.confidence:.0%} · Intent: {getattr(result, 'intent', 'unknown')}"
            return "AI advisory completed"
        elif name == "screenshot":
            if hasattr(result, 'is_visual_clone') and result.is_visual_clone:
                return f"VISUAL CLONE of {result.closest_brand} ({result.similarity_score:.0%})"
            return "No visual clone detected"
        elif name == "threat_intel":
            if hasattr(result, 'is_known_threat') and result.is_known_threat:
                return f"KNOWN THREAT in {result.feed_count} feeds"
            return "Not in threat feeds"
        elif name == "community":
            if hasattr(result, 'total_reports'):
                return f"{result.total_reports} community reports (risk: {result.crowd_risk_score:.0f}/100)"
            return "No community data"
    except Exception:
        pass
    return "Completed"


def _build_deep_dive(analysis: URLAnalysis) -> DeepDiveData:
    """Build the full transparency deep-dive data from the analysis."""
    settings = get_settings()

    # ── Crawl details ────────────────────────────────────────
    crawl = None
    if analysis.crawl_result is not None:
        cr = analysis.crawl_result
        # Build screenshot URL if screenshot exists
        screenshot_url = None
        if cr.screenshot_path and Path(cr.screenshot_path).exists():
            screenshot_url = f"/api/v1/analysis/{analysis.id}/screenshot"

        crawl = CrawlDetails(
            final_url=cr.final_url,
            status_code=cr.status_code,
            load_time_ms=cr.load_time_ms,
            page_title=cr.page_title,
            redirect_chain=[
                {"url": hop.url, "status_code": hop.status_code}
                for hop in cr.redirect_chain
            ],
            ssl_info=cr.ssl_info,
            forms_count=len(cr.forms),
            external_links_count=len(cr.external_links),
            scripts_count=len(cr.scripts),
            meta_tags=cr.meta_tags,
            cookies_count=len(cr.cookies),
            screenshot_path=cr.screenshot_path,
            screenshot_url=screenshot_url,
            errors=cr.errors,
        )

    # ── Domain intel ─────────────────────────────────────────
    di = None
    if analysis.domain_intel is not None:
        d = analysis.domain_intel
        di = DomainIntelSummary(
            domain=d.domain,
            registered_domain=d.registered_domain,
            tld=d.tld,
            is_suspicious_tld=d.is_suspicious_tld,
            domain_age_days=d.domain_age_days,
            registrar=d.registrar,
            registration_date=d.registration_date,
            expiration_date=d.expiration_date,
            dns_records=d.dns_records,
            age_score=d.age_score,
            tld_score=d.tld_score,
            domain_score=d.domain_score,
            signals=d.signals,
        )

    # ── Brand matches ────────────────────────────────────────
    brand_matches = [
        BrandMatchSummary(
            brand_name=bm.brand_name,
            similarity_score=bm.similarity_score,
            domain_similarity=bm.domain_similarity,
            content_similarity=bm.content_similarity,
            impersonation_probability=bm.impersonation_probability,
            is_official=bm.is_official,
            matched_features=bm.matched_features,
        )
        for bm in (analysis.brand_matches or [])
    ]

    # ── Security headers ─────────────────────────────────────
    sh = None
    if analysis.security_headers is not None:
        h = analysis.security_headers
        sh = SecurityHeadersSummary(
            is_https=h.is_https,
            has_hsts=h.has_hsts,
            has_csp=h.has_csp,
            has_x_frame_options=h.has_x_frame_options,
            has_x_content_type_options=h.has_x_content_type_options,
            has_referrer_policy=h.has_referrer_policy,
            has_permissions_policy=h.has_permissions_policy,
            missing_headers=h.missing_headers,
            header_score=h.header_score,
            signals=h.signals,
        )

    # ── AI analysis ──────────────────────────────────────────
    ai = AIAnalysisSummary(
        provider=settings.ai_provider.value,
        model=_get_ai_model_name(settings),
        available=False,
    )
    if analysis.ai_result is not None:
        ar = analysis.ai_result
        ai = AIAnalysisSummary(
            provider=settings.ai_provider.value,
            model=_get_ai_model_name(settings),
            deception_indicators=ar.deception_indicators,
            legitimacy_indicators=ar.legitimacy_indicators,
            social_engineering_tactics=ar.social_engineering_tactics,
            intent=ar.intent_classification.value,
            intent_confidence=ar.intent_confidence,
            risk_score=ar.risk_score,
            explanation=ar.explanation,
            classifier=ar.classifier,
            available=True,
        )

    return DeepDiveData(
        crawl=crawl,
        domain_intel=di,
        brand_matches=brand_matches,
        security_headers=sh,
        ai_analysis=ai,
        screenshot_similarity=analysis.screenshot_similarity,
        zeroday_suspicion=analysis.zeroday_suspicion,
        threat_intel=analysis.threat_intel,
        community_consensus=analysis.community_consensus,
        behavioral_signals=analysis.behavioral_signals or [],
        rule_signals=analysis.rule_signals or [],
    )


def _get_ai_model_name(settings) -> str:
    """Get the model name based on the configured AI provider."""
    if settings.ai_provider.value == "openai":
        return settings.openai_model
    elif settings.ai_provider.value == "anthropic":
        return settings.anthropic_model
    elif settings.ai_provider.value == "grok":
        return settings.grok_model
    elif settings.ai_provider.value == "gemini":
        return settings.gemini_model
    return "unknown"

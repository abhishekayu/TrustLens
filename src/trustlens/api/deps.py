"""
FastAPI dependency injection – provides shared instances to route handlers.
"""

from __future__ import annotations

from typing import Optional

from trustlens.db import (
    AnalysisRepository,
    APIKeyRepository,
    AuditLogRepository,
    BrandMonitorRepository,
    BrandRepository,
    CommunityReportRepository,
    Database,
    ScreenshotHashRepository,
    ThreatIntelRepository,
)
from trustlens.services.orchestrator import AnalysisOrchestrator
from trustlens.services.analysis.screenshot_similarity import ScreenshotSimilarityEngine
from trustlens.services.queue import AsyncTaskQueue

# ── Singletons (set during app startup) ──────────────────────────────────────

_db: Database | None = None
_task_queue: AsyncTaskQueue | None = None
_community_service = None
_threat_intel_service = None
_feed_ingester = None
_brand_monitor_service = None
_api_key_repo: APIKeyRepository | None = None


def set_db(db: Database) -> None:
    global _db
    _db = db


def set_task_queue(queue: AsyncTaskQueue) -> None:
    global _task_queue
    _task_queue = queue


def set_community_service(service) -> None:
    global _community_service
    _community_service = service


def set_threat_intel_service(service) -> None:
    global _threat_intel_service
    _threat_intel_service = service


def set_feed_ingester(ingester) -> None:
    global _feed_ingester
    _feed_ingester = ingester


def set_brand_monitor_service(service) -> None:
    global _brand_monitor_service
    _brand_monitor_service = service


def set_api_key_repo(repo: APIKeyRepository) -> None:
    global _api_key_repo
    _api_key_repo = repo


# ── Dependency functions ─────────────────────────────────────────────────────


def get_db() -> Database:
    if _db is None:
        raise RuntimeError("Database not initialized")
    return _db


def get_analysis_repo() -> AnalysisRepository:
    return AnalysisRepository(get_db())


def get_brand_repo() -> BrandRepository:
    return BrandRepository(get_db())


def get_task_queue() -> AsyncTaskQueue:
    if _task_queue is None:
        raise RuntimeError("Task queue not initialized")
    return _task_queue


def get_orchestrator() -> AnalysisOrchestrator:
    db = get_db()
    orch = AnalysisOrchestrator(
        db=db,
        analysis_repo=AnalysisRepository(db),
        brand_repo=BrandRepository(db),
    )

    # Wire up Phase 5 services
    screenshot_repo = ScreenshotHashRepository(db)
    screenshot_engine = ScreenshotSimilarityEngine()
    orch.set_screenshot_engine(screenshot_engine)

    if _threat_intel_service is not None:
        orch.set_threat_intel(_threat_intel_service)

    if _community_service is not None:
        orch.set_community(_community_service)

    if _brand_monitor_service is not None:
        orch.set_enterprise(_brand_monitor_service)

    return orch


def get_community_service():
    return _community_service


def get_threat_intel_service():
    return _threat_intel_service


def get_feed_ingester():
    return _feed_ingester


def get_brand_monitor_service():
    return _brand_monitor_service


def get_api_key_repo() -> Optional[APIKeyRepository]:
    return _api_key_repo

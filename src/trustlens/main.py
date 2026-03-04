"""
TrustLens AI – FastAPI application entry-point.

Run with:
    PYTHONPATH=src python3 -m uvicorn trustlens.main:app --host 0.0.0.0 --port 8000

The LLM setup wizard runs automatically on first start.
"""

from __future__ import annotations

import os
import sys
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from trustlens.core import get_settings
from trustlens.core.logging import get_logger, setup_logging
from trustlens.db import (
    APIKeyRepository,
    AuditLogRepository,
    BrandMonitorRepository,
    BrandRepository,
    CommunityReportRepository,
    Database,
    ScreenshotHashRepository,
    ThreatIntelRepository,
)
from trustlens.api.deps import (
    set_api_key_repo,
    set_brand_monitor_service,
    set_community_service,
    set_db,
    set_feed_ingester,
    set_task_queue,
    set_threat_intel_service,
)
from trustlens.api.middleware.api_auth import APIKeyAuthMiddleware
from trustlens.api.middleware.rate_limit import RateLimitMiddleware
from trustlens.api.middleware.domain_filter import DomainFilterMiddleware
from trustlens.api.routes.analyze import router as analyze_router
from trustlens.api.routes.community import router as community_router
from trustlens.api.routes.enterprise import router as enterprise_router
from trustlens.api.routes.health import router as health_router
from trustlens.api.routes.keys import router as keys_router
from trustlens.api.routes.report import router as report_router
from trustlens.api.routes.threat_intel import router as threat_intel_router
from trustlens.observability import AuditLogger, EventTypes, get_audit_logger, set_audit_logger
from trustlens.services.community import CommunityReportingService
from trustlens.services.enterprise import BrandMonitorService
from trustlens.services.queue import AsyncTaskQueue
from trustlens.services.threat_intel import FeedIngester, ThreatIntelService

logger = get_logger(__name__)


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application lifespan – startup & shutdown hooks."""
    settings = get_settings()
    setup_logging(settings.log_level.value, json_output=not settings.debug)

    logger.info(
        "trustlens.starting",
        host=settings.host,
        port=settings.port,
        ai_provider=settings.ai_provider.value,
    )

    # ── Startup ──────────────────────────────────────────────────────────
    # 1. Database
    db = Database(settings.db_url)
    await db.connect()
    set_db(db)

    # 2. Seed default brands
    brand_repo = BrandRepository(db)
    await brand_repo.seed_defaults()

    # 3. Screenshot directory
    settings.screenshot_dir.mkdir(parents=True, exist_ok=True)

    # 4. Task queue
    queue = AsyncTaskQueue(max_concurrent=5)
    await queue.start()
    set_task_queue(queue)

    # 5. Audit logger
    audit_repo = AuditLogRepository(db)
    audit = AuditLogger(repo=audit_repo)
    set_audit_logger(audit)

    # 6. API key repository
    api_key_repo = APIKeyRepository(db)
    set_api_key_repo(api_key_repo)

    # Set API key repo on middleware (if middleware requires it)
    for mw in app.user_middleware:
        if hasattr(mw, 'cls') and mw.cls is APIKeyAuthMiddleware:
            pass  # Middleware will use the repo from deps

    # 7. Community reporting service
    if settings.community_reports_enabled:
        community_repo = CommunityReportRepository(db)
        community_service = CommunityReportingService(community_repo)
        set_community_service(community_service)

    # 8. Threat intelligence service
    threat_repo = ThreatIntelRepository(db)
    threat_service = ThreatIntelService(threat_repo)
    set_threat_intel_service(threat_service)

    feed_ingester = FeedIngester(threat_repo)
    set_feed_ingester(feed_ingester)

    # Auto-ingest configured feeds at startup
    if settings.threat_feed_urls.strip():
        try:
            results = await feed_ingester.ingest_all_configured()
            total = sum(results.values())
            logger.info("trustlens.threat_feeds_loaded", total_entries=total)
        except Exception as e:
            logger.warning("trustlens.threat_feed_ingest_failed", error=str(e))

    # 9. Enterprise brand monitor service
    if settings.enterprise_mode:
        monitor_repo = BrandMonitorRepository(db)
        monitor_service = BrandMonitorService(monitor_repo)
        set_brand_monitor_service(monitor_service)
        logger.info("trustlens.enterprise_mode_enabled")

    # 10. Emit startup audit event
    await audit.emit(
        event_type=EventTypes.SYSTEM_STARTUP,
        action="startup",
        metadata={
            "ai_provider": settings.ai_provider.value,
            "enterprise_mode": settings.enterprise_mode,
            "community_enabled": settings.community_reports_enabled,
        },
    )

    logger.info("trustlens.ready")

    yield  # ── Application runs here ──

    # ── Shutdown ─────────────────────────────────────────────────────────
    logger.info("trustlens.shutting_down")
    await audit.emit(event_type=EventTypes.SYSTEM_SHUTDOWN, action="shutdown")
    await queue.stop()
    await db.disconnect()
    logger.info("trustlens.stopped")


def create_app() -> FastAPI:
    """FastAPI application factory."""
    settings = get_settings()

    app = FastAPI(
        title="TrustLens AI",
        description=(
            "Explainable AI-Powered URL Trust Intelligence Engine. "
            "Provides transparent, evidence-based trust scoring for any URL "
            "with screenshot similarity detection, threat intelligence feeds, "
            "community reporting, and enterprise brand monitoring."
        ),
        version="0.2.0",
        lifespan=lifespan,
        docs_url="/docs",
        redoc_url="/redoc",
    )

    # ── Middleware (order matters – outermost first) ──────────────────────
    app.add_middleware(
        CORSMiddleware,
        allow_origins=["*"],
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    app.add_middleware(
        RateLimitMiddleware,
        max_requests=settings.rate_limit_requests,
        window_seconds=settings.rate_limit_window_seconds,
    )

    app.add_middleware(DomainFilterMiddleware)
    app.add_middleware(APIKeyAuthMiddleware)

    # ── Routes ───────────────────────────────────────────────────────────
    app.include_router(analyze_router)
    app.include_router(report_router)
    app.include_router(health_router)
    app.include_router(community_router)
    app.include_router(keys_router)
    app.include_router(threat_intel_router)
    app.include_router(enterprise_router)

    return app


# ── Run wizard before creating the app ───────────────────────────────
def _run_setup_wizard() -> None:
    """
    Run the interactive LLM setup wizard if:
    - Not already completed (TRUSTLENS_WIZARD_DONE env var prevents re-run on --reload)
    - If saved config exists and running in background → auto-continue
    - If interactive foreground terminal → show the full wizard menu
    """
    # Skip if already done (reload guard)
    if os.environ.get("TRUSTLENS_WIZARD_DONE") == "1":
        return

    root_dir = Path(__file__).resolve().parent.parent.parent  # TrustLens/
    sys.path.insert(0, str(root_dir))

    try:
        from setup_wizard import run_wizard, _write_env, _read_env, _get_saved_config
        import setup_wizard

        # Point wizard at workspace root .env
        setup_wizard.ENV_FILE = root_dir / ".env"

        saved = _get_saved_config()

        # Detect if we're truly in the foreground (can accept keyboard input)
        is_foreground = False
        if sys.stdin.isatty():
            try:
                # Check if our process group owns the terminal
                fg_pgid = os.tcgetpgrp(sys.stdin.fileno())
                is_foreground = fg_pgid == os.getpgrp()
            except (OSError, AttributeError):
                is_foreground = False

        if not is_foreground:
            # Background / non-interactive — auto-continue if saved config exists
            if saved:
                provider = saved["provider"]
                model = saved.get("model", "default")
                print(f"\033[92m▶  Auto-continuing with saved config: {provider.upper()} ({model})\033[0m")
            else:
                print("\033[93mNo LLM config found. Using default (gemini). Run in foreground to configure.\033[0m")
            os.environ["TRUSTLENS_WIZARD_DONE"] = "1"
            get_settings.cache_clear()
            return

        # Interactive foreground mode — run full wizard
        config = run_wizard()
        if config is None:
            print("\033[91mSetup cancelled. Exiting.\033[0m")
            sys.exit(1)

        if config != "continue":
            _write_env(config)
            provider = config.get("TRUSTLENS_AI_PROVIDER", "unknown")
        else:
            env = _read_env()
            provider = env.get("TRUSTLENS_AI_PROVIDER", "unknown")

        # Mark wizard as done so --reload doesn't re-trigger it
        os.environ["TRUSTLENS_WIZARD_DONE"] = "1"

        # Clear settings cache so new .env values are picked up
        get_settings.cache_clear()

        print(f"\n\033[92m\033[1m{'═' * 50}\033[0m")
        print(f"\033[92m\033[1m  🚀 Starting TrustLens AI with {provider.upper()}\033[0m")
        print(f"\033[92m\033[1m{'═' * 50}\033[0m\n")

    except ImportError:
        # setup_wizard.py not found — skip silently (e.g. production deployment)
        pass
    except Exception as e:
        print(f"\033[93mWizard skipped: {e}\033[0m")


_run_setup_wizard()

app = create_app()

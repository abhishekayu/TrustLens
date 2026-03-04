"""
TrustLens – Core configuration via pydantic-settings.

All settings are read from environment variables prefixed with TRUSTLENS_.
A .env file is loaded automatically when present.
"""

from __future__ import annotations

from enum import Enum
from functools import lru_cache
from pathlib import Path
from typing import Optional

from pydantic import Field, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class AIProvider(str, Enum):
    OPENAI = "openai"
    ANTHROPIC = "anthropic"
    GROK = "grok"
    GEMINI = "gemini"


class LogLevel(str, Enum):
    DEBUG = "debug"
    INFO = "info"
    WARNING = "warning"
    ERROR = "error"
    CRITICAL = "critical"


class Settings(BaseSettings):
    """Application-wide settings driven by env vars / .env file."""

    model_config = SettingsConfigDict(
        env_prefix="TRUSTLENS_",
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
        extra="ignore",
    )

    # ── Server ──────────────────────────────────────
    host: str = "0.0.0.0"
    port: int = 8000
    log_level: LogLevel = LogLevel.INFO
    debug: bool = False

    # ── Database ────────────────────────────────────
    db_url: str = "sqlite+aiosqlite:///./trustlens.db"

    # ── AI ──────────────────────────────────────────
    ai_provider: AIProvider = AIProvider.GEMINI

    openai_api_key: Optional[str] = None
    openai_model: str = "gpt-4o"

    anthropic_api_key: Optional[str] = None
    anthropic_model: str = "claude-sonnet-4-20250514"

    grok_api_key: Optional[str] = None
    grok_model: str = "grok-3"

    gemini_api_key: Optional[str] = None
    gemini_model: str = "gemini-2.5-flash"

    # ── Crawler / Security ──────────────────────────
    crawler_timeout: int = 30
    crawler_max_redirects: int = 10
    crawler_user_agent: str = "TrustLens/0.1 SecurityScanner"
    ssrf_block_private: bool = True
    screenshot_enabled: bool = True
    screenshot_dir: Path = Path("screenshots")

    # ── Rate Limiting ───────────────────────────────
    rate_limit_requests: int = 30
    rate_limit_window_seconds: int = 60

    # ── Domain allow/deny ───────────────────────────
    domain_allowlist: str = ""       # comma-separated, empty = allow all
    domain_denylist: str = ""        # comma-separated

    # ── Scoring weights ─────────────────────────────
    # Rule-based signals account for 70%, AI for 30%
    score_weight_rules: float = 0.70
    score_weight_ai: float = 0.30

    # ── API Key Authentication ──────────────────────
    api_key_required: bool = False                  # enforce API key auth globally
    api_key_header: str = "X-API-Key"

    # ── Threat Intelligence ─────────────────────────
    threat_feed_urls: str = ""                      # comma-separated feed URLs
    threat_feed_refresh_hours: int = 6              # auto-refresh interval

    # ── Screenshot Similarity ───────────────────────
    screenshot_similarity_threshold: float = 0.85   # above = visual clone
    screenshot_hash_algorithm: str = "phash"        # phash or dhash

    # ── Community Reporting ─────────────────────────
    community_reports_enabled: bool = True
    community_report_min_trust: float = 0.5         # min reporter trust weight

    # ── Enterprise Mode ─────────────────────────────
    enterprise_mode: bool = False
    enterprise_brand_scan_interval: int = 24        # hours

    # ── Observability ───────────────────────────────
    audit_log_enabled: bool = True
    suspicious_activity_threshold: int = 100        # events/hour to flag

    @field_validator("score_weight_rules", "score_weight_ai")
    @classmethod
    def weight_range(cls, v: float) -> float:
        if not 0.0 <= v <= 1.0:
            raise ValueError("Weight must be between 0 and 1")
        return v

    # ── Helpers ─────────────────────────────────────

    @property
    def allowed_domains(self) -> list[str]:
        if not self.domain_allowlist.strip():
            return []
        return [d.strip().lower() for d in self.domain_allowlist.split(",") if d.strip()]

    @property
    def denied_domains(self) -> list[str]:
        if not self.domain_denylist.strip():
            return []
        return [d.strip().lower() for d in self.domain_denylist.split(",") if d.strip()]


@lru_cache
def get_settings() -> Settings:
    """Return a cached singleton of the application settings."""
    return Settings()

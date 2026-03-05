"""
Rule-based heuristic analysis engine.

Each rule is a self-contained function that examines CrawlResult data and
produces RuleSignal objects. Rules are registered via decorator and executed
in parallel.
"""

from __future__ import annotations

import asyncio
import re
from typing import Callable, Awaitable
from urllib.parse import urlparse

from trustlens.core.logging import get_logger
from trustlens.models import CrawlResult, RiskLevel, RuleSignal
from trustlens.security import extract_domain

logger = get_logger(__name__)

# Rule registry
RuleFunc = Callable[[CrawlResult, str], Awaitable[list[RuleSignal]]]
_rules: list[RuleFunc] = []


def rule(func: RuleFunc) -> RuleFunc:
    """Decorator to register a heuristic rule."""
    _rules.append(func)
    return func


class RuleEngine:
    """Execute all registered heuristic rules against crawl data."""

    async def analyze(self, crawl: CrawlResult, original_url: str) -> list[RuleSignal]:
        """Run all rules concurrently and collect signals."""
        tasks = [r(crawl, original_url) for r in _rules]
        results = await asyncio.gather(*tasks, return_exceptions=True)

        signals: list[RuleSignal] = []
        for i, result in enumerate(results):
            if isinstance(result, Exception):
                logger.warning("rule_engine.rule_failed", rule=_rules[i].__name__, error=str(result))
            else:
                signals.extend(result)

        logger.info("rule_engine.completed", total_signals=len(signals))
        return signals


# ── Rules ────────────────────────────────────────────────────────────────────


@rule
async def check_ssl(crawl: CrawlResult, original_url: str) -> list[RuleSignal]:
    """Check if the site uses HTTPS and has valid SSL."""
    signals = []
    ssl = crawl.ssl_info or {}

    if not ssl.get("is_https"):
        signals.append(
            RuleSignal(
                rule_id="SSL_001",
                rule_name="No HTTPS",
                category="ssl",
                severity=RiskLevel.HIGH,
                description="Site does not use HTTPS encryption – data is transmitted in plain text",
                evidence=f"URL scheme: {urlparse(crawl.final_url).scheme}",
                score_impact=25.0,
            )
        )
    else:
        # HTTPS is present — check certificate details
        protocol = ssl.get("protocol", "")
        if protocol and "TLSv1.3" in protocol:
            signals.append(
                RuleSignal(
                    rule_id="SSL_004",
                    rule_name="TLS 1.3",
                    category="ssl",
                    severity=RiskLevel.INFO,
                    description="Site uses modern TLS 1.3 protocol for encryption",
                    evidence=f"Protocol: {protocol}",
                    score_impact=-5.0,  # positive signal
                )
            )
        elif protocol and ("TLSv1.0" in protocol or "TLSv1.1" in protocol or "SSLv" in protocol):
            signals.append(
                RuleSignal(
                    rule_id="SSL_005",
                    rule_name="Outdated TLS",
                    category="ssl",
                    severity=RiskLevel.MEDIUM,
                    description=f"Site uses outdated {protocol} protocol – vulnerable to known attacks",
                    evidence=f"Protocol: {protocol}",
                    score_impact=15.0,
                )
            )
        if ssl.get("valid") is False:
            signals.append(
                RuleSignal(
                    rule_id="SSL_006",
                    rule_name="Invalid Certificate",
                    category="ssl",
                    severity=RiskLevel.HIGH,
                    description="SSL certificate is invalid, expired, or self-signed",
                    evidence="Certificate validation failed",
                    score_impact=25.0,
                )
            )

    if ssl.get("is_https") and not ssl.get("has_hsts"):
        signals.append(
            RuleSignal(
                rule_id="SSL_002",
                rule_name="No HSTS",
                category="ssl",
                severity=RiskLevel.LOW,
                description="Site uses HTTPS but does not enforce it via HSTS header",
                evidence="Missing Strict-Transport-Security header",
                score_impact=5.0,
            )
        )
    return signals


@rule
async def check_suspicious_forms(crawl: CrawlResult, original_url: str) -> list[RuleSignal]:
    """Detect forms that collect sensitive data (passwords, credit cards)."""
    signals = []
    sensitive_types = {"password", "credit-card", "ssn"}
    sensitive_names = re.compile(
        r"(password|passwd|pass|pwd|credit.?card|ccn|cvv|ssn|social.?security|"
        r"card.?number|expir|routing|account.?num)",
        re.IGNORECASE,
    )

    for i, form in enumerate(crawl.forms):
        fields = form.get("fields", [])
        for field in fields:
            field_type = (field.get("type") or "").lower()
            field_name = (field.get("name") or "") + (field.get("placeholder") or "")

            if field_type == "password":
                signals.append(
                    RuleSignal(
                        rule_id="FORM_001",
                        rule_name="Password field detected",
                        category="credential_harvest",
                        severity=RiskLevel.MEDIUM,
                        description=f"Form #{i+1} contains a password input field",
                        evidence=f"Field: {field.get('name', 'unnamed')}",
                        score_impact=20.0,
                    )
                )
            if sensitive_names.search(field_name):
                signals.append(
                    RuleSignal(
                        rule_id="FORM_002",
                        rule_name="Sensitive field name",
                        category="credential_harvest",
                        severity=RiskLevel.MEDIUM,
                        description=f"Form #{i+1} has a field matching sensitive patterns",
                        evidence=f"Field: {field_name[:80]}",
                        score_impact=15.0,
                    )
                )

        # Cross-origin form submission
        action = form.get("action", "")
        if action and not action.startswith("/") and not action.startswith("#"):
            form_domain = extract_domain(action) if "://" in action else ""
            page_domain = extract_domain(crawl.final_url)
            if form_domain and form_domain != page_domain:
                signals.append(
                    RuleSignal(
                        rule_id="FORM_003",
                        rule_name="Cross-origin form submission",
                        category="credential_harvest",
                        severity=RiskLevel.HIGH,
                        description=f"Form submits data to a different domain: {form_domain}",
                        evidence=f"Page: {page_domain}, Form action: {form_domain}",
                        score_impact=30.0,
                    )
                )
    return signals


@rule
async def check_suspicious_url_patterns(crawl: CrawlResult, original_url: str) -> list[RuleSignal]:
    """Detect URL-based phishing indicators."""
    signals = []
    parsed = urlparse(crawl.final_url)
    hostname = parsed.hostname or ""

    # Excessive subdomains
    parts = hostname.split(".")
    if len(parts) > 4:
        signals.append(
            RuleSignal(
                rule_id="URL_001",
                rule_name="Excessive subdomains",
                category="url_structure",
                severity=RiskLevel.MEDIUM,
                description=f"URL has {len(parts)} domain levels, which is suspicious",
                evidence=hostname,
                score_impact=15.0,
            )
        )

    # IP address as hostname
    ip_pattern = re.compile(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$")
    if ip_pattern.match(hostname):
        signals.append(
            RuleSignal(
                rule_id="URL_002",
                rule_name="IP address hostname",
                category="url_structure",
                severity=RiskLevel.HIGH,
                description="URL uses an IP address instead of a domain name",
                evidence=hostname,
                score_impact=25.0,
            )
        )

    # Suspicious keywords in URL
    url_lower = crawl.final_url.lower()
    suspicious_keywords = [
        "login", "signin", "verify", "secure", "account", "update",
        "confirm", "banking", "password", "credential", "suspend",
        "unusual", "alert", "urgent",
    ]
    found = [kw for kw in suspicious_keywords if kw in url_lower]
    if len(found) >= 2:
        signals.append(
            RuleSignal(
                rule_id="URL_003",
                rule_name="Suspicious URL keywords",
                category="url_structure",
                severity=RiskLevel.MEDIUM,
                description="URL contains multiple suspicious keywords",
                evidence=f"Keywords found: {', '.join(found)}",
                score_impact=15.0,
            )
        )

    # Very long URL
    if len(crawl.final_url) > 200:
        signals.append(
            RuleSignal(
                rule_id="URL_004",
                rule_name="Excessively long URL",
                category="url_structure",
                severity=RiskLevel.LOW,
                description=f"URL is unusually long ({len(crawl.final_url)} chars)",
                evidence=crawl.final_url[:100] + "...",
                score_impact=5.0,
            )
        )

    # URL contains @ symbol (credential-based redirect trick)
    if "@" in parsed.netloc:
        signals.append(
            RuleSignal(
                rule_id="URL_005",
                rule_name="@ symbol in URL",
                category="url_structure",
                severity=RiskLevel.HIGH,
                description="URL contains @ symbol which can be used to disguise the real destination",
                evidence=parsed.netloc,
                score_impact=30.0,
            )
        )

    return signals


@rule
async def check_page_content(crawl: CrawlResult, original_url: str) -> list[RuleSignal]:
    """Detect suspicious page content patterns."""
    signals = []
    html_lower = crawl.html_content.lower()
    title_lower = crawl.page_title.lower()

    # Urgency language in title
    urgency_patterns = [
        "your account", "suspended", "verify your", "confirm your",
        "unusual activity", "security alert", "action required",
        "limited time", "act now", "expire",
    ]
    found_urgency = [p for p in urgency_patterns if p in title_lower or p in html_lower[:3000]]
    if len(found_urgency) >= 2:
        signals.append(
            RuleSignal(
                rule_id="CONTENT_001",
                rule_name="Urgency language detected",
                category="social_engineering",
                severity=RiskLevel.MEDIUM,
                description="Page uses urgency/fear language common in phishing",
                evidence=f"Patterns: {', '.join(found_urgency[:5])}",
                score_impact=20.0,
            )
        )

    # Hidden iframes
    if re.search(r'<iframe[^>]*style\s*=\s*"[^"]*display\s*:\s*none', html_lower):
        signals.append(
            RuleSignal(
                rule_id="CONTENT_002",
                rule_name="Hidden iframe",
                category="deception",
                severity=RiskLevel.HIGH,
                description="Page contains a hidden iframe",
                evidence="display:none iframe found",
                score_impact=25.0,
            )
        )

    # Data URI in src attributes
    if 'src="data:' in html_lower or "src='data:" in html_lower:
        signals.append(
            RuleSignal(
                rule_id="CONTENT_003",
                rule_name="Data URI in source",
                category="deception",
                severity=RiskLevel.MEDIUM,
                description="Page uses data: URIs to embed content inline",
                evidence="data: URI found in src attribute",
                score_impact=10.0,
            )
        )

    # Title mismatch with domain
    page_domain = extract_domain(crawl.final_url).lower()
    if crawl.page_title and page_domain:
        title_words = set(re.findall(r'\b\w+\b', title_lower))
        brand_keywords = {"google", "microsoft", "apple", "amazon", "paypal",
                         "facebook", "netflix", "chase", "bank", "wells"}
        mentioned_brands = title_words & brand_keywords
        if mentioned_brands:
            for brand in mentioned_brands:
                if brand not in page_domain:
                    signals.append(
                        RuleSignal(
                            rule_id="CONTENT_004",
                            rule_name="Brand name mismatch",
                            category="brand_impersonation",
                            severity=RiskLevel.HIGH,
                            description=f"Page title mentions '{brand}' but domain is '{page_domain}'",
                            evidence=f"Title: {crawl.page_title[:80]}",
                            score_impact=30.0,
                        )
                    )

    return signals


@rule
async def check_redirect_behavior(crawl: CrawlResult, original_url: str) -> list[RuleSignal]:
    """Analyze redirect chain for suspicious patterns."""
    signals = []
    chain = crawl.redirect_chain

    if len(chain) > 3:
        signals.append(
            RuleSignal(
                rule_id="REDIRECT_001",
                rule_name="Excessive redirects",
                category="behavioral",
                severity=RiskLevel.MEDIUM,
                description=f"URL went through {len(chain)} redirects",
                evidence=" → ".join(r.url[:60] for r in chain[:5]),
                score_impact=15.0,
            )
        )

    # Domain changes during redirect
    original_domain = extract_domain(original_url)
    final_domain = extract_domain(crawl.final_url)
    if original_domain != final_domain:
        signals.append(
            RuleSignal(
                rule_id="REDIRECT_002",
                rule_name="Domain change via redirect",
                category="behavioral",
                severity=RiskLevel.MEDIUM,
                description=f"URL redirected from {original_domain} to {final_domain}",
                evidence=f"{original_domain} → {final_domain}",
                score_impact=15.0,
            )
        )

    # Cross-domain redirects through unknown intermediaries
    domains_seen = set()
    for hop in chain:
        domains_seen.add(extract_domain(hop.url))
    if len(domains_seen) > 2:
        signals.append(
            RuleSignal(
                rule_id="REDIRECT_003",
                rule_name="Multi-domain redirect chain",
                category="behavioral",
                severity=RiskLevel.HIGH,
                description=f"Redirected through {len(domains_seen)} different domains",
                evidence=", ".join(list(domains_seen)[:5]),
                score_impact=25.0,
            )
        )

    return signals


@rule
async def check_security_headers(crawl: CrawlResult, original_url: str) -> list[RuleSignal]:
    """Check for missing security headers."""
    signals = []
    headers_lower = {k.lower(): v for k, v in crawl.headers.items()}

    important_headers = {
        "content-security-policy": ("CSP_001", "Missing Content-Security-Policy", 5.0),
        "x-frame-options": ("CSP_002", "Missing X-Frame-Options", 3.0),
        "x-content-type-options": ("CSP_003", "Missing X-Content-Type-Options", 2.0),
    }

    missing_count = 0
    for header, (rule_id, desc, impact) in important_headers.items():
        if header not in headers_lower:
            missing_count += 1

    # Only flag if most security headers are missing (indicates less professional setup)
    if missing_count >= 2:
        signals.append(
            RuleSignal(
                rule_id="SEC_001",
                rule_name="Missing security headers",
                category="security_posture",
                severity=RiskLevel.LOW,
                description=f"Site is missing {missing_count}/3 standard security headers",
                evidence="Missing headers indicate lower security maturity",
                score_impact=8.0,
            )
        )

    return signals


@rule
async def check_external_resources(crawl: CrawlResult, original_url: str) -> list[RuleSignal]:
    """Check for suspicious external resource loading patterns."""
    signals = []
    page_domain = extract_domain(crawl.final_url).lower()

    # Count external scripts from different domains
    external_script_domains: set[str] = set()
    for script in crawl.external_scripts:
        if "://" in script:
            script_domain = extract_domain(script).lower()
            if script_domain and script_domain != page_domain:
                external_script_domains.add(script_domain)

    if len(external_script_domains) > 10:
        signals.append(
            RuleSignal(
                rule_id="EXT_001",
                rule_name="Excessive external scripts",
                category="security_posture",
                severity=RiskLevel.MEDIUM,
                description=f"Page loads scripts from {len(external_script_domains)} different external domains",
                evidence=f"Domains: {', '.join(list(external_script_domains)[:5])}...",
                score_impact=10.0,
            )
        )

    # Check for data exfiltration via image pixels (tracking pixels)
    html_lower = crawl.html_content.lower()
    pixel_count = len(re.findall(r'<img[^>]*(?:width\s*=\s*["\']1|height\s*=\s*["\']1|1x1)', html_lower))
    if pixel_count > 3:
        signals.append(
            RuleSignal(
                rule_id="EXT_002",
                rule_name="Multiple tracking pixels",
                category="privacy",
                severity=RiskLevel.LOW,
                description=f"Page contains {pixel_count} tracking pixel images (1x1 pixel images used for tracking)",
                evidence=f"{pixel_count} 1x1 pixel images found",
                score_impact=5.0,
            )
        )

    return signals

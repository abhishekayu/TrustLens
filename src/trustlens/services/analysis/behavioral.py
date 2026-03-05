"""
Behavioral redirect & runtime analysis.

Analyzes redirect chains, timing patterns, and page behavior for
evasion / deception signals. This complements the rule engine by
focusing specifically on dynamic behavioral patterns.
"""

from __future__ import annotations

import re
from urllib.parse import urlparse, parse_qs

from trustlens.core.logging import get_logger
from trustlens.models import BehavioralSignal, CrawlResult, RiskLevel
from trustlens.security import extract_domain

logger = get_logger(__name__)


class BehavioralAnalyzer:
    """Analyze page/redirect behavior for evasion and deception."""

    async def analyze(self, crawl: CrawlResult, original_url: str) -> list[BehavioralSignal]:
        """Run all behavioral checks."""
        signals: list[BehavioralSignal] = []

        signals.extend(self._analyze_redirects(crawl, original_url))
        signals.extend(self._analyze_page_behavior(crawl))
        signals.extend(self._analyze_timing(crawl))
        signals.extend(self._analyze_evasion_techniques(crawl))

        logger.info("behavioral_analyzer.completed", total_signals=len(signals))
        return signals

    def _analyze_redirects(self, crawl: CrawlResult, original_url: str) -> list[BehavioralSignal]:
        """Deep redirect chain analysis."""
        signals = []
        chain = crawl.redirect_chain

        if not chain:
            return signals

        # JavaScript-based redirect detection
        html_lower = crawl.html_content.lower()
        js_redirect_patterns = [
            r"window\.location\s*=",
            r"window\.location\.href\s*=",
            r"window\.location\.replace\(",
            r"document\.location\s*=",
            r"meta\s+http-equiv\s*=\s*[\"']refresh",
            r"window\.navigate\(",
        ]
        js_redirects_found = []
        for pattern in js_redirect_patterns:
            if re.search(pattern, html_lower):
                js_redirects_found.append(pattern.replace("\\", ""))

        if js_redirects_found:
            signals.append(
                BehavioralSignal(
                    signal_type="js_redirect",
                    description="Page contains JavaScript-based redirect mechanisms",
                    severity=RiskLevel.MEDIUM,
                    evidence=f"Patterns: {', '.join(js_redirects_found[:3])}",
                    score_impact=15.0,
                )
            )

        # URL shortener / tracker detection
        shortener_domains = {
            "bit.ly", "t.co", "goo.gl", "tinyurl.com", "ow.ly",
            "is.gd", "buff.ly", "short.link", "rebrand.ly",
        }
        for hop in chain:
            hop_domain = extract_domain(hop.url).lower()
            if hop_domain in shortener_domains:
                signals.append(
                    BehavioralSignal(
                        signal_type="url_shortener",
                        description=f"Redirect chain passes through URL shortener: {hop_domain}",
                        severity=RiskLevel.LOW,
                        evidence=hop.url[:100],
                        score_impact=8.0,
                    )
                )
                break

        # Suspicious query parameter forwarding (e.g., email in URL)
        for hop in chain:
            parsed = urlparse(hop.url)
            params = parse_qs(parsed.query)
            suspicious_params = {
                k for k in params
                if any(s in k.lower() for s in ["email", "user", "login", "token", "session"])
            }
            if suspicious_params:
                signals.append(
                    BehavioralSignal(
                        signal_type="sensitive_params",
                        description="Redirect chain passes sensitive parameters",
                        severity=RiskLevel.MEDIUM,
                        evidence=f"Params: {', '.join(suspicious_params)}",
                        score_impact=12.0,
                    )
                )
                break

        return signals

    def _analyze_page_behavior(self, crawl: CrawlResult) -> list[BehavioralSignal]:
        """Analyze page-level behavioral signals."""
        signals = []
        html_lower = crawl.html_content.lower()

        # Right-click / copy disabled (anti-analysis)
        anti_analysis = [
            (r"oncontextmenu\s*=\s*[\"']return\s+false", "right-click disabled"),
            (r"onselectstart\s*=\s*[\"']return\s+false", "text selection disabled"),
            (r"onkeydown.*?F12", "F12 key blocked"),
            (r"devtools", "devtools detection"),
            (r"ondragstart\s*=\s*[\"']return\s+false", "drag disabled"),
            (r"oncopy\s*=\s*[\"']return\s+false", "copy disabled"),
        ]
        for pattern, desc in anti_analysis:
            if re.search(pattern, html_lower):
                signals.append(
                    BehavioralSignal(
                        signal_type="anti_analysis",
                        description=f"Anti-analysis technique detected: {desc}",
                        severity=RiskLevel.MEDIUM,
                        evidence=desc,
                        score_impact=15.0,
                    )
                )

        # Countdown timers / urgency mechanisms
        urgency_patterns = [
            r"countdown|timer|setTimeout.*redirect|setInterval.*redirect",
            r"expires?\s+in\s+\d+",
            r"hurry|urgent|immediately|act\s+now",
            r"only\s+\d+\s+(left|remaining|available)",
        ]
        for pattern in urgency_patterns:
            if re.search(pattern, html_lower):
                signals.append(
                    BehavioralSignal(
                        signal_type="urgency",
                        description="Page uses urgency/scarcity tactics to pressure users",
                        severity=RiskLevel.MEDIUM,
                        evidence=f"Pattern: {pattern[:50]}",
                        score_impact=10.0,
                    )
                )
                break  # One signal is enough

        # Auto-submit forms
        if re.search(r"\.submit\(\)|autosubmit|auto-submit", html_lower):
            signals.append(
                BehavioralSignal(
                    signal_type="auto_submit",
                    description="Page appears to auto-submit forms without user interaction",
                    severity=RiskLevel.HIGH,
                    evidence="Form auto-submission detected",
                    score_impact=25.0,
                )
            )

        # Clipboard manipulation
        if re.search(r"navigator\.clipboard|execCommand.*copy|clipboardData", html_lower):
            signals.append(
                BehavioralSignal(
                    signal_type="clipboard_access",
                    description="Page attempts to access or manipulate the clipboard",
                    severity=RiskLevel.MEDIUM,
                    evidence="Clipboard API usage detected",
                    score_impact=10.0,
                )
            )

        # Popup / overlay abuse (fake dialogs)
        popup_patterns = [
            (r"window\.open\s*\(", "window.open() popup"),
            (r"alert\s*\(\s*[\"'].*?(virus|infected|compromised|hacked|warning)", "fake alert dialog"),
            (r"confirm\s*\(\s*[\"'].*?(update|download|install)", "fake confirm dialog"),
        ]
        for pattern, desc in popup_patterns:
            if re.search(pattern, html_lower):
                signals.append(
                    BehavioralSignal(
                        signal_type="popup_abuse",
                        description=f"Suspicious popup/dialog detected: {desc}",
                        severity=RiskLevel.MEDIUM,
                        evidence=desc,
                        score_impact=12.0,
                    )
                )

        # Notification permission request (used in push notification spam)
        if re.search(r"Notification\.requestPermission|push.*subscribe", html_lower):
            signals.append(
                BehavioralSignal(
                    signal_type="notification_request",
                    description="Page requests push notification permissions",
                    severity=RiskLevel.LOW,
                    evidence="Notification.requestPermission() or push subscription detected",
                    score_impact=5.0,
                )
            )

        # Geolocation tracking
        if re.search(r"navigator\.geolocation|getCurrentPosition|watchPosition", html_lower):
            signals.append(
                BehavioralSignal(
                    signal_type="geolocation",
                    description="Page requests user geolocation data",
                    severity=RiskLevel.LOW,
                    evidence="Geolocation API usage detected",
                    score_impact=5.0,
                )
            )

        # WebSocket connections (can be used for C2 communication)
        if re.search(r"new\s+WebSocket\s*\(|wss?://", html_lower):
            signals.append(
                BehavioralSignal(
                    signal_type="websocket",
                    description="Page establishes WebSocket connection (real-time data channel)",
                    severity=RiskLevel.LOW,
                    evidence="WebSocket connection detected",
                    score_impact=3.0,
                )
            )

        # Service Worker registration (can persist after page close)
        if re.search(r"serviceWorker\.register|navigator\.serviceWorker", html_lower):
            signals.append(
                BehavioralSignal(
                    signal_type="service_worker",
                    description="Page registers a Service Worker (can persist after tab close)",
                    severity=RiskLevel.LOW,
                    evidence="Service Worker registration detected",
                    score_impact=3.0,
                )
            )

        return signals

    def _analyze_timing(self, crawl: CrawlResult) -> list[BehavioralSignal]:
        """Analyze timing-related signals."""
        signals = []

        # Very fast load might indicate a simple phishing page
        if crawl.load_time_ms > 0 and crawl.load_time_ms < 200 and len(crawl.html_content) < 5000:
            signals.append(
                BehavioralSignal(
                    signal_type="fast_simple_page",
                    description="Very fast load time with minimal content (typical of phishing pages)",
                    severity=RiskLevel.LOW,
                    evidence=f"Load time: {crawl.load_time_ms}ms, HTML size: {len(crawl.html_content)} bytes",
                    score_impact=5.0,
                )
            )

        return signals

    def _analyze_evasion_techniques(self, crawl: CrawlResult) -> list[BehavioralSignal]:
        """Detect common phishing evasion techniques."""
        signals = []
        html_lower = crawl.html_content.lower()

        # Base64 encoded content
        import re as re_mod
        b64_count = len(re_mod.findall(r"data:image/[^;]+;base64,", html_lower))
        if b64_count > 5:
            signals.append(
                BehavioralSignal(
                    signal_type="excessive_base64",
                    description=f"Page embeds {b64_count} base64-encoded images (may evade content scanners)",
                    severity=RiskLevel.MEDIUM,
                    evidence=f"{b64_count} base64 images found",
                    score_impact=12.0,
                )
            )

        # Obfuscated JavaScript
        obfuscation_patterns = [
            (r"eval\s*\(\s*atob\s*\(", "eval(atob()) – base64 JS execution"),
            (r"eval\s*\(\s*unescape\s*\(", "eval(unescape()) – URL-encoded JS"),
            (r"String\.fromCharCode", "String.fromCharCode – char code obfuscation"),
            (r"\\x[0-9a-f]{2}\\x[0-9a-f]{2}\\x[0-9a-f]{2}", "hex-encoded strings"),
            (r"eval\s*\(\s*function\s*\(\s*p\s*,\s*a\s*,\s*c\s*,\s*k", "Dean Edwards packer – JS obfuscation"),
            (r"document\.write\s*\(\s*unescape", "document.write(unescape()) – DOM injection"),
            (r"\[\s*['\"]\\x", "hex-encoded array entries"),
        ]
        for pattern, desc in obfuscation_patterns:
            if re.search(pattern, html_lower):
                signals.append(
                    BehavioralSignal(
                        signal_type="js_obfuscation",
                        description=f"JavaScript obfuscation detected: {desc}",
                        severity=RiskLevel.HIGH,
                        evidence=desc,
                        score_impact=20.0,
                    )
                )

        # Hidden elements with input fields (phishing technique)
        hidden_inputs = len(re_mod.findall(
            r'<(?:div|span|form)[^>]*style\s*=\s*"[^"]*(?:display\s*:\s*none|visibility\s*:\s*hidden|opacity\s*:\s*0)[^"]*"[^>]*>(?:(?!</(?:div|span|form)>).)*<input',
            html_lower,
        ))
        if hidden_inputs > 0:
            signals.append(
                BehavioralSignal(
                    signal_type="hidden_inputs",
                    description=f"Found {hidden_inputs} hidden container(s) with input fields – potential honeypot or data exfiltration",
                    severity=RiskLevel.MEDIUM,
                    evidence=f"{hidden_inputs} hidden input containers",
                    score_impact=15.0,
                )
            )

        # External script from suspicious TLD
        suspicious_script_tlds = {"tk", "ml", "ga", "cf", "gq", "xyz", "top", "icu", "buzz"}
        ext_script_matches = re_mod.findall(r'src\s*=\s*["\']https?://([^/"\']+)', html_lower)
        for domain in ext_script_matches:
            tld = domain.split(".")[-1] if "." in domain else ""
            if tld in suspicious_script_tlds:
                signals.append(
                    BehavioralSignal(
                        signal_type="suspicious_external_script",
                        description=f"External script loaded from suspicious TLD domain: {domain}",
                        severity=RiskLevel.HIGH,
                        evidence=f"Script source: {domain}",
                        score_impact=20.0,
                    )
                )
                break  # One is enough

        # Iframe sandbox bypass or suspicious iframes
        iframe_count = len(re_mod.findall(r"<iframe", html_lower))
        if iframe_count > 3:
            signals.append(
                BehavioralSignal(
                    signal_type="excessive_iframes",
                    description=f"Page contains {iframe_count} iframes – may be loading external phishing content",
                    severity=RiskLevel.MEDIUM,
                    evidence=f"{iframe_count} iframe elements found",
                    score_impact=10.0,
                )
            )

        return signals

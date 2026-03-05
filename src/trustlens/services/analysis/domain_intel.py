"""
Domain Intelligence Module.

Provides RDAP lookup, domain age scoring, suspicious TLD detection,
DNS resolution analysis, and structural domain risk scoring.
"""

from __future__ import annotations

import asyncio
import re
import socket
from datetime import datetime, timezone
from typing import Any, Optional
from urllib.parse import urlparse

import httpx
import tldextract

from trustlens.core.logging import get_logger
from trustlens.models import DomainIntelligence

logger = get_logger(__name__)

# TLDs commonly abused in phishing campaigns (data-driven from APWG reports)
SUSPICIOUS_TLDS = {
    "tk", "ml", "ga", "cf", "gq",          # Freenom free TLDs
    "buzz", "xyz", "top", "club", "work",    # cheap gTLDs
    "icu", "cam", "surf", "monster",
    "click", "link", "site", "online",
    "rest", "fit", "loan", "racing",
    "win", "bid", "stream", "download",
    "gdn", "men", "review", "party",
    "date", "faith", "science", "cricket",
    "accountant", "realtor", "ren", "kim",
    "country", "wang", "trade", "webcam",
}

# Well-known registrars often used for throwaway domains
SUSPICIOUS_REGISTRARS = {
    "namecheap", "namesilo", "porkbun", "freenom",
    "enom", "epik", "nicenic",
}

# RDAP bootstrap for gTLDs
_RDAP_BOOTSTRAP = "https://rdap.org/domain/"


class DomainIntelligenceService:
    """Analyse domain registration, age, TLD risk, and DNS."""

    async def analyze(self, url: str) -> DomainIntelligence:
        """Run full domain intelligence gathering."""
        parsed = urlparse(url)
        hostname = parsed.hostname or ""
        ext = tldextract.extract(url)
        registered_domain = f"{ext.domain}.{ext.suffix}" if ext.suffix else ext.domain
        tld = ext.suffix.split(".")[-1] if ext.suffix else ""

        intel = DomainIntelligence(
            domain=hostname,
            registered_domain=registered_domain,
            tld=tld,
        )

        # Run sub-analyses concurrently
        rdap_task = self._rdap_lookup(registered_domain)
        dns_task = self._dns_resolve(hostname)

        rdap_result, dns_result = await asyncio.gather(
            rdap_task, dns_task, return_exceptions=True
        )

        # ── TLD scoring ──────────────────────────────────────────
        if tld.lower() in SUSPICIOUS_TLDS:
            intel.is_suspicious_tld = True
            intel.tld_score = 30.0
            intel.signals.append(f"Suspicious TLD: .{tld} is frequently abused in phishing campaigns")
        else:
            intel.tld_score = 100.0
            intel.signals.append(f"TLD .{tld} is not commonly associated with abuse")

        # ── Domain structure analysis ────────────────────────────
        self._analyze_domain_structure(intel, hostname, ext)

        # ── RDAP / domain age ────────────────────────────────────
        if isinstance(rdap_result, dict) and rdap_result:
            intel.rdap_raw = rdap_result
            self._parse_rdap(intel, rdap_result)
        elif isinstance(rdap_result, Exception):
            logger.warning("domain_intel.rdap_failed", domain=registered_domain, error=str(rdap_result))
            intel.signals.append("RDAP lookup failed – domain registration data unavailable")
        else:
            intel.signals.append("No RDAP data available for this domain")

        # ── DNS ──────────────────────────────────────────────────
        if isinstance(dns_result, dict):
            intel.dns_records = dns_result
            a_records = dns_result.get("A", [])
            aaaa_records = dns_result.get("AAAA", [])
            if not a_records and not aaaa_records:
                intel.signals.append("No A/AAAA DNS records found – domain may not resolve")
            else:
                if a_records:
                    intel.signals.append(f"DNS resolves to {len(a_records)} IPv4 address(es): {', '.join(a_records[:3])}")
                if aaaa_records:
                    intel.signals.append(f"DNS resolves to {len(aaaa_records)} IPv6 address(es)")
        elif isinstance(dns_result, Exception):
            logger.warning("domain_intel.dns_failed", domain=hostname, error=str(dns_result))
            intel.signals.append("DNS resolution failed")

        # ── Aggregate domain score ───────────────────────────────
        intel.domain_score = (intel.age_score * 0.5 + intel.tld_score * 0.5)
        return intel

    def _analyze_domain_structure(self, intel: DomainIntelligence, hostname: str, ext: Any) -> None:
        """Analyze domain structural patterns for risk signals."""
        domain_part = ext.domain

        # Excessive hyphens (common in phishing: paypal-secure-login.com)
        hyphen_count = domain_part.count("-")
        if hyphen_count >= 3:
            intel.signals.append(f"Domain contains {hyphen_count} hyphens – common in phishing domains (e.g., brand-secure-login.com)")
        elif hyphen_count >= 1:
            intel.signals.append(f"Domain contains {hyphen_count} hyphen(s)")

        # Very long domain names
        if len(domain_part) > 20:
            intel.signals.append(f"Unusually long domain name ({len(domain_part)} chars) – long domains can be used to hide malicious intent")
        elif len(domain_part) > 12:
            intel.signals.append(f"Domain name is {len(domain_part)} characters long")

        # Subdomain depth
        subdomains = ext.subdomain.split(".") if ext.subdomain else []
        subdomain_count = len([s for s in subdomains if s])
        if subdomain_count > 2:
            intel.signals.append(f"Deep subdomain nesting ({subdomain_count} levels: {hostname}) – may be used to impersonate brands")
        elif subdomain_count > 0:
            intel.signals.append(f"Has {subdomain_count} subdomain level(s)")

        # Digit-heavy domain (e.g., x8329login.com)
        digit_ratio = sum(1 for c in domain_part if c.isdigit()) / max(len(domain_part), 1)
        if digit_ratio > 0.4:
            intel.signals.append(f"Domain is {int(digit_ratio*100)}% numeric – randomly generated domains are suspicious")

        # Homograph characters (basic check for l/1, o/0 substitutions)
        homograph_pairs = [("l", "1"), ("o", "0"), ("i", "1"), ("s", "5"), ("a", "4"), ("e", "3")]
        for real, fake in homograph_pairs:
            if fake in domain_part and real in domain_part:
                intel.signals.append(f"Potential character substitution in domain: '{real}' and '{fake}' both present")
                break

    async def _rdap_lookup(self, domain: str) -> dict[str, Any]:
        """Query RDAP for domain registration data."""
        url = f"{_RDAP_BOOTSTRAP}{domain}"
        try:
            async with httpx.AsyncClient(timeout=10.0) as client:
                resp = await client.get(url, follow_redirects=True)
                if resp.status_code == 200:
                    return resp.json()
                return {}
        except Exception as e:
            logger.debug("rdap.request_failed", domain=domain, error=str(e))
            return {}

    async def _dns_resolve(self, hostname: str) -> dict[str, list[str]]:
        """Resolve A, AAAA records."""
        records: dict[str, list[str]] = {}
        loop = asyncio.get_event_loop()

        for qtype, family in [("A", socket.AF_INET), ("AAAA", socket.AF_INET6)]:
            try:
                infos = await loop.run_in_executor(
                    None, lambda f=family: socket.getaddrinfo(hostname, None, f, socket.SOCK_STREAM)
                )
                records[qtype] = list({sockaddr[0] for _, _, _, _, sockaddr in infos})
            except socket.gaierror:
                records[qtype] = []

        return records

    def _parse_rdap(self, intel: DomainIntelligence, data: dict[str, Any]) -> None:
        """Extract registration dates, registrar, and status from RDAP response."""
        events = data.get("events", [])
        for event in events:
            action = event.get("eventAction", "")
            date_str = event.get("eventDate", "")
            if action == "registration" and date_str:
                intel.registration_date = date_str[:10]
                try:
                    reg_date = datetime.fromisoformat(date_str.replace("Z", "+00:00"))
                    age = (datetime.now(timezone.utc) - reg_date).days
                    intel.domain_age_days = age
                    intel.age_score = self._compute_age_score(age)
                    if age < 7:
                        intel.signals.append(f"⚠ Extremely new domain: registered only {age} days ago – very high risk")
                    elif age < 30:
                        intel.signals.append(f"⚠ Very new domain: registered {age} days ago – phishing domains are often < 30 days old")
                    elif age < 90:
                        intel.signals.append(f"Recently registered domain: {age} days ago")
                    elif age < 365:
                        intel.signals.append(f"Domain age: {age} days ({age // 30} months)")
                    else:
                        years = age // 365
                        intel.signals.append(f"Established domain: registered {years}+ year(s) ago ({age} days) – older domains are more trustworthy")
                except (ValueError, TypeError):
                    pass
            elif action == "expiration" and date_str:
                intel.expiration_date = date_str[:10]
                # Check for short-lived registrations
                if intel.registration_date:
                    try:
                        reg = datetime.fromisoformat(intel.registration_date)
                        exp = datetime.fromisoformat(date_str[:10])
                        reg_length = (exp - reg).days
                        if reg_length <= 365:
                            intel.signals.append(f"Short registration period: only {reg_length} days – phishing domains are often registered for ≤1 year")
                    except (ValueError, TypeError):
                        pass
            elif action == "last changed" and date_str:
                intel.signals.append(f"Domain last updated: {date_str[:10]}")

        # Status flags
        statuses = data.get("status", [])
        if statuses:
            client_holds = [s for s in statuses if "hold" in s.lower()]
            if client_holds:
                intel.signals.append(f"Domain has hold status: {', '.join(client_holds)} – may indicate abuse")
            privacy_statuses = [s for s in statuses if "proxy" in s.lower() or "private" in s.lower()]
            if privacy_statuses:
                intel.signals.append("Domain registration uses privacy/proxy protection – common in both legitimate and malicious domains")

        # Registrar
        entities = data.get("entities", [])
        for ent in entities:
            roles = ent.get("roles", [])
            if "registrar" in roles:
                vcard = ent.get("vcardArray", [None, []])
                if len(vcard) > 1:
                    for field in vcard[1]:
                        if field[0] == "fn":
                            registrar_name = field[3] if len(field) > 3 else ""
                            intel.registrar = registrar_name
                            intel.signals.append(f"Registrar: {registrar_name}")
                            # Flag commonly abused registrars
                            if any(sus in registrar_name.lower() for sus in SUSPICIOUS_REGISTRARS):
                                intel.signals.append(f"Registrar '{registrar_name}' is commonly used for disposable phishing domains")
                            break

    @staticmethod
    def _compute_age_score(age_days: int) -> float:
        """Map domain age to a trust score (0-100) with more granularity."""
        if age_days < 1:
            return 5.0
        elif age_days < 7:
            return 10.0
        elif age_days < 14:
            return 18.0
        elif age_days < 30:
            return 25.0
        elif age_days < 60:
            return 40.0
        elif age_days < 90:
            return 50.0
        elif age_days < 180:
            return 60.0
        elif age_days < 365:
            return 75.0
        elif age_days < 365 * 2:
            return 85.0
        elif age_days < 365 * 3:
            return 90.0
        elif age_days < 365 * 5:
            return 95.0
        else:
            return 100.0

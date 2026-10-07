"""Passive subdomain enumeration via Certificate Transparency logs and DNS."""

from __future__ import annotations

import asyncio
import json
import socket
from typing import Any

from autosecpro.core.http_client import AsyncHttpClient
from autosecpro.core.models import Finding, ScanContext
from autosecpro.vuln.cvss import get_preset

CRTSH_URL = "https://crt.sh/?q=%25.{domain}&output=json"

# Fingerprints for third-party services commonly associated with dangling
# CNAME subdomain takeover when the target hostname is unregistered. This
# list is used only to raise/lower confidence in the informational finding
# text; no exploitation or registration attempt is ever performed.
_KNOWN_TAKEOVER_SERVICE_HINTS = (
    "github.io",
    "herokuapp.com",
    "azurewebsites.net",
    "cloudapp.net",
    "s3.amazonaws.com",
    "s3-website",
    "trafficmanager.net",
    "wordpress.com",
    "shopify.com",
    "fastly.net",
    "netlify.app",
    "surge.sh",
)


def _extract_names(entries: list[dict[str, Any]]) -> set[str]:
    names: set[str] = set()
    for entry in entries:
        name_value = entry.get("name_value", "")
        for line in name_value.splitlines():
            candidate = line.strip().lstrip("*.")
            if candidate:
                names.add(candidate.lower())
    return names


async def enumerate_subdomains_crtsh(client: AsyncHttpClient, domain: str) -> set[str]:
    """Query crt.sh Certificate Transparency logs passively for subdomains."""
    url = CRTSH_URL.format(domain=domain)
    response = await client.get(url, headers={"Accept": "application/json"})
    if response is None or response.status != 200:
        return set()
    try:
        text = await response.text()
        data = json.loads(text)
    except (json.JSONDecodeError, asyncio.TimeoutError):
        return set()
    return _extract_names(data)


def resolve_cname(hostname: str) -> str | None:
    """Attempt to resolve the CNAME chain target for a hostname (best-effort)."""
    try:
        _, aliases, addresses = socket.gethostbyname_ex(hostname)
        if not addresses:
            return None
        return aliases[0] if aliases else None
    except socket.gaierror:
        return "UNRESOLVED"


def check_dangling_cname(hostname: str) -> bool:
    """Heuristically check whether a subdomain has a dangling CNAME (takeover risk)."""
    try:
        socket.gethostbyname(hostname)
        return False
    except socket.gaierror:
        return True


def build_dangling_subdomain_findings(context: ScanContext) -> list[Finding]:
    """Build INFO/MEDIUM findings for subdomains that failed DNS resolution.

    These are reported with low-to-medium confidence: DNS resolution
    failure alone does not prove a CNAME takeover is exploitable, only
    that the record is dangling and warrants manual verification (e.g.
    confirming the CNAME target and whether the third-party service allows
    unauthenticated resource claiming). No registration or claim attempt is
    ever performed.
    """
    findings: list[Finding] = []
    for sub in sorted(context.dangling_subdomains):
        severity, score, vector = get_preset("subdomain_takeover")
        findings.append(
            Finding(
                id="",
                name=f"Potentially Dangling Subdomain: {sub}",
                category="OWASP A05:2021 - Security Misconfiguration",
                severity=severity,
                cvss_score=score,
                cvss_vector=vector,
                url=f"https://{sub}",
                evidence_poc=f"DNS resolution failed for '{sub}', which was discovered via passive Certificate "
                "Transparency log enumeration. This may indicate a dangling DNS record vulnerable to "
                "subdomain takeover if a CNAME still points to an unclaimed third-party resource.",
                remediation="Manually verify the DNS record for this subdomain. Remove the record if it is "
                "unused, or reclaim/reconfigure the referenced third-party resource if still in use.",
            )
        )
    return findings


async def run_subdomain_enumeration(client: AsyncHttpClient, context: ScanContext) -> None:
    """Run passive subdomain enumeration and populate the scan context."""
    if context.target.is_ip:
        return
    domain = context.target.host
    subdomains = await enumerate_subdomains_crtsh(client, domain)
    subdomains.discard(domain)
    context.discovered_subdomains.update(subdomains)

    loop = asyncio.get_event_loop()
    sample = list(subdomains)[:40]
    dangling_checks = await asyncio.gather(
        *(loop.run_in_executor(None, check_dangling_cname, sub) for sub in sample),
        return_exceptions=True,
    )
    for sub, is_dangling in zip(sample, dangling_checks):
        if is_dangling is True:
            context.dangling_subdomains.append(sub)

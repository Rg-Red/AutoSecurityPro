"""Safe Reflected Cross-Site Scripting (XSS) verification using canary strings."""

from __future__ import annotations

import random
import string
from urllib.parse import urlencode, urlparse, urlunparse

from autosecpro.core.http_client import AsyncHttpClient
from autosecpro.core.models import Finding, ScanContext
from autosecpro.vuln.cvss import get_preset


def _generate_canary() -> str:
    """Generate a unique, safe alphanumeric canary token for reflection testing."""
    suffix = "".join(random.choices(string.ascii_lowercase + string.digits, k=8))
    return f"asp_canary_{suffix}"


def _inject_param(url: str, param: str, payload: str) -> str:
    parsed = urlparse(url)
    query_pairs = dict(pair.split("=", 1) for pair in parsed.query.split("&") if "=" in pair)
    query_pairs[param] = payload
    return urlunparse(parsed._replace(query=urlencode(query_pairs)))


async def run_xss_checks(client: AsyncHttpClient, context: ScanContext) -> list[Finding]:
    """Probe query parameters with safe canary payloads to detect reflected XSS."""
    findings: list[Finding] = []
    for url in list(context.discovered_endpoints):
        parsed = urlparse(url)
        if not parsed.query:
            continue
        params = [pair.split("=", 1)[0] for pair in parsed.query.split("&") if "=" in pair]
        for param in params:
            canary = _generate_canary()
            payload = f"<{canary}>"
            test_url = _inject_param(url, param, payload)
            response = await client.get(test_url)
            if response is None:
                continue
            try:
                body = await response.text(errors="ignore")
            except Exception:
                continue
            if payload in body:
                severity, score, vector = get_preset("xss")
                findings.append(
                    Finding(
                        id="",
                        name="Reflected Cross-Site Scripting (XSS)",
                        category="OWASP A03:2021 - Injection",
                        severity=severity,
                        cvss_score=score,
                        cvss_vector=vector,
                        url=test_url,
                        parameter=param,
                        evidence_poc=f"Canary reflection detected in response body: {payload}",
                        remediation="Implement contextual HTML output encoding and enforce a strong "
                        "Content-Security-Policy (CSP).",
                    )
                )
    return findings

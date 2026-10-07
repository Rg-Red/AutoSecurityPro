"""Safe Local File Inclusion / Path Traversal and SSRF verification checks.

LFI checks perform read-only verification of benign, non-sensitive markers
within well-known operating system files. SSRF checks rely on non-routable
loopback response heuristics only; no external callback infrastructure is used.
"""

from __future__ import annotations

import re
from urllib.parse import urlencode, urlparse, urlunparse

from autosecpro.core.http_client import AsyncHttpClient
from autosecpro.core.models import Finding, ScanContext
from autosecpro.vuln.cvss import get_preset

LFI_PAYLOADS = {
    "../../../../../../etc/passwd": re.compile(r"root:.*:0:0:"),
    "..\\..\\..\\..\\..\\..\\windows\\win.ini": re.compile(r"\[fonts\]", re.IGNORECASE),
    "....//....//....//....//etc/passwd": re.compile(r"root:.*:0:0:"),
}

SSRF_PAYLOADS = [
    "http://127.0.0.1",
    "http://localhost",
    "http://[::1]",
    "http://169.254.169.254/latest/meta-data/",
]

SSRF_RESPONSE_HINTS = re.compile(r"(root:.*:0:0:|localhost|ami-id|instance-id|latest/meta-data)", re.IGNORECASE)


def _inject_param(url: str, param: str, payload: str) -> str:
    parsed = urlparse(url)
    query_pairs = dict(pair.split("=", 1) for pair in parsed.query.split("&") if "=" in pair)
    query_pairs[param] = payload
    return urlunparse(parsed._replace(query=urlencode(query_pairs)))


async def run_lfi_checks(client: AsyncHttpClient, context: ScanContext) -> list[Finding]:
    """Run read-only Local File Inclusion / Path Traversal verification checks."""
    findings: list[Finding] = []
    for url in list(context.discovered_endpoints):
        parsed = urlparse(url)
        if not parsed.query:
            continue
        params = [pair.split("=", 1)[0] for pair in parsed.query.split("&") if "=" in pair]
        for param in params:
            for payload, marker_pattern in LFI_PAYLOADS.items():
                test_url = _inject_param(url, param, payload)
                response = await client.get(test_url)
                if response is None:
                    continue
                try:
                    body = await response.text(errors="ignore")
                except Exception:
                    continue
                match = marker_pattern.search(body)
                if match:
                    severity, score, vector = get_preset("lfi")
                    findings.append(
                        Finding(
                            id="",
                            name="Local File Inclusion / Path Traversal",
                            category="OWASP A01:2021 - Broken Access Control",
                            severity=severity,
                            cvss_score=score,
                            cvss_vector=vector,
                            url=test_url,
                            parameter=param,
                            evidence_poc=f"Benign system file marker detected in response: '{match.group(0)[:60]}'",
                            remediation="Validate and sanitize file path input; use an allow-list of permitted "
                            "files and avoid direct filesystem access based on user input.",
                        )
                    )
                    break
    return findings


async def run_ssrf_checks(client: AsyncHttpClient, context: ScanContext) -> list[Finding]:
    """Run safe SSRF detection using non-routable loopback response heuristics."""
    findings: list[Finding] = []
    for url in list(context.discovered_endpoints):
        parsed = urlparse(url)
        if not parsed.query:
            continue
        params = [pair.split("=", 1)[0] for pair in parsed.query.split("&") if "=" in pair]
        for param in params:
            if param.lower() not in ("url", "uri", "path", "redirect", "next", "target", "dest", "callback", "src"):
                continue
            for payload in SSRF_PAYLOADS:
                test_url = _inject_param(url, param, payload)
                response = await client.get(test_url)
                if response is None:
                    continue
                try:
                    body = await response.text(errors="ignore")
                except Exception:
                    continue
                if SSRF_RESPONSE_HINTS.search(body):
                    severity, score, vector = get_preset("ssrf")
                    findings.append(
                        Finding(
                            id="",
                            name="Server-Side Request Forgery (SSRF)",
                            category="OWASP A10:2021 - Server-Side Request Forgery",
                            severity=severity,
                            cvss_score=score,
                            cvss_vector=vector,
                            url=test_url,
                            parameter=param,
                            evidence_poc="Response content suggests the server fetched an internal/loopback "
                            "resource on behalf of the request.",
                            remediation="Implement strict allow-listing of outbound destinations and block "
                            "requests to private/loopback IP ranges at the network layer.",
                        )
                    )
                    break
    return findings

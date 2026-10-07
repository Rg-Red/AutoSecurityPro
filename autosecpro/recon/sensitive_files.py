"""Exposed sensitive file and directory discovery."""

from __future__ import annotations

import asyncio

from autosecpro.core.http_client import AsyncHttpClient
from autosecpro.core.models import Finding, ScanContext, Severity

SENSITIVE_PATHS: list[tuple[str, Severity]] = [
    ("/.git/HEAD", Severity.HIGH),
    ("/.env", Severity.CRITICAL),
    ("/config.json", Severity.MEDIUM),
    ("/backup.zip", Severity.HIGH),
    ("/dump.sql", Severity.CRITICAL),
    ("/phpinfo.php", Severity.MEDIUM),
    ("/.htaccess", Severity.MEDIUM),
    ("/wp-config.php.bak", Severity.CRITICAL),
    ("/.DS_Store", Severity.LOW),
    ("/composer.json", Severity.LOW),
    ("/package.json", Severity.LOW),
    ("/id_rsa", Severity.CRITICAL),
]

# Standard, benign public files. Their presence is expected web hygiene and
# must never be reported as a security vulnerability. Instead they are
# recorded as informational observations only.
BENIGN_PUBLIC_PATHS: list[str] = [
    "/robots.txt",
    "/sitemap.xml",
    "/.well-known/security.txt",
]

BENIGN_PUBLIC_PATH_LABELS: dict[str, str] = {
    "/robots.txt": "Public robots.txt Detected",
    "/sitemap.xml": "Public sitemap.xml Detected",
    "/.well-known/security.txt": "Public security.txt Detected",
}

CVSS_BY_SEVERITY = {
    Severity.CRITICAL: (9.1, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"),
    Severity.HIGH: (7.5, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"),
    Severity.MEDIUM: (5.3, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N"),
    Severity.LOW: (3.1, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N"),
    Severity.INFO: (0.0, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N"),
}


async def _check_path(client: AsyncHttpClient, base_url: str, path: str, severity: Severity) -> Finding | None:
    url = base_url + path
    response = await client.get(url, allow_redirects=False)
    if response is None:
        return None
    if response.status != 200:
        return None

    try:
        body = await response.text(errors="ignore")
    except Exception:
        body = ""
    if len(body.strip()) == 0:
        return None

    score, vector = CVSS_BY_SEVERITY[severity]
    return Finding(
        id="",
        name=f"Exposed Sensitive File: {path}",
        category="OWASP A05:2021 - Security Misconfiguration",
        severity=severity,
        cvss_score=score,
        cvss_vector=vector,
        url=url,
        remediation=f"Remove or restrict public access to '{path}' via web server configuration or access control rules.",
        evidence_poc=f"HTTP 200 OK response received for '{path}' with non-empty body content.",
    )


async def _check_benign_path(client: AsyncHttpClient, base_url: str, path: str) -> dict | None:
    """Probe a standard, benign public path and record it as an informational
    observation rather than a vulnerability finding.
    """
    url = base_url + path
    response = await client.get(url, allow_redirects=False)
    if response is None:
        return None
    if response.status != 200:
        return None

    try:
        body = await response.text(errors="ignore")
    except Exception:
        body = ""
    if len(body.strip()) == 0:
        return None

    return {
        "name": BENIGN_PUBLIC_PATH_LABELS.get(path, f"Public File Detected: {path}"),
        "category": "Informational",
        "url": url,
        "evidence": f"HTTP 200 OK response received for '{path}' with non-empty body content.",
        "remediation": "No action required; this is a standard, benign publicly served file "
        "and its presence is not a vulnerability.",
    }


async def run_sensitive_file_discovery(client: AsyncHttpClient, context: ScanContext) -> None:
    """Probe for common exposed sensitive files and directories."""
    base_url = context.target.base_url
    semaphore = asyncio.Semaphore(context.concurrency)

    async def bound_check(path: str, severity: Severity) -> Finding | None:
        async with semaphore:
            return await _check_path(client, base_url, path, severity)

    async def bound_benign_check(path: str) -> dict | None:
        async with semaphore:
            return await _check_benign_path(client, base_url, path)

    results = await asyncio.gather(
        *(bound_check(path, severity) for path, severity in SENSITIVE_PATHS),
        return_exceptions=True,
    )

    counter = len(context.findings) + 1
    for result in results:
        context.endpoints_scanned += 1
        if isinstance(result, Finding):
            result.id = f"SEC-VULN-{counter:03d}"
            counter += 1
            context.discovered_endpoints.add(result.url)
            context.add_finding(result)

    benign_results = await asyncio.gather(
        *(bound_benign_check(path) for path in BENIGN_PUBLIC_PATHS),
        return_exceptions=True,
    )
    for result in benign_results:
        context.endpoints_scanned += 1
        if isinstance(result, dict):
            context.discovered_endpoints.add(result["url"])
            context.informational_observations.append(result)

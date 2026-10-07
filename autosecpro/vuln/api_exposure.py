"""API Security Exposure Analyzer.

Aggregates API documentation discovery, endpoint inventory, safe BOLA/IDOR
indicator analysis, and bounded rate-limit checking into a single, safe-only
scan phase. All network activity is read-only (GET requests) and strictly
bounded by :class:`~autosecpro.core.config.ApiSecurityConfig` limits.

No destructive or exploitative requests are ever issued. Findings are
classified with an explicit `verification_status` ("observed", "potential",
or "verified") so passive observations are never conflated with confirmed
issues. Sensitive values (tokens, cookies, authorization headers) are never
logged or included in findings.
"""

from __future__ import annotations

import logging
import time
from typing import Any, Optional

from autosecpro.core.http_client import AsyncHttpClient
from autosecpro.core.config import ApiSecurityConfig
from autosecpro.core import bola_detector
from autosecpro.core.models import (
    ApiCvss,
    ApiFinding,
    Confidence,
    EndpointInventoryItem,
    RateLimitObservation,
    ScanContext,
    Severity,
    VerificationStatus,
)
from autosecpro.recon import api_discovery

logger = logging.getLogger(__name__)

# Keywords indicating a sensitive resource category, used to tag endpoints.
_SENSITIVITY_KEYWORDS = ("user", "account", "order", "invoice", "profile", "admin", "payment", "billing", "token", "key")


def _path_from_url(base_url: str, url: str) -> str:
    """Extract the path component of `url` relative to `base_url`."""
    path = url[len(base_url):] if url.startswith(base_url) else url
    if not path.startswith("/"):
        path = f"/{path}"
    return path.split("?", 1)[0]


def _classify_sensitivity(path: str) -> list[str]:
    """Return sensitivity tags for a path based on known-sensitive keywords."""
    lowered = path.lower()
    return [keyword for keyword in _SENSITIVITY_KEYWORDS if keyword in lowered]


def _has_id_segment(path: str) -> bool:
    """Return True if any path segment looks like an object identifier."""
    return bola_detector.has_id_path_segment(path)


def build_endpoint_inventory(context: ScanContext) -> list[EndpointInventoryItem]:
    """Build a lightweight endpoint inventory from discovered crawl data.

    This is a conservative, passive classification pass over endpoints that
    were already discovered during recon (crawling, documentation probing);
    it issues no additional network requests.

    Both genuinely discovered endpoints (`context.discovered_endpoints`, from
    crawling/robots/sitemap) and speculative documentation/API probe hits
    (`context.auxiliary_probe_targets`) are included in the inventory, but
    the two sources remain separately tracked in the report metrics so a
    handful of guessed probe URLs is never reported as if it were organic
    discovery.
    """
    base_url = context.target.base_url
    inventory: list[EndpointInventoryItem] = []
    seen_paths: set[str] = set()

    all_urls = sorted(context.discovered_endpoints | context.auxiliary_probe_targets)
    for url in all_urls:
        path = _path_from_url(base_url, url)
        if path in seen_paths:
            continue
        seen_paths.add(path)

        sensitivity_tags = _classify_sensitivity(path)
        risk_indicators = []
        if _has_id_segment(path):
            risk_indicators.append("object_identifier_in_path")
        if bola_detector.find_id_query_params(url):
            risk_indicators.append("object_identifier_in_query_param")
        if sensitivity_tags:
            risk_indicators.append("sensitive_resource_keyword")

        inventory.append(
            EndpointInventoryItem(
                method="GET",
                path=path,
                source_url=url,
                sensitivity_tags=sensitivity_tags,
                requires_auth=None,
                risk_indicators=risk_indicators,
            )
        )

    context.api_security.endpoint_inventory = inventory
    return inventory


def analyze_bola_indicators(context: ScanContext, inventory: list[EndpointInventoryItem]) -> list[ApiFinding]:
    """Flag endpoints with object-identifier path segments or query parameters
    as potential BOLA/IDOR candidates.

    This is a passive, pattern-based analysis only. No authorization bypass
    is attempted, no authentication, tokens, or credentials are ever used,
    and only publicly observable path/query structure is inspected.
    Findings are always reported with `verification_status` set to
    "potential" and require manual or authorized follow-up review.
    """
    findings: list[ApiFinding] = []
    for item in inventory:
        has_path_indicator = "object_identifier_in_path" in item.risk_indicators
        has_query_indicator = "object_identifier_in_query_param" in item.risk_indicators
        if not has_path_indicator and not has_query_indicator:
            continue

        severity = Severity.MEDIUM if item.sensitivity_tags else Severity.LOW
        dedup_key = f"bola:{item.method}:{item.path}"
        evidence = []
        if has_path_indicator:
            evidence.append(f"Path contains an object identifier segment: {item.path}")
        if has_query_indicator:
            evidence.append(f"URL query string contains an object identifier parameter: {item.source_url}")
        finding = ApiFinding(
            id=f"API-BOLA-{len(findings) + 1:03d}",
            category="Broken Object Level Authorization",
            title=f"Potential BOLA/IDOR exposure on {item.method} {item.path}",
            severity=severity,
            confidence=Confidence.LOW,
            cvss=ApiCvss(),
            asset=item.source_url,
            verification_status=VerificationStatus.POTENTIAL,
            evidence=evidence,
            affected_endpoints=[item.path],
            safe_poc_steps=[
                "Manually review whether object ownership is enforced server-side for this identifier.",
                "No authorization bypass was attempted automatically.",
            ],
            impact="If ownership checks are missing, an authenticated user could access or modify objects "
            "belonging to other users by changing the identifier.",
            remediation=[
                "Enforce server-side object ownership checks on every request that accepts an object identifier.",
                "Prefer indirect, non-guessable references (e.g. per-user opaque tokens) over sequential IDs.",
            ],
            false_positive_notes="Automatically flagged from public path/query structure only; no authenticated "
            "requests, tokens, or credentials were used, and no request testing was performed.",
            dedup_key=dedup_key,
        )
        findings.append(finding)

    context.api_security.findings.extend(findings)
    return findings


async def check_rate_limits(
    client: AsyncHttpClient,
    context: ScanContext,
    inventory: list[EndpointInventoryItem],
    max_requests_per_endpoint: int = 2,
    max_endpoints: int = 10,
) -> list[RateLimitObservation]:
    """Passively probe a small, bounded sample of endpoints for rate-limit signals.

    Only GET requests are issued, at most `max_requests_per_endpoint` per
    endpoint across at most `max_endpoints` endpoints, to keep the check
    safe and low-volume.
    """
    observations: list[RateLimitObservation] = []
    base_url = context.target.base_url

    for item in inventory[:max_endpoints]:
        url = base_url + item.path
        status_codes: list[int] = []
        timing_ms: list[float] = []
        relevant_headers: dict[str, str] = {}

        for _ in range(max(1, max_requests_per_endpoint)):
            start = time.monotonic()
            response = await client.get(url)
            elapsed = (time.monotonic() - start) * 1000
            if response is None:
                continue
            status_codes.append(response.status)
            timing_ms.append(elapsed)
            for header_name in ("X-RateLimit-Limit", "X-RateLimit-Remaining", "RateLimit-Limit", "Retry-After"):
                header_value = response.headers.get(header_name)
                if header_value:
                    relevant_headers[header_name] = header_value
            response.release()

        if not status_codes:
            continue

        signal_observed = bool(relevant_headers) or 429 in status_codes
        observations.append(
            RateLimitObservation(
                endpoint=item.path,
                method=item.method,
                status_codes=status_codes,
                relevant_headers=relevant_headers,
                timing_ms=timing_ms,
                signal_observed=signal_observed,
                confidence=Confidence.LOW,
                limitations="Low-volume, non-destructive sampling only; absence of a signal does not "
                "guarantee no rate limiting is configured.",
            )
        )

    context.api_security.rate_limit_observations = observations
    return observations


async def run_api_security_scan(
    client: AsyncHttpClient,
    context: ScanContext,
    config: Optional[ApiSecurityConfig] = None,
) -> dict[str, Any]:
    """Run the full, safe-only API Security Exposure Analyzer against `context.target`.

    Workflow: documentation discovery -> endpoint inventory -> BOLA
    indicator analysis -> bounded rate-limit checking. All results are
    written into `context.api_security` and a compact summary is returned.
    """
    config = config or ApiSecurityConfig()
    if not config.enabled:
        logger.info("API Security Exposure Analyzer disabled by configuration; skipping.")
        return {"enabled": False}

    logger.info("Starting API Security Exposure Analyzer for target=%s", context.target.host)

    if config.discover_docs and not context.api_security.documentation_targets:
        await api_discovery.run_documentation_discovery(
            client,
            context,
            max_requests=config.max_doc_requests,
            max_response_bytes=config.max_response_bytes,
        )

    inventory = build_endpoint_inventory(context)
    bola_findings = analyze_bola_indicators(context, inventory)

    rate_limit_observations: list[RateLimitObservation] = []
    if config.check_rate_limits:
        rate_limit_observations = await check_rate_limits(
            client,
            context,
            inventory,
            max_requests_per_endpoint=config.max_requests_per_endpoint,
        )

    if not config.enable_authorized_safe_bola_check:
        context.api_security.limitations.append(
            "Authorized safe BOLA comparison check was not enabled; only passive path-based indicators were analyzed."
        )

    logger.info(
        "API Security Exposure Analyzer complete: %d documented targets, %d inventory items, "
        "%d BOLA indicators, %d rate limit observations.",
        len(context.api_security.documentation_targets),
        len(inventory),
        len(bola_findings),
        len(rate_limit_observations),
    )

    return {
        "documentation_targets": len(context.api_security.documentation_targets),
        "endpoint_inventory": len(inventory),
        "bola_findings": len(bola_findings),
        "rate_limit_observations": len(rate_limit_observations),
    }

"""API route enumeration: Swagger/OpenAPI discovery and safe GraphQL introspection."""

from __future__ import annotations

import asyncio
import json
import time
from typing import Optional

from autosecpro.core.http_client import AsyncHttpClient
from autosecpro.core.models import DocumentationTarget, ScanContext

SWAGGER_PATHS = [
    "/swagger.json",
    "/swagger/v1/swagger.json",
    "/v2/api-docs",
    "/v3/api-docs",
    "/api-docs",
    "/docs",
    "/redoc",
    "/openapi.json",
]

GRAPHQL_PATHS = ["/graphql", "/graphiql", "/api/graphql", "/v1/graphql"]

INTROSPECTION_QUERY = {
    "query": "query IntrospectionQuery { __schema { queryType { name } "
    "mutationType { name } types { name kind description } } }"
}


async def discover_swagger(client: AsyncHttpClient, context: ScanContext) -> None:
    """Probe standard paths for exposed Swagger / OpenAPI documentation."""
    base_url = context.target.base_url
    for path in SWAGGER_PATHS:
        url = base_url + path
        response = await client.get(url, allow_redirects=True)
        context.endpoints_scanned += 1
        if response is None or response.status != 200:
            continue
        content_type = response.headers.get("Content-Type", "")
        if "json" in content_type or "html" in content_type:
            context.auxiliary_probe_targets.add(url)


async def discover_graphql(client: AsyncHttpClient, context: ScanContext) -> None:
    """Probe standard GraphQL endpoints and safely run an introspection query."""
    base_url = context.target.base_url
    for path in GRAPHQL_PATHS:
        url = base_url + path
        response = await client.post(
            url,
            json=INTROSPECTION_QUERY,
            headers={"Content-Type": "application/json"},
        )
        context.endpoints_scanned += 1
        if response is None or response.status not in (200, 400):
            continue
        try:
            payload = await response.json(content_type=None)
        except Exception:
            continue
        if isinstance(payload, dict) and "data" in payload and payload.get("data", {}).get("__schema"):
            context.auxiliary_probe_targets.add(url)
            context.graphql_schema = payload["data"]["__schema"]
            break


# ---------------------------------------------------------------------------
# Safe API Documentation Discovery Engine (API Security Exposure Analyzer)
# ---------------------------------------------------------------------------

# Standard, non-versioned documentation candidate paths (Feature 1).
API_DOC_PATHS: list[str] = [
    "/swagger",
    "/swagger/",
    "/swagger/index.html",
    "/swagger-ui",
    "/swagger-ui/",
    "/swagger-ui.html",
    "/swagger.json",
    "/swagger.yaml",
    "/swagger/v1/swagger.json",
    "/swagger/v2/swagger.json",
    "/swagger/v3/swagger.json",
    "/openapi.json",
    "/openapi.yaml",
    "/openapi.yml",
    "/api-docs",
    "/api-docs/",
    "/docs",
    "/docs/",
    "/redoc",
    "/redoc/",
    "/v2/api-docs",
    "/v3/api-docs",
    "/api/swagger.json",
    "/api/openapi.json",
    "/api/docs",
    "/api/docs/openapi.json",
]

# Versioned documentation candidate paths (Feature 4 - API-VERSION-ENUMERATION).
API_VERSIONED_DOC_PATHS: list[str] = [
    "/v1/swagger.json",
    "/v2/swagger.json",
    "/v3/swagger.json",
    "/v1/openapi.json",
    "/v2/openapi.json",
    "/v3/openapi.json",
    "/v1/api-docs",
    "/v2/api-docs",
    "/v3/api-docs",
]

_SWAGGER_UI_MARKERS = ("swagger-ui", "swagger ui", "swaggerui", "swagger-ui-bundle")
_REDOC_MARKERS = ("redoc", "spec-url", "redoc.standalone")


def _looks_like_openapi_structure(text: str) -> tuple[bool, str]:
    """Return (is_openapi_like, kind) based on structural JSON/YAML evidence only.

    A generic JSON response must never be labeled as OpenAPI/Swagger without
    finding the characteristic top-level keys (an `openapi`/`swagger` version
    marker combined with a `paths` or `info` object).
    """
    stripped = text.strip()
    if not stripped:
        return False, ""

    parsed: Optional[dict] = None
    if stripped.startswith("{"):
        try:
            candidate = json.loads(stripped)
            if isinstance(candidate, dict):
                parsed = candidate
        except (json.JSONDecodeError, ValueError):
            parsed = None

    if parsed is None:
        try:
            import yaml  # optional dependency; degrades gracefully if absent

            candidate = yaml.safe_load(stripped)
            if isinstance(candidate, dict):
                parsed = candidate
        except Exception:
            parsed = None

    if parsed is None:
        return False, ""

    has_version_marker = "openapi" in parsed or "swagger" in parsed
    has_structure = "paths" in parsed or "info" in parsed
    if has_version_marker and has_structure:
        kind = "openapi" if "openapi" in parsed else "swagger"
        return True, kind
    return False, ""


def detect_documentation_kind(content_type: str, body: str) -> tuple[bool, str]:
    """Detect whether a response body represents API documentation, and its kind.

    Detection relies on content type plus structural/HTML markers so that a
    generic JSON or HTML page is never misclassified as documentation.
    """
    content_type = (content_type or "").lower()
    lowered_body = (body or "")[:200_000].lower()

    if "html" in content_type or "<html" in lowered_body[:2000]:
        if any(marker in lowered_body for marker in _SWAGGER_UI_MARKERS):
            return True, "swagger-ui"
        if any(marker in lowered_body for marker in _REDOC_MARKERS):
            return True, "redoc"
        return False, ""

    if "json" in content_type or "yaml" in content_type or "yml" in content_type or body.strip()[:1] in ("{", "-"):
        is_openapi, kind = _looks_like_openapi_structure(body)
        if is_openapi:
            return True, kind

    return False, ""


def _dedupe_paths(paths: list[str]) -> list[str]:
    seen: set[str] = set()
    ordered: list[str] = []
    for path in paths:
        normalized = path if path.startswith("/") else f"/{path}"
        if normalized not in seen:
            seen.add(normalized)
            ordered.append(normalized)
    return ordered


async def probe_documentation_url(
    client: AsyncHttpClient, url: str, max_response_bytes: int = 2_000_000
) -> DocumentationTarget:
    """Safely probe a single candidate documentation URL and record structured evidence."""
    start = time.monotonic()
    try:
        response = await client.get(url, allow_redirects=True)
    except Exception as exc:  # defensive: never let a single probe crash the scan
        return DocumentationTarget(
            requested_url=url,
            final_url=url,
            method="GET",
            status_code=None,
            error=str(exc),
        )
    elapsed_ms = (time.monotonic() - start) * 1000

    if response is None:
        return DocumentationTarget(
            requested_url=url,
            final_url=url,
            method="GET",
            status_code=None,
            response_time_ms=elapsed_ms,
            error="No response (connection error, timeout, or blocked request).",
        )

    redirect_chain = [str(hist.url) for hist in response.history] if response.history else []
    final_url = str(response.url)
    content_type = response.headers.get("Content-Type", "")
    www_authenticate = response.headers.get("WWW-Authenticate")
    auth_challenge = response.status in (401, 403) or www_authenticate is not None

    body = ""
    content_length = 0
    try:
        raw = await response.content.read(max_response_bytes)
        content_length = len(raw)
        body = raw.decode("utf-8", errors="ignore")
    except Exception:
        body = ""
    finally:
        response.release()

    looks_like_doc = False
    doc_kind = ""
    if response.status == 200:
        looks_like_doc, doc_kind = detect_documentation_kind(content_type, body)

    return DocumentationTarget(
        requested_url=url,
        final_url=final_url,
        method="GET",
        status_code=response.status,
        content_type=content_type,
        content_length=content_length,
        response_time_ms=elapsed_ms,
        redirect_chain=redirect_chain,
        auth_challenge=auth_challenge,
        www_authenticate=www_authenticate,
        looks_like_documentation=looks_like_doc,
        doc_kind=doc_kind,
        accessible_without_auth=(response.status == 200 and not auth_challenge),
        error=None,
    )


async def run_documentation_discovery(
    client: AsyncHttpClient,
    context: ScanContext,
    max_requests: int = 50,
    concurrency: int = 10,
    max_response_bytes: int = 2_000_000,
    include_versioned: bool = True,
) -> None:
    """Run the safe, bounded API documentation discovery engine (Feature 1 & 4).

    Probes standard and versioned documentation candidate paths using GET
    requests only, deduplicates by normalized path, and enforces a hard cap
    on the total number of requests issued (`max_requests`).
    """
    base_url = context.target.base_url
    candidate_paths = _dedupe_paths(API_DOC_PATHS)
    if include_versioned:
        candidate_paths.extend(p for p in _dedupe_paths(API_VERSIONED_DOC_PATHS) if p not in candidate_paths)

    candidate_paths = candidate_paths[:max_requests]
    semaphore = asyncio.Semaphore(max(1, concurrency))

    async def bound_probe(path: str) -> DocumentationTarget:
        async with semaphore:
            url = base_url + path
            return await probe_documentation_url(client, url, max_response_bytes=max_response_bytes)

    results = await asyncio.gather(*(bound_probe(path) for path in candidate_paths), return_exceptions=True)

    seen_final_urls: set[str] = set()
    for result in results:
        context.endpoints_scanned += 1
        if not isinstance(result, DocumentationTarget):
            continue
        if result.final_url in seen_final_urls:
            continue
        seen_final_urls.add(result.final_url)
        context.api_security.documentation_targets.append(result)
        if result.looks_like_documentation:
            context.auxiliary_probe_targets.add(result.final_url)

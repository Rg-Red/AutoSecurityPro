"""Core data models and enumerations shared across AutoSecurityPro modules."""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Optional


class Severity(str, Enum):
    """Standard severity classification for findings."""

    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"

    @property
    def weight(self) -> int:
        """Return the risk weight used for the overall security score calculation."""
        return {
            Severity.CRITICAL: 25,
            Severity.HIGH: 15,
            Severity.MEDIUM: 7,
            Severity.LOW: 3,
            Severity.INFO: 0,
        }[self]

    @property
    def style(self) -> str:
        """Return the `rich` markup style associated with this severity."""
        return {
            Severity.CRITICAL: "bold white on red",
            Severity.HIGH: "bold red",
            Severity.MEDIUM: "bold yellow",
            Severity.LOW: "bold cyan",
            Severity.INFO: "bold green",
        }[self]


class Confidence(str, Enum):
    """Confidence level for an API security finding or observation."""

    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"


class VerificationStatus(str, Enum):
    """Verification status describing how strongly a finding was established."""

    OBSERVED = "observed"
    POTENTIAL = "potential"
    VERIFIED = "verified"
    INCONCLUSIVE = "inconclusive"
    NOT_VERIFIED = "not_verified"


@dataclass(slots=True)
class Target:
    """Normalized representation of the assessment target."""

    raw_input: str
    host: str
    is_ip: bool
    scheme: str = "https"
    port: Optional[int] = None
    resolved_ip: Optional[str] = None
    base_url: str = ""

    def __post_init__(self) -> None:
        if not self.base_url:
            self.base_url = self.build_url()

    def build_url(self) -> str:
        """Construct the fully qualified base URL for this target."""
        netloc = self.host
        default_port = 443 if self.scheme == "https" else 80
        if self.port and self.port != default_port:
            netloc = f"{self.host}:{self.port}"
        return f"{self.scheme}://{netloc}"


@dataclass(slots=True)
class Finding:
    """A single security finding discovered during the assessment."""

    id: str
    name: str
    category: str
    severity: Severity
    cvss_score: float
    cvss_vector: str
    url: str
    remediation: str
    parameter: Optional[str] = None
    evidence_poc: str = ""
    extra: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        """Serialize the finding into a JSON-safe dictionary."""
        payload = {
            "id": self.id,
            "name": self.name,
            "category": self.category,
            "severity": self.severity.value,
            "cvss_score": self.cvss_score,
            "cvss_vector": self.cvss_vector,
            "url": self.url,
            "parameter": self.parameter,
            "evidence_poc": self.evidence_poc,
            "remediation": self.remediation,
        }
        if self.extra:
            payload.update(self.extra)
        return payload


def _iso_from_timestamp(timestamp: float) -> str:
    """Format a UNIX timestamp as an ISO-8601 UTC string."""
    from datetime import datetime, timezone

    return datetime.fromtimestamp(timestamp, tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


@dataclass(slots=True)
class ApiCvss:
    """CVSS v3.1 metadata attached to an API security finding."""

    version: str = "3.1"
    vector: Optional[str] = None
    base_score: float = 0.0

    def to_dict(self) -> dict[str, Any]:
        return {"version": self.version, "vector": self.vector, "base_score": self.base_score}


@dataclass(slots=True)
class ApiFinding:
    """A single API security finding produced by the API Exposure Analyzer.

    Distinct from :class:`Finding` in that it carries explicit confidence and
    verification-status metadata, so observations, potential indicators, and
    safely verified issues are never conflated with confirmed exploitation.
    """

    id: str
    category: str
    title: str
    severity: Severity
    confidence: Confidence
    cvss: ApiCvss
    asset: str
    verification_status: VerificationStatus
    evidence: list[str] = field(default_factory=list)
    affected_endpoints: list[str] = field(default_factory=list)
    safe_poc_steps: list[str] = field(default_factory=list)
    impact: str = ""
    remediation: list[str] = field(default_factory=list)
    references: list[str] = field(default_factory=list)
    false_positive_notes: str = ""
    timestamp: float = field(default_factory=time.time)
    dedup_key: str = ""

    def to_dict(self) -> dict[str, Any]:
        """Serialize the API finding into a JSON-safe dictionary."""
        return {
            "id": self.id,
            "category": self.category,
            "title": self.title,
            "severity": self.severity.value,
            "confidence": self.confidence.value,
            "cvss": self.cvss.to_dict(),
            "asset": self.asset,
            "evidence": self.evidence,
            "affected_endpoints": self.affected_endpoints,
            "verification_status": self.verification_status.value,
            "safe_poc_steps": self.safe_poc_steps,
            "impact": self.impact,
            "remediation": self.remediation,
            "references": self.references,
            "false_positive_notes": self.false_positive_notes,
            "timestamp": _iso_from_timestamp(self.timestamp),
        }


@dataclass(slots=True)
class DocumentationTarget:
    """Result of probing a single candidate API documentation URL."""

    requested_url: str
    final_url: str
    method: str
    status_code: Optional[int]
    content_type: str = ""
    content_length: int = 0
    response_time_ms: float = 0.0
    redirect_chain: list[str] = field(default_factory=list)
    auth_challenge: bool = False
    www_authenticate: Optional[str] = None
    looks_like_documentation: bool = False
    doc_kind: str = ""  # "swagger-ui", "openapi", "swagger", "redoc", "unknown"
    accessible_without_auth: bool = False
    error: Optional[str] = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "requested_url": self.requested_url,
            "final_url": self.final_url,
            "method": self.method,
            "status_code": self.status_code,
            "content_type": self.content_type,
            "content_length": self.content_length,
            "response_time_ms": round(self.response_time_ms, 2),
            "redirect_chain": self.redirect_chain,
            "auth_challenge": self.auth_challenge,
            "www_authenticate": self.www_authenticate,
            "looks_like_documentation": self.looks_like_documentation,
            "doc_kind": self.doc_kind,
            "accessible_without_auth": self.accessible_without_auth,
            "error": self.error,
        }


@dataclass(slots=True)
class OpenApiSchemaInfo:
    """Parsed summary of a single OpenAPI/Swagger schema document."""

    source_url: str
    spec_version: str = ""  # "2.0", "3.0.x", "3.1.x"
    title: str = ""
    version: str = ""
    servers: list[str] = field(default_factory=list)
    base_path: str = ""
    schemes: list[str] = field(default_factory=list)
    path_count: int = 0
    operation_count: int = 0
    tags: list[str] = field(default_factory=list)
    security_schemes: list[str] = field(default_factory=list)
    global_security_defined: bool = False
    deprecated_operation_count: int = 0
    schema_names: list[str] = field(default_factory=list)
    external_refs: list[str] = field(default_factory=list)
    parse_warnings: list[str] = field(default_factory=list)
    parse_errors: list[str] = field(default_factory=list)
    truncated: bool = False

    def to_dict(self) -> dict[str, Any]:
        return {
            "source_url": self.source_url,
            "spec_version": self.spec_version,
            "title": self.title,
            "version": self.version,
            "servers": self.servers,
            "base_path": self.base_path,
            "schemes": self.schemes,
            "path_count": self.path_count,
            "operation_count": self.operation_count,
            "tags": self.tags,
            "security_schemes": self.security_schemes,
            "global_security_defined": self.global_security_defined,
            "deprecated_operation_count": self.deprecated_operation_count,
            "schema_names": self.schema_names,
            "external_refs": self.external_refs,
            "parse_warnings": self.parse_warnings,
            "parse_errors": self.parse_errors,
            "truncated": self.truncated,
        }


@dataclass(slots=True)
class EndpointInventoryItem:
    """A single documented API operation with sensitivity classification."""

    method: str
    path: str
    source_url: str
    operation_id: str = ""
    tags: list[str] = field(default_factory=list)
    sensitivity_tags: list[str] = field(default_factory=list)
    path_parameters: list[str] = field(default_factory=list)
    query_parameters: list[str] = field(default_factory=list)
    body_fields: list[str] = field(default_factory=list)
    response_fields: list[str] = field(default_factory=list)
    requires_auth: Optional[bool] = None
    deprecated: bool = False
    external_refs: list[str] = field(default_factory=list)
    risk_indicators: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "method": self.method,
            "path": self.path,
            "source_url": self.source_url,
            "operation_id": self.operation_id,
            "tags": self.tags,
            "sensitivity_tags": self.sensitivity_tags,
            "path_parameters": self.path_parameters,
            "query_parameters": self.query_parameters,
            "body_fields": self.body_fields,
            "response_fields": self.response_fields,
            "requires_auth": self.requires_auth,
            "deprecated": self.deprecated,
            "external_refs": self.external_refs,
            "risk_indicators": self.risk_indicators,
        }


@dataclass(slots=True)
class AuthAnalysisResult:
    """Authentication requirement analysis for a single documentation URL."""

    url: str
    accessible_without_auth: bool = False
    returns_401_or_403: bool = False
    has_www_authenticate: bool = False
    redirects_to_login: bool = False
    requires_cookie: bool = False
    requires_bearer_token: bool = False
    requires_api_key: bool = False
    auth_behavior_confidence: Confidence = Confidence.LOW
    classification: str = "inconclusive"
    # classification values:
    # public_by_design | public_but_sensitive | protected | inaccessible | inconclusive

    def to_dict(self) -> dict[str, Any]:
        return {
            "url": self.url,
            "accessible_without_auth": self.accessible_without_auth,
            "returns_401_or_403": self.returns_401_or_403,
            "has_www_authenticate": self.has_www_authenticate,
            "redirects_to_login": self.redirects_to_login,
            "requires_cookie": self.requires_cookie,
            "requires_bearer_token": self.requires_bearer_token,
            "requires_api_key": self.requires_api_key,
            "auth_behavior_confidence": self.auth_behavior_confidence.value,
            "classification": self.classification,
        }


@dataclass(slots=True)
class RateLimitObservation:
    """Result of a conservative, bounded rate-limit presence check."""

    endpoint: str
    method: str
    status_codes: list[int] = field(default_factory=list)
    relevant_headers: dict[str, str] = field(default_factory=dict)
    timing_ms: list[float] = field(default_factory=list)
    signal_observed: bool = False
    confidence: Confidence = Confidence.LOW
    limitations: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "endpoint": self.endpoint,
            "method": self.method,
            "status_codes": self.status_codes,
            "relevant_headers": self.relevant_headers,
            "timing_ms": [round(value, 2) for value in self.timing_ms],
            "signal_observed": self.signal_observed,
            "confidence": self.confidence.value,
            "limitations": self.limitations,
        }


@dataclass(slots=True)
class ApiSecurityState:
    """Aggregated state produced by the API Security Exposure Analyzer."""

    documentation_targets: list[DocumentationTarget] = field(default_factory=list)
    openapi_schemas: list[OpenApiSchemaInfo] = field(default_factory=list)
    endpoint_inventory: list[EndpointInventoryItem] = field(default_factory=list)
    authentication_analysis: list[AuthAnalysisResult] = field(default_factory=list)
    rate_limit_observations: list[RateLimitObservation] = field(default_factory=list)
    findings: list[ApiFinding] = field(default_factory=list)
    limitations: list[str] = field(default_factory=list)


@dataclass(slots=True)
class RequestStats:
    """Aggregate HTTP request counters collected over a full scan run.

    Populated from :class:`~autosecpro.core.http_client.AsyncHttpClient`
    counters once the scan session closes; used to compute coverage and
    confidence metrics independently of the Security Health Score.
    """

    total_requests: int = 0
    successful_requests: int = 0
    failed_requests: int = 0
    timeout_count: int = 0

    def to_dict(self) -> dict[str, Any]:
        return {
            "total_requests": self.total_requests,
            "successful_requests": self.successful_requests,
            "failed_requests": self.failed_requests,
            "timeout_count": self.timeout_count,
        }


@dataclass(slots=True)
class ScanContext:
    """Mutable shared state passed between all scan modules during a run."""

    target: Target
    tor_enabled: bool = False
    proxy_file: Optional[str] = None
    cookie: Optional[str] = None
    jwt: Optional[str] = None
    timeout: float = 10.0
    concurrency: int = 10
    findings: list[Finding] = field(default_factory=list)
    discovered_subdomains: set[str] = field(default_factory=set)
    dangling_subdomains: list[str] = field(default_factory=list)
    discovered_endpoints: set[str] = field(default_factory=set)
    # Guessed Swagger/OpenAPI/GraphQL/documentation probe URLs that returned a
    # positive hit. Kept separate from `discovered_endpoints` so reports never
    # conflate genuinely crawled/robots/sitemap endpoints with speculative probes.
    auxiliary_probe_targets: set[str] = field(default_factory=set)
    # Benign, non-vulnerability recon observations (e.g. a public robots.txt).
    informational_observations: list[dict[str, Any]] = field(default_factory=list)
    discovered_forms: list[dict[str, Any]] = field(default_factory=list)
    discovered_js_files: set[str] = field(default_factory=set)
    detected_technologies: set[str] = field(default_factory=set)
    server_banner: Optional[str] = None
    operating_system: Optional[str] = None
    google_dorks_found: list[dict[str, Any]] = field(default_factory=list)
    graphql_schema: Optional[dict[str, Any]] = None
    started_at: float = field(default_factory=time.time)
    finished_at: Optional[float] = None
    endpoints_scanned: int = 0
    request_stats: RequestStats = field(default_factory=RequestStats)
    api_security: ApiSecurityState = field(default_factory=ApiSecurityState)

    def add_finding(self, finding: Finding) -> None:
        """Register a new finding into the shared scan context."""
        self.findings.append(finding)

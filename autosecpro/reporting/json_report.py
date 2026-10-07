"""Structured JSON report generation for completed AutoSecurityPro scans."""

from __future__ import annotations

import json
import re
import time
from datetime import datetime, timezone
from pathlib import Path

from autosecpro import __version__
from autosecpro.core.models import ScanContext
from autosecpro.core.metrics import compute_scan_metrics
from autosecpro.vuln.scoring import compute_security_score, count_by_severity


def _iso(timestamp: float) -> str:
    return datetime.fromtimestamp(timestamp, tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _safe_filename_component(value: str) -> str:
    return re.sub(r"[^a-zA-Z0-9_.-]", "_", value)


def build_report(context: ScanContext) -> dict:
    """Assemble the full structured report dictionary from a completed scan context."""
    finished_at = context.finished_at or time.time()
    severity_counts = count_by_severity(context.findings)
    score = compute_security_score(context.findings, context.api_security.findings)
    scan_metrics = compute_scan_metrics(context)

    return {
        "scan_metadata": {
            "tool_name": "AutoSecurityPro",
            "version": __version__,
            "target": context.target.host,
            "target_ip": context.target.resolved_ip,
            "scan_started": _iso(context.started_at),
            "scan_finished": _iso(finished_at),
            "tor_enabled": context.tor_enabled,
        },
        "attack_surface_recon": {
            "server": context.server_banner,
            "operating_system": context.operating_system,
            "detected_technologies": sorted(context.detected_technologies),
            "discovered_subdomains": sorted(context.discovered_subdomains),
            "dangling_subdomains": sorted(context.dangling_subdomains),
            "discovered_endpoints": sorted(context.discovered_endpoints),
            "auxiliary_probe_targets": sorted(context.auxiliary_probe_targets),
            "discovered_js_files": sorted(context.discovered_js_files),
            "discovered_forms": context.discovered_forms,
            "graphql_schema_detected": context.graphql_schema is not None,
            "google_dorks_found": context.google_dorks_found,
        },
        "vulnerabilities": [finding.to_dict() for finding in context.findings],
        "informational_observations": context.informational_observations,
        "api_security": {
            "documentation_targets": [target.to_dict() for target in context.api_security.documentation_targets],
            "openapi_schemas": [schema.to_dict() for schema in context.api_security.openapi_schemas],
            "endpoint_inventory": [item.to_dict() for item in context.api_security.endpoint_inventory],
            "authentication_analysis": [item.to_dict() for item in context.api_security.authentication_analysis],
            "rate_limit_observations": [obs.to_dict() for obs in context.api_security.rate_limit_observations],
            "findings": [finding.to_dict() for finding in context.api_security.findings],
            "limitations": context.api_security.limitations,
        },
        "metrics": {
            "total_endpoints_scanned": context.endpoints_scanned,
            "discovered_endpoints_count": len(context.discovered_endpoints),
            "auxiliary_probe_targets_count": len(context.auxiliary_probe_targets),
            "vulnerabilities_by_severity": severity_counts,
            "overall_security_score": score,
            "coverage_percent": scan_metrics.coverage_percent,
            "confidence_score": scan_metrics.confidence_score,
            "scan_quality": scan_metrics.scan_quality.value,
            "total_requests": scan_metrics.total_requests,
            "successful_requests": scan_metrics.successful_requests,
            "failed_requests": scan_metrics.failed_requests,
            "timeout_count": scan_metrics.timeout_count,
        },
    }


def write_report(context: ScanContext, output_dir: str = "reports") -> Path:
    """Serialize the scan context into a JSON report file and return its path."""
    output_path = Path(output_dir)
    output_path.mkdir(parents=True, exist_ok=True)

    target_slug = _safe_filename_component(context.target.host)
    timestamp_slug = datetime.now().strftime("%Y%m%d_%H%M%S")
    filename = f"scan_report_{target_slug}_{timestamp_slug}.json"
    filepath = output_path / filename

    report = build_report(context)
    filepath.write_text(json.dumps(report, indent=2, ensure_ascii=False), encoding="utf-8")
    return filepath

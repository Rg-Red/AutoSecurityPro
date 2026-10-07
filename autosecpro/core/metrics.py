"""Scan coverage, confidence, and quality metrics.

These metrics describe how much of the target's attack surface was
actually observed and how reliable the collected results are. They are
computed entirely independently of the Security Health Score
(`autosecpro.vuln.scoring.compute_security_score`), which measures the
risk found rather than how complete the scan itself was. A target with
zero vulnerabilities but a failed/low-coverage scan must never be reported
as a clean, low-risk target.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Any

from autosecpro.core.models import ScanContext


class ScanQuality(str, Enum):
    """Overall reliability classification for a completed scan run."""

    COMPLETE = "COMPLETE"
    PARTIAL = "PARTIAL"
    LOW_CONFIDENCE = "LOW_CONFIDENCE"
    FAILED = "FAILED"


@dataclass(slots=True)
class ScanMetrics:
    """Computed coverage/confidence metrics for a single scan run."""

    total_requests: int
    successful_requests: int
    failed_requests: int
    timeout_count: int
    discovered_endpoints_count: int
    auxiliary_probe_targets_count: int
    coverage_percent: float
    confidence_score: int
    scan_quality: ScanQuality

    def to_dict(self) -> dict[str, Any]:
        return {
            "total_requests": self.total_requests,
            "successful_requests": self.successful_requests,
            "failed_requests": self.failed_requests,
            "timeout_count": self.timeout_count,
            "discovered_endpoints_count": self.discovered_endpoints_count,
            "auxiliary_probe_targets_count": self.auxiliary_probe_targets_count,
            "coverage_percent": self.coverage_percent,
            "confidence_score": self.confidence_score,
            "scan_quality": self.scan_quality.value,
        }


def _compute_coverage_percent(total_requests: int, successful_requests: int) -> float:
    """Return the percentage of issued requests that received a usable response."""
    if total_requests <= 0:
        return 0.0
    return round((successful_requests / total_requests) * 100, 1)


def _compute_confidence_score(
    coverage_percent: float,
    discovered_endpoints_count: int,
    timeout_count: int,
    total_requests: int,
) -> int:
    """Blend request coverage, timeout ratio, and recon yield into a 0-100 score."""
    score = coverage_percent
    if discovered_endpoints_count == 0:
        score -= 20
    if total_requests > 0:
        timeout_ratio = timeout_count / total_requests
        score -= timeout_ratio * 30
    return max(0, min(100, round(score)))


def _classify_scan_quality(
    total_requests: int,
    successful_requests: int,
    coverage_percent: float,
    confidence_score: int,
) -> ScanQuality:
    """Classify overall scan reliability from coverage and confidence figures."""
    if total_requests == 0 or successful_requests == 0:
        return ScanQuality.FAILED
    if coverage_percent >= 90 and confidence_score >= 75:
        return ScanQuality.COMPLETE
    if coverage_percent < 40 or confidence_score < 40:
        return ScanQuality.LOW_CONFIDENCE
    return ScanQuality.PARTIAL


def compute_scan_metrics(context: ScanContext) -> ScanMetrics:
    """Compute the full set of coverage/confidence metrics for `context`."""
    stats = context.request_stats
    coverage_percent = _compute_coverage_percent(stats.total_requests, stats.successful_requests)
    confidence_score = _compute_confidence_score(
        coverage_percent,
        len(context.discovered_endpoints),
        stats.timeout_count,
        stats.total_requests,
    )
    scan_quality = _classify_scan_quality(
        stats.total_requests, stats.successful_requests, coverage_percent, confidence_score
    )
    return ScanMetrics(
        total_requests=stats.total_requests,
        successful_requests=stats.successful_requests,
        failed_requests=stats.failed_requests,
        timeout_count=stats.timeout_count,
        discovered_endpoints_count=len(context.discovered_endpoints),
        auxiliary_probe_targets_count=len(context.auxiliary_probe_targets),
        coverage_percent=coverage_percent,
        confidence_score=confidence_score,
        scan_quality=scan_quality,
    )

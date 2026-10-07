"""Overall Security Health Score computation (0-100 scale)."""

from __future__ import annotations

from collections import Counter

from autosecpro.core.models import ApiFinding, Finding, Severity, VerificationStatus


def count_by_severity(findings: list[Finding]) -> dict[str, int]:
    """Count findings grouped by severity level, including zero-count levels."""
    counter = Counter(finding.severity for finding in findings)
    return {severity.value.lower(): counter.get(severity, 0) for severity in Severity}


# Verification statuses that are penalized at full weight vs. reduced weight.
# Unverified/observed indicators are discounted since they may be false positives.
_API_FINDING_WEIGHT_FACTOR = {
    VerificationStatus.VERIFIED: 1.0,
    VerificationStatus.POTENTIAL: 0.5,
    VerificationStatus.OBSERVED: 0.25,
    VerificationStatus.INCONCLUSIVE: 0.1,
    VerificationStatus.NOT_VERIFIED: 0.0,
}


def compute_security_score(findings: list[Finding], api_findings: list[ApiFinding] | None = None) -> int:
    """Compute an overall Security Health Score from 0 (critical risk) to 100 (excellent)."""
    penalty = sum(finding.severity.weight for finding in findings)
    for api_finding in api_findings or []:
        factor = _API_FINDING_WEIGHT_FACTOR.get(api_finding.verification_status, 0.25)
        penalty += api_finding.severity.weight * factor
    score = max(0, round(100 - penalty))
    return score

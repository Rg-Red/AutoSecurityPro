"""CVSS v3.1 base score presets used across the vulnerability assessment engine."""

from __future__ import annotations

from autosecpro.core.models import Severity

CVSS_PRESETS: dict[str, tuple[Severity, float, str]] = {
    "sqli": (Severity.CRITICAL, 9.8, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"),
    "xss": (Severity.MEDIUM, 6.1, "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N"),
    "command_injection": (Severity.CRITICAL, 9.8, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"),
    "lfi": (Severity.HIGH, 7.5, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"),
    "ssrf": (Severity.HIGH, 8.6, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:L/A:N"),
    "cors_misconfig": (Severity.MEDIUM, 6.5, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N"),
    "missing_header": (Severity.LOW, 3.1, "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:L/A:N"),
    "missing_hsts": (Severity.LOW, 2.6, "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N"),
    "cookie_flags": (Severity.LOW, 3.7, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N"),
    "subdomain_takeover": (Severity.HIGH, 8.1, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N"),
}


def get_preset(name: str) -> tuple[Severity, float, str]:
    """Return the (severity, score, vector) preset for a given vulnerability class."""
    return CVSS_PRESETS.get(name, (Severity.INFO, 0.0, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N"))

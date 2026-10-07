"""Infrastructure and technology fingerprinting heuristics."""

from __future__ import annotations

import re
from typing import Optional

from autosecpro.core.http_client import AsyncHttpClient
from autosecpro.core.models import ScanContext

SERVER_OS_HINTS = {
    "ubuntu": "Ubuntu Linux",
    "debian": "Debian Linux",
    "centos": "CentOS Linux",
    "red hat": "Red Hat Enterprise Linux",
    "fedora": "Fedora Linux",
    "win32": "Windows Server",
    "win64": "Windows Server",
}

TECH_HEADER_HINTS = {
    "x-powered-by": {
        "php": "PHP",
        "express": "Node.js / Express",
        "asp.net": "ASP.NET",
        "next.js": "Next.js",
    },
    "x-generator": {
        "wordpress": "WordPress",
        "drupal": "Drupal",
        "joomla": "Joomla",
    },
}

BODY_TECH_HINTS = {
    "wp-content": "WordPress",
    "wp-includes": "WordPress",
    "laravel_session": "Laravel",
    "csrfmiddlewaretoken": "Django",
    "__next_data__": "Next.js",
    "django": "Django",
    "spring": "Spring Framework",
    "fastapi": "FastAPI",
    "x-fastapi": "FastAPI",
}

CLOUD_WAF_HEADER_HINTS = {
    "cf-ray": "Cloudflare",
    "cf-cache-status": "Cloudflare",
    "x-akamai-transformed": "Akamai",
    "x-sucuri-id": "Sucuri WAF",
    "server": None,
}


def _detect_os_from_server_header(server_header: str) -> Optional[str]:
    lowered = server_header.lower()
    for hint, os_name in SERVER_OS_HINTS.items():
        if hint in lowered:
            return os_name
    if "nginx" in lowered or "apache" in lowered:
        return "Linux (heuristic)"
    if "iis" in lowered:
        return "Windows Server (heuristic)"
    return None


def _detect_technologies(headers: dict[str, str], body: str) -> set[str]:
    technologies: set[str] = set()
    lowered_headers = {key.lower(): value for key, value in headers.items()}

    for header_name, mapping in TECH_HEADER_HINTS.items():
        value = lowered_headers.get(header_name, "").lower()
        for keyword, tech_name in mapping.items():
            if keyword in value:
                technologies.add(tech_name)

    lowered_body = body.lower()
    for keyword, tech_name in BODY_TECH_HINTS.items():
        if keyword in lowered_body:
            technologies.add(tech_name)

    for header_name, tech_name in CLOUD_WAF_HEADER_HINTS.items():
        if header_name in lowered_headers and tech_name:
            technologies.add(tech_name)

    return technologies


async def run_fingerprinting(client: AsyncHttpClient, context: ScanContext) -> None:
    """Fingerprint the target's web server, OS, and technology stack."""
    response = await client.get(context.target.base_url + "/")
    if response is None:
        return

    headers = dict(response.headers)
    try:
        body = await response.text(errors="ignore")
    except Exception:
        body = ""

    server_header = headers.get("Server", "")
    if server_header:
        context.server_banner = server_header
        os_guess = _detect_os_from_server_header(server_header)
        if os_guess:
            context.operating_system = os_guess

    context.detected_technologies.update(_detect_technologies(headers, body))

"""Pure, side-effect-free HTTP response analysis helpers.

Covers security response headers, cookie flags (HttpOnly/Secure/SameSite),
CORS wildcard-origin misconfigurations, and the HTTP OPTIONS method's
Allow/Access-Control-Allow-Methods response for unsafe verb exposure.
No requests are issued from this module; callers pass in already-fetched
headers/cookies so this logic can be unit tested independently of the
network layer.
"""

from __future__ import annotations

from http.cookies import SimpleCookie
from typing import NamedTuple

REQUIRED_SECURITY_HEADERS: dict[str, str] = {
    "Content-Security-Policy": "Missing Content-Security-Policy (CSP) header allows a broader attack surface for "
    "injection-based attacks such as XSS.",
    "Strict-Transport-Security": "Missing HTTP Strict-Transport-Security (HSTS) header exposes users to "
    "SSL-stripping / downgrade attacks.",
    "X-Frame-Options": "Missing X-Frame-Options header allows the page to be embedded in a frame, enabling "
    "clickjacking attacks.",
    "X-Content-Type-Options": "Missing X-Content-Type-Options header allows browsers to MIME-sniff responses, "
    "which can lead to content-type confusion attacks.",
}

UNSAFE_HTTP_METHODS = {"PUT", "DELETE", "TRACE", "CONNECT"}


class MissingHeaderIssue(NamedTuple):
    header_name: str
    remediation: str


class CookieIssue(NamedTuple):
    cookie_name: str
    missing_flags: list[str]


def find_missing_security_headers(headers: dict[str, str]) -> list[MissingHeaderIssue]:
    """Return the set of required security headers absent from `headers`."""
    lowered = {key.lower() for key in headers}
    issues = []
    for header_name, remediation in REQUIRED_SECURITY_HEADERS.items():
        if header_name.lower() not in lowered:
            issues.append(MissingHeaderIssue(header_name, remediation))
    return issues


def has_wildcard_cors_with_credentials(headers: dict[str, str]) -> bool:
    """Return True if CORS allows any origin (`*`) while also allowing credentials."""
    lowered = {key.lower(): value for key, value in headers.items()}
    acao = lowered.get("access-control-allow-origin")
    acac = lowered.get("access-control-allow-credentials", "").lower()
    return acao == "*" and acac == "true"


def analyze_cookie_flags(set_cookie_headers: list[str]) -> list[CookieIssue]:
    """Return cookies missing the HttpOnly, Secure, and/or SameSite attributes."""
    issues: list[CookieIssue] = []
    for raw_cookie in set_cookie_headers:
        cookie = SimpleCookie()
        try:
            cookie.load(raw_cookie)
        except Exception:
            continue
        for name, morsel in cookie.items():
            missing_flags = []
            if not morsel["httponly"]:
                missing_flags.append("HttpOnly")
            if not morsel["secure"]:
                missing_flags.append("Secure")
            if not morsel.get("samesite"):
                missing_flags.append("SameSite")
            if missing_flags:
                issues.append(CookieIssue(name, missing_flags))
    return issues


def find_exposed_unsafe_methods(allow_header: str) -> list[str]:
    """Return the unsafe HTTP methods advertised in an Allow/Access-Control-Allow-Methods header."""
    if not allow_header:
        return []
    advertised = {method.strip().upper() for method in allow_header.split(",") if method.strip()}
    return sorted(advertised & UNSAFE_HTTP_METHODS)

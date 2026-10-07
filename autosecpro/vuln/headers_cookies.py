"""Security header, CORS misconfiguration, and cookie flag verification checks."""

from __future__ import annotations

from autosecpro.core.header_analyzer import (
    analyze_cookie_flags,
    find_exposed_unsafe_methods,
    find_missing_security_headers,
    has_wildcard_cors_with_credentials,
)
from autosecpro.core.http_client import AsyncHttpClient
from autosecpro.core.models import Finding, ScanContext
from autosecpro.vuln.cvss import get_preset


async def check_security_headers(client: AsyncHttpClient, context: ScanContext) -> list[Finding]:
    """Check for missing critical security headers, CORS misconfigurations, insecure
    cookie flags, and exposed unsafe HTTP methods on the target's base URL."""
    findings: list[Finding] = []
    response = await client.get(context.target.base_url + "/")
    if response is None:
        return findings

    headers = {key.lower(): value for key, value in response.headers.items()}

    for issue in find_missing_security_headers(headers):
        vuln_key = "missing_hsts" if issue.header_name == "Strict-Transport-Security" else "missing_header"
        severity, score, vector = get_preset(vuln_key)
        findings.append(
            Finding(
                id="",
                name=f"Missing Security Header: {issue.header_name}",
                category="OWASP A05:2021 - Security Misconfiguration",
                severity=severity,
                cvss_score=score,
                cvss_vector=vector,
                url=context.target.base_url + "/",
                evidence_poc=f"Response headers did not include '{issue.header_name}'.",
                remediation=issue.remediation,
            )
        )

    if has_wildcard_cors_with_credentials(headers):
        severity, score, vector = get_preset("cors_misconfig")
        findings.append(
            Finding(
                id="",
                name="Overly Permissive CORS Policy with Credentials",
                category="OWASP A05:2021 - Security Misconfiguration",
                severity=severity,
                cvss_score=score,
                cvss_vector=vector,
                url=context.target.base_url + "/",
                evidence_poc="Access-Control-Allow-Origin: * combined with Access-Control-Allow-Credentials: true.",
                remediation="Restrict Access-Control-Allow-Origin to a strict allow-list of trusted origins and "
                "never combine wildcard origins with credentialed requests.",
            )
        )

    set_cookie_headers = response.headers.getall("Set-Cookie", []) if hasattr(response.headers, "getall") else []
    for issue in analyze_cookie_flags(set_cookie_headers):
        severity, score, vector = get_preset("cookie_flags")
        findings.append(
            Finding(
                id="",
                name=f"Insecure Cookie Configuration: {issue.cookie_name}",
                category="OWASP A05:2021 - Security Misconfiguration",
                severity=severity,
                cvss_score=score,
                cvss_vector=vector,
                url=context.target.base_url + "/",
                parameter=issue.cookie_name,
                evidence_poc=f"Cookie '{issue.cookie_name}' is missing flag(s): {', '.join(issue.missing_flags)}.",
                remediation="Set the HttpOnly, Secure, and SameSite attributes on all session cookies.",
            )
        )

    options_response = await client.request("OPTIONS", context.target.base_url + "/")
    if options_response is not None:
        allow_header = options_response.headers.get("Allow") or options_response.headers.get(
            "Access-Control-Allow-Methods", ""
        )
        options_response.release()
        unsafe_methods = find_exposed_unsafe_methods(allow_header)
        if unsafe_methods:
            severity, score, vector = get_preset("missing_header")
            findings.append(
                Finding(
                    id="",
                    name="Potentially Unsafe HTTP Methods Exposed",
                    category="OWASP A05:2021 - Security Misconfiguration",
                    severity=severity,
                    cvss_score=score,
                    cvss_vector=vector,
                    url=context.target.base_url + "/",
                    evidence_poc=f"OPTIONS response advertised method(s): {', '.join(unsafe_methods)}.",
                    remediation="Disable unused HTTP methods (e.g. PUT, DELETE, TRACE) at the web server or "
                    "framework routing layer unless explicitly required and properly authorized.",
                )
            )
    return findings

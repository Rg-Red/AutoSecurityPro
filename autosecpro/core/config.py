"""Runtime configuration container and CLI argument parsing for AutoSecurityPro."""

from __future__ import annotations

import argparse
import os
from dataclasses import dataclass, field
from typing import Optional


@dataclass(slots=True)
class ApiSecurityConfig:
    """Configuration for the API Security Exposure Analyzer module.

    All limits are conservative by default to guarantee safe, non-destructive,
    low-volume behavior. Authenticated scanning uses only a token supplied by
    the user through CLI flags or environment variables; tokens are never
    logged, printed, or written into reports.
    """

    enabled: bool = True
    discover_docs: bool = True
    analyze_schemas: bool = True
    check_auth_requirements: bool = True
    check_rate_limits: bool = True
    max_doc_requests: int = 50
    max_requests_per_endpoint: int = 2
    request_timeout_seconds: float = 10.0
    max_response_bytes: int = 2_000_000
    max_paths_per_schema: int = 1000
    max_operations_per_schema: int = 3000
    allow_external_refs: bool = False
    authorized_sensitive_targets: list[str] = field(default_factory=list)
    documentation_policy: str = "unknown"  # unknown | public_allowed | protected_required
    enable_authorized_safe_bola_check: bool = False


@dataclass(slots=True)
class AppConfig:
    """Fully resolved runtime configuration for a scan session."""

    target: str = ""
    tor: bool = False
    proxy_file: Optional[str] = None
    cookie: Optional[str] = None
    jwt: Optional[str] = None
    timeout: float = 10.0
    concurrency: int = 10
    output_dir: str = "reports"
    modules: list[str] = field(default_factory=lambda: ["all"])
    no_dorking: bool = False
    verbose: bool = False
    api_security: ApiSecurityConfig = field(default_factory=ApiSecurityConfig)


def build_arg_parser() -> argparse.ArgumentParser:
    """Build the `argparse` parser exposing all AutoSecurityPro CLI flags."""
    parser = argparse.ArgumentParser(
        prog="autosecpro",
        description="AutoSecurityPro (WhiteHat Hacker Suite) - "
        "Web Security & Attack Surface Assessment Suite.",
    )
    parser.add_argument("--target", "-t", type=str, default=None, help="Target domain or IP address to assess.")
    parser.add_argument("--tor", action="store_true", help="Route all traffic through the local Tor SOCKS5 proxy.")
    parser.add_argument("--proxy-file", type=str, default=None, help="Path to a file containing a list of HTTP/SOCKS proxies.")
    parser.add_argument("--cookie", type=str, default=None, help="Session cookie header for authenticated scanning, e.g. 'key=value'.")
    parser.add_argument("--jwt", type=str, default=None, help="Bearer JWT token for authenticated scanning.")
    parser.add_argument(
        "--jwt-env",
        type=str,
        default=None,
        help="Name of an environment variable holding the bearer JWT token for authenticated scanning "
        "(preferred over --jwt to avoid exposing the token on the command line).",
    )
    parser.add_argument("--timeout", type=float, default=10.0, help="Per-request timeout in seconds (default: 10).")
    parser.add_argument("--concurrency", type=int, default=10, help="Maximum number of concurrent asynchronous requests (default: 10).")
    parser.add_argument("--output-dir", type=str, default="reports", help="Directory where JSON reports will be written.")
    parser.add_argument(
        "--modules",
        type=str,
        default="all",
        help="Comma-separated list of modules to run: recon,vuln,dorking,all (default: all).",
    )
    parser.add_argument("--no-dorking", action="store_true", help="Disable the Google/DuckDuckGo dorking recon phase.")
    parser.add_argument("--verbose", "-v", action="store_true", help="Enable verbose diagnostic logging output.")
    parser.add_argument("--no-api-security", action="store_true", help="Disable the API Security Exposure Analyzer module.")
    parser.add_argument(
        "--max-doc-requests",
        type=int,
        default=50,
        help="Maximum number of API documentation discovery requests to send (default: 50).",
    )
    parser.add_argument(
        "--max-requests-per-endpoint",
        type=int,
        default=2,
        help="Maximum number of safe rate-limit-check requests per documented endpoint (default: 2).",
    )
    parser.add_argument(
        "--allow-external-refs",
        action="store_true",
        help="Allow the OpenAPI parser to fetch external $ref URLs that are explicitly in scope (disabled by default).",
    )
    parser.add_argument(
        "--documentation-policy",
        type=str,
        default="unknown",
        choices=["unknown", "public_allowed", "protected_required"],
        help="Declared policy for whether API documentation should be public (default: unknown).",
    )
    parser.add_argument(
        "--authorized-sensitive-target",
        dest="authorized_sensitive_targets",
        action="append",
        default=[],
        help="Mark a documentation path/URL as an authorized sensitive target (repeatable).",
    )
    parser.add_argument(
        "--enable-authorized-safe-bola-check",
        action="store_true",
        help="Enable authorized safe BOLA/IDOR comparison using two known test objects owned by the same "
        "authorized test account (requires an authenticated session; disabled by default).",
    )
    return parser


def parse_config(argv: Optional[list[str]] = None) -> AppConfig:
    """Parse CLI arguments into an :class:`AppConfig` instance."""
    parser = build_arg_parser()
    args = parser.parse_args(argv)
    modules = [m.strip().lower() for m in args.modules.split(",") if m.strip()]

    jwt = args.jwt
    if args.jwt_env:
        env_value = os.environ.get(args.jwt_env)
        if env_value:
            jwt = env_value

    api_security = ApiSecurityConfig(
        enabled=not args.no_api_security,
        max_doc_requests=args.max_doc_requests,
        max_requests_per_endpoint=args.max_requests_per_endpoint,
        request_timeout_seconds=args.timeout,
        allow_external_refs=args.allow_external_refs,
        authorized_sensitive_targets=list(args.authorized_sensitive_targets),
        documentation_policy=args.documentation_policy,
        enable_authorized_safe_bola_check=args.enable_authorized_safe_bola_check,
    )

    return AppConfig(
        target=args.target or "",
        tor=args.tor,
        proxy_file=args.proxy_file,
        cookie=args.cookie,
        jwt=jwt,
        timeout=args.timeout,
        concurrency=args.concurrency,
        output_dir=args.output_dir,
        modules=modules,
        no_dorking=args.no_dorking,
        verbose=args.verbose,
        api_security=api_security,
    )

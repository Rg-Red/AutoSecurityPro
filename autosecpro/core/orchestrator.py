"""Scan orchestration engine: sequences recon and vulnerability assessment phases."""

from __future__ import annotations

import time
from typing import Callable

from rich.progress import BarColumn, Progress, SpinnerColumn, TextColumn, TimeElapsedColumn

from autosecpro.core.config import ApiSecurityConfig
from autosecpro.core.http_client import AsyncHttpClient
from autosecpro.core.models import Finding, ScanContext
from autosecpro.recon import api_discovery, crawler, dorking, fingerprint, sensitive_files, subdomains
from autosecpro.vuln import api_exposure, headers_cookies, injection, lfi_ssrf, xss
from autosecpro.ui.console import console


def _renumber_findings(context: ScanContext) -> None:
    for index, finding in enumerate(context.findings, start=1):
        finding.id = f"SEC-VULN-{index:03d}"


async def run_recon_phase(client: AsyncHttpClient, context: ScanContext, run_dorking: bool, progress: Progress) -> None:
    """Run the full attack surface reconnaissance phase with live progress tracking."""
    task_sub = progress.add_task("[cyan]Passive Subdomain Enumeration", total=1)
    await subdomains.run_subdomain_enumeration(client, context)
    context.findings.extend(subdomains.build_dangling_subdomain_findings(context))
    progress.update(task_sub, completed=1)

    task_fp = progress.add_task("[cyan]Technology & Infrastructure Fingerprinting", total=1)
    await fingerprint.run_fingerprinting(client, context)
    progress.update(task_fp, completed=1)

    task_crawl = progress.add_task("[cyan]Crawling & Spidering", total=1)
    await crawler.crawl(client, context)
    progress.update(task_crawl, completed=1)

    task_files = progress.add_task("[cyan]Sensitive File & Directory Discovery", total=1)
    await sensitive_files.run_sensitive_file_discovery(client, context)
    progress.update(task_files, completed=1)

    task_api = progress.add_task("[cyan]API / Swagger / GraphQL Discovery", total=1)
    await api_discovery.discover_swagger(client, context)
    await api_discovery.discover_graphql(client, context)
    progress.update(task_api, completed=1)

    if run_dorking:
        task_dork = progress.add_task("[cyan]Google/DuckDuckGo Dorking Recon", total=1)
        await dorking.run_dorking(client, context)
        progress.update(task_dork, completed=1)


async def run_vuln_phase(
    client: AsyncHttpClient,
    context: ScanContext,
    progress: Progress,
    api_security_config: ApiSecurityConfig | None = None,
) -> None:
    """Run the safe vulnerability verification phase with live progress tracking."""
    task_headers = progress.add_task("[yellow]Security Headers / CORS / Cookies", total=1)
    context.findings.extend(await headers_cookies.check_security_headers(client, context))
    progress.update(task_headers, completed=1)

    task_xss = progress.add_task("[yellow]Reflected XSS Verification", total=1)
    context.findings.extend(await xss.run_xss_checks(client, context))
    progress.update(task_xss, completed=1)

    task_sqli = progress.add_task("[yellow]SQL Injection (Time-Based Safe PoC)", total=1)
    context.findings.extend(await injection.run_sqli_checks(client, context))
    progress.update(task_sqli, completed=1)

    task_cmdi = progress.add_task("[yellow]Command Injection (Time-Based Safe PoC)", total=1)
    context.findings.extend(await injection.run_command_injection_checks(client, context))
    progress.update(task_cmdi, completed=1)

    task_lfi = progress.add_task("[yellow]LFI / Path Traversal Verification", total=1)
    context.findings.extend(await lfi_ssrf.run_lfi_checks(client, context))
    progress.update(task_lfi, completed=1)

    task_ssrf = progress.add_task("[yellow]SSRF Detection", total=1)
    context.findings.extend(await lfi_ssrf.run_ssrf_checks(client, context))
    progress.update(task_ssrf, completed=1)

    if api_security_config is None or api_security_config.enabled:
        task_api_security = progress.add_task("[yellow]API Security Exposure Analysis (Docs / Inventory / BOLA / Rate Limits)", total=1)
        await api_exposure.run_api_security_scan(client, context, config=api_security_config)
        progress.update(task_api_security, completed=1)


async def run_full_scan(
    context: ScanContext,
    modules: list[str],
    on_tor_notice: Callable[[str], None] | None = None,
    api_security_config: ApiSecurityConfig | None = None,
) -> None:
    """Execute the full AutoSecurityPro assessment pipeline against `context.target`."""
    run_recon = "all" in modules or "recon" in modules
    run_vuln = "all" in modules or "vuln" in modules
    run_dork = ("all" in modules or "dorking" in modules) and "no-dorking" not in modules

    async with AsyncHttpClient(
        timeout=context.timeout,
        tor_enabled=context.tor_enabled,
        proxy_file=context.proxy_file,
        cookie=context.cookie,
        jwt=context.jwt,
    ) as client:
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            TimeElapsedColumn(),
            console=console,
        ) as progress:
            if run_recon:
                await run_recon_phase(client, context, run_dork, progress)
            if run_vuln:
                await run_vuln_phase(client, context, progress, api_security_config=api_security_config)

        context.request_stats.total_requests = client.total_requests
        context.request_stats.successful_requests = client.successful_requests
        context.request_stats.failed_requests = client.failed_requests
        context.request_stats.timeout_count = client.timeout_count

    context.finished_at = time.time()
    _renumber_findings(context)

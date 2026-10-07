"""Rich status tables and executive summary dashboard rendering."""

from __future__ import annotations

import time

from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from autosecpro.core.models import ScanContext, Severity
from autosecpro.core.metrics import ScanQuality, compute_scan_metrics
from autosecpro.ui.console import console
from autosecpro.vuln.scoring import compute_security_score, count_by_severity

SEVERITY_ORDER = [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.INFO]

_SCAN_QUALITY_STYLE = {
    ScanQuality.COMPLETE: "bold green",
    ScanQuality.PARTIAL: "bold yellow",
    ScanQuality.LOW_CONFIDENCE: "bold red",
    ScanQuality.FAILED: "bold white on red",
}


def print_findings_table(context: ScanContext) -> None:
    """Render a color-coded findings table sorted by severity."""
    if not context.findings:
        console.print(Panel("[bold green]No vulnerabilities were identified during this assessment.[/]", border_style="green"))
        return

    table = Table(title="Security Findings", show_lines=False, expand=True)
    table.add_column("ID", style="dim", width=14)
    table.add_column("Severity", justify="center", width=12)
    table.add_column("Finding", overflow="fold")
    table.add_column("URL / Parameter", overflow="fold")
    table.add_column("CVSS", justify="center", width=6)

    sorted_findings = sorted(context.findings, key=lambda f: SEVERITY_ORDER.index(f.severity))
    for finding in sorted_findings:
        badge = Text(f"[{finding.severity.value}]", style=finding.severity.style)
        location = finding.url
        if finding.parameter:
            location += f"\nparam: {finding.parameter}"
        table.add_row(finding.id, badge, finding.name, location, f"{finding.cvss_score:.1f}")

    console.print(table)


def print_executive_summary(context: ScanContext) -> None:
    """Render the final executive summary dashboard with key metrics."""
    finished_at = context.finished_at or time.time()
    elapsed = finished_at - context.started_at
    severity_counts = count_by_severity(context.findings)
    score = compute_security_score(context.findings)
    scan_metrics = compute_scan_metrics(context)

    score_style = "bold green" if score >= 80 else "bold yellow" if score >= 50 else "bold red"
    quality_style = _SCAN_QUALITY_STYLE[scan_metrics.scan_quality]

    grid = Table.grid(padding=(0, 3))
    grid.add_column(style="bold white")
    grid.add_column(style="cyan")

    grid.add_row("Total Execution Time:", f"{elapsed:.2f} seconds")
    grid.add_row("Requests Sent:", str(context.endpoints_scanned))
    grid.add_row("Discovered Endpoints (crawl/robots/sitemap):", str(len(context.discovered_endpoints)))
    grid.add_row("Auxiliary Probe Targets (guessed doc/API paths):", str(len(context.auxiliary_probe_targets)))
    grid.add_row("Subdomains Discovered:", str(len(context.discovered_subdomains)))
    grid.add_row(
        "Findings by Severity:",
        f"[bold white on red]CRITICAL: {severity_counts['critical']}[/]  "
        f"[bold red]HIGH: {severity_counts['high']}[/]  "
        f"[bold yellow]MEDIUM: {severity_counts['medium']}[/]  "
        f"[bold cyan]LOW: {severity_counts['low']}[/]  "
        f"[bold green]INFO: {severity_counts['info']}[/]",
    )
    grid.add_row("Overall Security Health Score:", f"[{score_style}]{score} / 100[/]")
    grid.add_row(
        "Scan Coverage / Confidence:",
        f"{scan_metrics.coverage_percent:.1f}% coverage, {scan_metrics.confidence_score} / 100 confidence",
    )
    grid.add_row("Scan Quality:", f"[{quality_style}]{scan_metrics.scan_quality.value}[/]")
    if context.informational_observations:
        grid.add_row(
            "Informational Observations:",
            ", ".join(item["name"] for item in context.informational_observations),
        )

    console.print(Panel(grid, title="[bold]Executive Summary Dashboard[/]", border_style="magenta", expand=False))

    if scan_metrics.scan_quality in (ScanQuality.PARTIAL, ScanQuality.LOW_CONFIDENCE, ScanQuality.FAILED):
        console.print(
            Panel(
                f"[{quality_style}]This scan was classified as {scan_metrics.scan_quality.value}[/]. "
                "The Security Health Score above reflects only the vulnerabilities that were actually "
                "observed; it does not imply full attack surface coverage. Re-run the scan or investigate "
                "connectivity/timeout issues for a more complete assessment.",
                title="[bold yellow]Scan Reliability Notice[/]",
                border_style="yellow",
            )
        )


def print_api_security_summary(context: ScanContext) -> None:
    """Render a panel summarizing the API Security Exposure Analyzer results."""
    api_security = context.api_security
    has_data = (
        api_security.documentation_targets
        or api_security.openapi_schemas
        or api_security.endpoint_inventory
        or api_security.findings
        or api_security.rate_limit_observations
    )
    if not has_data:
        return

    bola_count = sum(1 for finding in api_security.findings if finding.category == "Broken Object Level Authorization")
    rate_limit_signals = sum(1 for obs in api_security.rate_limit_observations if obs.signal_observed)

    grid = Table.grid(padding=(0, 3))
    grid.add_column(style="bold white")
    grid.add_column(style="cyan")

    grid.add_row("Documentation Targets Discovered:", str(len(api_security.documentation_targets)))
    grid.add_row("OpenAPI/Swagger Schemas Parsed:", str(len(api_security.openapi_schemas)))
    grid.add_row("Endpoint Inventory Size:", str(len(api_security.endpoint_inventory)))
    grid.add_row(
        "BOLA/IDOR Indicators:",
        f"[bold yellow]{bola_count}[/]" if bola_count else "[bold green]0[/]",
    )
    grid.add_row(
        "Rate-Limit Signals Observed:",
        f"[bold cyan]{rate_limit_signals}[/] / {len(api_security.rate_limit_observations)} sampled endpoints",
    )
    grid.add_row("API Security Findings:", str(len(api_security.findings)))

    console.print(Panel(grid, title="[bold]API Security Exposure Summary[/]", border_style="blue", expand=False))

    if api_security.endpoint_inventory:
        table = Table(title="API Endpoint Inventory", show_lines=False, expand=True)
        table.add_column("Method", justify="center", width=8)
        table.add_column("Path", overflow="fold")
        table.add_column("Sensitivity Tags", overflow="fold")
        table.add_column("BOLA Risk", justify="center", width=10)
        table.add_column("Rate Limit", justify="center", width=12)

        rate_limit_by_path = {obs.endpoint: obs.signal_observed for obs in api_security.rate_limit_observations}
        for item in api_security.endpoint_inventory:
            bola_risk = "[bold yellow]YES[/]" if "object_identifier_in_path" in item.risk_indicators else "no"
            if item.path in rate_limit_by_path:
                rate_limit_cell = "[bold green]observed[/]" if rate_limit_by_path[item.path] else "[bold red]none[/]"
            else:
                rate_limit_cell = "not sampled"
            table.add_row(item.method, item.path, ", ".join(item.sensitivity_tags) or "-", bola_risk, rate_limit_cell)

        console.print(table)

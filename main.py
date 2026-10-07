"""AutoSecurityPro (WhiteHat Hacker Suite) - CLI entrypoint."""

from __future__ import annotations

import asyncio
import sys

if sys.stdout.encoding and sys.stdout.encoding.lower() != "utf-8":
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    sys.stderr.reconfigure(encoding="utf-8", errors="replace")

from rich.panel import Panel
from rich.prompt import Prompt

from autosecpro.core.config import AppConfig, parse_config
from autosecpro.core.http_client import load_proxy_pool
from autosecpro.core.models import ScanContext
from autosecpro.core.orchestrator import run_full_scan
from autosecpro.core.target_resolver import normalize_target
from autosecpro.core.tor_manager import is_tor_socks_reachable, tor_preflight_message
from autosecpro.reporting.json_report import write_report
from autosecpro.ui.banner import print_banner, print_config_panel
from autosecpro.ui.console import console
from autosecpro.ui.report_view import print_api_security_summary, print_executive_summary, print_findings_table


def resolve_interactive_config(config: AppConfig) -> AppConfig:
    """Fill in missing configuration values via interactive terminal prompts."""
    if not config.target:
        config.target = Prompt.ask("[bold cyan]Enter Target Domain or IP Address[/]").strip()
    return config


async def async_main() -> int:
    print_banner()

    config = parse_config()
    if not config.target:
        config = resolve_interactive_config(config)

    if not config.target:
        console.print("[bold red]No target provided. Aborting.[/]")
        return 1

    if config.tor and not is_tor_socks_reachable():
        console.print(Panel(f"[bold yellow]{tor_preflight_message()}[/]", title="[bold red]Tor Preflight Warning[/]", border_style="red"))

    with console.status("[bold cyan]Normalizing and probing target...", spinner="dots"):
        target = await normalize_target(config.target, timeout=config.timeout)

    proxy_count = len(load_proxy_pool(config.proxy_file))
    print_config_panel(target, config.tor, proxy_count, config.modules, config.cookie, config.jwt)

    context = ScanContext(
        target=target,
        tor_enabled=config.tor,
        proxy_file=config.proxy_file,
        cookie=config.cookie,
        jwt=config.jwt,
        timeout=config.timeout,
        concurrency=config.concurrency,
    )

    effective_modules = list(config.modules)
    if config.no_dorking:
        effective_modules = [m for m in effective_modules if m != "dorking"]
        effective_modules.append("no-dorking")

    await run_full_scan(context, effective_modules, api_security_config=config.api_security)

    console.rule("[bold]Assessment Results[/]")
    print_findings_table(context)
    print_api_security_summary(context)
    print_executive_summary(context)

    report_path = write_report(context, output_dir=config.output_dir)
    console.print(f"[bold green]JSON report written to:[/] {report_path}")

    return 0


def main() -> None:
    """Synchronous console-script entrypoint."""
    try:
        exit_code = asyncio.run(async_main())
    except KeyboardInterrupt:
        console.print("\n[bold red]Scan interrupted by user.[/]")
        exit_code = 130
    sys.exit(exit_code)


if __name__ == "__main__":
    main()

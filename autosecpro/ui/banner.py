"""ASCII art banner and startup configuration panels."""

from __future__ import annotations

from datetime import datetime
from typing import Optional

from rich.align import Align
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from autosecpro import __version__
from autosecpro.core.models import Target
from autosecpro.ui.console import console

BANNER = r"""
   ___        __        _____                  _ __       ____
  / _ | __ __/ /____   / __(_)__ ___ _______  (_) /___ __/ / /
 / __ |/ // / __/ _ \ _\ \/ / -_) _ `/ __/ / / / __/ // / /_/
/_/ |_|\_,_/\__/\___/ /___/_/\__/\_,_/_/  \_,_/\__/\_, /_(_)
                                                    /___/
"""


def print_banner() -> None:
    """Print the AutoSecurityPro ASCII art banner with version/author metadata."""
    title = Text(BANNER, style="bold cyan")
    subtitle = Text.assemble(
        ("AutoSecurityPro", "bold magenta"),
        (" - WhiteHat Hacker Suite  |  ", "white"),
        (f"v{__version__}", "bold green"),
        ("  |  Author: ", "white"),
        ("AutoSecurityPro Team", "bold yellow"),
    )
    console.print(Align.center(title))
    console.print(Align.center(subtitle))
    console.print(
        Align.center(
            Text(
                "Passive & non-intrusive attack surface assessment with Safe PoC verification",
                style="italic dim",
            )
        )
    )
    console.rule(style="cyan")


def print_config_panel(
    target: Target,
    tor_enabled: bool,
    proxy_count: int,
    modules: list[str],
    cookie: Optional[str],
    jwt: Optional[str],
) -> None:
    """Print a colored panel summarizing the resolved scan configuration."""
    table = Table.grid(padding=(0, 2))
    table.add_column(style="bold white")
    table.add_column(style="cyan")

    table.add_row("Target Host:", target.host)
    table.add_row("Resolved IP:", target.resolved_ip or "N/A")
    table.add_row("Base URL:", target.base_url)
    table.add_row("IP Address Target:", "Yes" if target.is_ip else "No")
    table.add_row("Tor Routing:", "[bold green]ENABLED[/]" if tor_enabled else "[dim]disabled[/]")
    table.add_row("Proxy Pool Size:", str(proxy_count))
    table.add_row("Active Modules:", ", ".join(modules))
    table.add_row("Authenticated Scan:", "Yes" if (cookie or jwt) else "No")
    table.add_row("Execution Timestamp:", datetime.now().strftime("%Y-%m-%d %H:%M:%S"))

    console.print(Panel(table, title="[bold]Scan Configuration[/]", border_style="bright_blue", expand=False))

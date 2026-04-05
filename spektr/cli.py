"""spektr CLI -- CVE intelligence and triage."""

from __future__ import annotations

import sys
from typing import Optional

import click
import pyfiglet
import typer
from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TextColumn
from rich.text import Text

from spektr import __version__
from spektr.config import DEFAULTS, DESCRIPTIONS, load_config, get_value, set_value
from spektr.core.cache import Cache
from spektr.core.fetcher import Fetcher
from spektr.core.scorer import Scorer
from spektr.output.report import save_report
from spektr.output.terminal import (
    print_cve_detail,
    print_cve_table,
    print_error,
    print_footer,
    print_header,
)

console = Console()


def _print_banner() -> None:
    """Print the ASCII art banner with red gradient."""
    banner = pyfiglet.figlet_format("spektr", font="big")
    lines = banner.rstrip("\n").split("\n")
    total = len(lines) if lines else 1
    styled = Text()
    for i, line in enumerate(lines):
        # Gradient from bright red (#ff0000) at top to dark red (#8b0000) at bottom
        ratio = i / max(total - 1, 1)
        r = int(255 - (255 - 139) * ratio)
        color = f"#{r:02x}0000"
        styled.append(line + "\n", style=color)
    console.print(styled, end="")
    console.print("  [dim white]CVE intelligence. No noise.[/dim white]\n")


def _show_config(args: list[str]) -> None:
    """Handle `spektr --config [key] [value]`."""
    if not args:
        # Show all config
        cfg = load_config()
        console.print("\n[bold red]spektr config[/bold red]")
        console.print("[dim]  ~/.config/spektr/config.toml[/dim]\n")
        for k in DEFAULTS:
            current = cfg.get(k, DEFAULTS[k])
            desc = DESCRIPTIONS.get(k, "")
            display = current if current != "" else "[dim](not set)[/dim]"
            if k == "nvd_api_key" and current:
                display = current[:8] + "..." if len(str(current)) > 8 else current
            console.print(f"  [bold]{k}[/bold] = {display}")
            console.print(f"  [dim]{desc}[/dim]\n")
        return

    key = args[0]
    if len(args) == 1:
        # Show single value
        if key not in DEFAULTS:
            print_error(f"Unknown config key: {key}")
            console.print(f"\n[dim]  Available keys: {', '.join(DEFAULTS.keys())}[/dim]")
            return
        current = get_value(key)
        console.print(f"  {key} = {current}")
        return

    # Set value
    value = args[1]
    try:
        set_value(key, value)
        console.print(f"[green]  {key} = {value}[/green]")
    except KeyError:
        print_error(f"Unknown config key: {key}")
        console.print(f"\n[dim]  Available keys: {', '.join(DEFAULTS.keys())}[/dim]")
    except ValueError:
        print_error(f"Invalid value for {key}: {value}")


HELP_TEXT = """\
CVE intelligence and triage CLI

[bold red]Search:[/bold red]
  spektr "log4j"                          Search NVD for CVEs
  spektr "nginx 1.18.0"                   Search with version filter
  spektr "apache struts" --severity high   Filter by severity
  spektr "openssl" --limit 10 --sort epss  Limit results, sort by EPSS
  spektr "log4j" --output report.md        Export results to Markdown

[bold red]Lookup:[/bold red]
  spektr cve CVE-2021-44228              Full detail on a single CVE
  spektr cve CVE-2021-44228 -o report    Export single CVE to Markdown

[bold red]Config:[/bold red]
  spektr --config                        Show current configuration
  spektr --config limit 50               Set default result limit
  spektr --config nvd_api_key YOUR_KEY   Set NVD API key
  spektr --config sort epss              Set default sort field

[bold red]Manage:[/bold red]
  spektr clear-cache                     Wipe all cached data

[bold red]Search options:[/bold red]
  --severity, -s   Filter: critical, high, medium, low
  --limit, -l      Max results to return (default: 20)
  --sort           Sort by: spektr_score, cvss, epss, published
  --no-cache       Bypass cache for fresh results
  --output, -o     Export results to Markdown file

[bold red]Scoring:[/bold red]
  spektr score = (0.35 × CVSS) + (0.65 × EPSS² × 10), capped at 10
  If in CISA KEV: score × 1.3

  EPSS is non-linear — a CVE at 90th percentile scores much higher than one 
  at 45th percentile. KEV adds a %30 boost on top

[bold red]Config file:[/bold red]
  ~/.config/spektr/config.toml
"""

class _SpektrGroup(typer.core.TyperGroup):
    """Custom group that treats unrecognised tokens as search queries.

    Click's ``Group.invoke`` asserts that ``resolve_command`` returns a
    real command when ``_protected_args`` is non-empty.  We intercept
    *before* ``super().invoke``: if the first positional token is **not**
    a registered subcommand we move it into ``ctx.args`` and clear
    ``_protected_args`` so Click takes the ``invoke_without_command``
    path instead.  The callback then reads the query from ``ctx.args``.
    """

    def invoke(self, ctx: click.Context):  # type: ignore[override]
        if ctx._protected_args:
            cmd_name = click.utils.make_str(ctx._protected_args[0])
            if self.get_command(ctx, cmd_name) is None:
                # Not a real subcommand → treat as a search query.
                ctx.args = list(ctx._protected_args)
                ctx._protected_args = []
        return super().invoke(ctx)


app = typer.Typer(
    name="spektr",
    cls=_SpektrGroup,
    rich_markup_mode="rich",
    add_completion=False,
    invoke_without_command=True,
    context_settings={"allow_extra_args": True, "allow_interspersed_args": True},
)


def _version_callback(value: bool) -> None:
    if value:
        _print_banner()
        console.print(f"  [dim]v{__version__}[/dim]\n")
        raise typer.Exit()


def _help_callback(value: bool) -> None:
    if value:
        _print_banner()
        console.print(HELP_TEXT)
        raise typer.Exit()


def _config_callback(value: bool) -> None:
    if value:
        # Grab everything after --config from sys.argv
        try:
            idx = sys.argv.index("--config")
        except ValueError:
            idx = len(sys.argv)
        args = sys.argv[idx + 1:]
        _show_config(args)
        raise typer.Exit()


def _validate_query(query: str) -> str | None:
    """Validate search query. Returns cleaned query or None if invalid."""
    cleaned = query.strip()
    if len(cleaned) < 2:
        return None
    if not any(c.isalpha() for c in cleaned):
        return None
    return cleaned


def _do_search(
    target: str,
    severity: str | None = None,
    limit: int = 20,
    sort: str = "spektr_score",
    no_cache: bool = False,
    output: str | None = None,
) -> None:
    """Core search logic."""
    validated = _validate_query(target)
    if validated is None:
        print_error("Invalid query. Please enter a software name (e.g. 'nginx', 'log4j 2.14.1')")
        raise typer.Exit(1)
    target = validated

    if limit < 1:
        print_error("--limit must be at least 1")
        raise typer.Exit(1)
    if limit > 2000:
        limit = 2000

    cfg = load_config()
    api_key = cfg.get("nvd_api_key") or None

    cache = Cache()

    if no_cache:
        cache.invalidate(f"query:{target}:{severity}:{limit}")

    fetcher = Fetcher(cache=cache, api_key=api_key)
    scorer = Scorer(cache=cache)

    with Progress(
        SpinnerColumn(style="red"),
        TextColumn("[bold white]{task.description}"),
        console=console,
        transient=True,
    ) as progress:
        progress.add_task("Fetching CVEs from NVD...", total=None)
        records = fetcher.search(keyword=target, severity=severity, limit=limit)

    if not records:
        print_error(f"No CVEs found for '{target}'")
        console.print(
            "\n[dim]  Tip: Try using the software name and version "
            "(e.g. 'nginx 1.18.0')\n"
            "  or look up a CVE ID directly with "
            "'spektr cve CVE-XXXX-XXXX'[/dim]\n"
        )
        raise typer.Exit(1)

    with Progress(
        SpinnerColumn(style="red"),
        TextColumn("[bold white]{task.description}"),
        console=console,
        transient=True,
    ) as progress:
        progress.add_task("Enriching with EPSS + KEV data...", total=None)
        records = scorer.score(records)

    print_header(target, len(records))
    print_cve_table(records, sort_by=sort)
    print_footer()

    if output is not None:
        out_path = output if output != "" else None
        path = save_report(target, records, out_path, sort_by=sort)
        console.print(f"\n[green]  Report saved to {path}[/green]")


@app.callback(invoke_without_command=True)
def main(
    ctx: typer.Context,
    version: Optional[bool] = typer.Option(
        None, "--version", "-v", help="Show version and exit.",
        callback=_version_callback, is_eager=True,
    ),
    help_flag: Optional[bool] = typer.Option(
        None, "--help", "-h", help="Show this help and exit.",
        callback=_help_callback, is_eager=True,
    ),
    config_flag: Optional[bool] = typer.Option(
        None, "--config", help="View or set configuration.",
        callback=_config_callback, is_eager=True,
    ),
    severity: Optional[str] = typer.Option(
        None, "--severity", "-s",
        help="Filter by severity: critical, high, medium, low",
    ),
    limit: Optional[int] = typer.Option(
        None, "--limit", "-l", help="Max results to return",
    ),
    sort: Optional[str] = typer.Option(
        None, "--sort",
        help="Sort by: spektr_score, cvss, epss, published",
    ),
    no_cache: bool = typer.Option(False, "--no-cache", help="Bypass cache for fresh results"),
    output: Optional[str] = typer.Option(
        None, "--output", "-o", help="Export results to Markdown file",
    ),
) -> None:
    """spektr -- CVE intelligence and triage CLI."""
    # Real subcommands are handled by Click after this callback returns.
    if ctx.invoked_subcommand is not None:
        return

    # _SpektrGroup.invoke moved unrecognised tokens into ctx.args.
    target: str | None = ctx.args[0] if ctx.args else None

    if target is None:
        _print_banner()
        console.print(HELP_TEXT)
        raise typer.Exit()

    # Apply config defaults for options not explicitly set
    cfg = load_config()
    if limit is None:
        limit = cfg.get("limit", DEFAULTS["limit"])
    if sort is None:
        sort = cfg.get("sort", DEFAULTS["sort"])
    if severity is None:
        cfg_sev = cfg.get("severity", "")
        severity = cfg_sev if cfg_sev else None

    _do_search(target, severity=severity, limit=limit, sort=sort, no_cache=no_cache, output=output)


@app.command(name="clear-cache")
def clear_cache() -> None:
    """Clear all cached NVD/EPSS/KEV data."""
    cache = Cache()
    cache.clear()
    console.print("[green]Cache cleared.[/green]")


@app.command()
def cve(
    cve_id: str = typer.Argument(..., help="CVE ID, e.g. CVE-2021-44228"),
    output: Optional[str] = typer.Option(
        None, "--output", "-o", help="Export results to Markdown file",
    ),
) -> None:
    """Look up a specific CVE by ID."""
    cfg = load_config()
    api_key = cfg.get("nvd_api_key") or None

    cache = Cache()
    fetcher = Fetcher(cache=cache, api_key=api_key)
    scorer = Scorer(cache=cache)

    with Progress(
        SpinnerColumn(style="red"),
        TextColumn("[bold white]{task.description}"),
        console=console,
        transient=True,
    ) as progress:
        progress.add_task(f"Fetching {cve_id}...", total=None)
        record = fetcher.get_cve(cve_id)

    if record is None:
        print_error(f"CVE '{cve_id}' not found")
        raise typer.Exit(1)

    records = scorer.score([record])
    print_cve_detail(records[0])
    print_footer()

    if output is not None:
        out_path = output if output != "" else None
        path = save_report(cve_id, records, out_path, sort_by="spektr_score")
        console.print(f"\n[green]  Report saved to {path}[/green]")

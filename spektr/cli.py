"""spektr CLI -- CVE intelligence and triage."""

from __future__ import annotations

import json
import re
import sys
from typing import Optional

import click
import httpx
import pyfiglet
import typer
from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TextColumn
from rich.text import Text

from spektr import __version__
from spektr.config import DEFAULTS, DESCRIPTIONS, SECRET_KEYS, load_config, get_value, set_value
from spektr.core.cache import Cache
from spektr.core.fetcher import CVERecord, Fetcher, SpektrNetworkError
from spektr.core.scorer import Scorer
from spektr.output.report import save_report
from spektr.output.terminal import (
    print_cve_detail,
    print_cve_table,
    print_error,
    print_footer,
    print_header,
    print_triage,
    print_triage_warning,
)
from spektr.providers import get_provider
from spektr.providers.base import TriageResult

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
            if k in SECRET_KEYS:
                has_val = current.reveal() if hasattr(current, "reveal") else current
                display = f"[green]{current.masked_preview()}[/green]" if has_val else "[dim](not set)[/dim]"
            else:
                display = current if current != "" else "[dim](not set)[/dim]"
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
        if key in SECRET_KEYS:
            has_val = current.reveal() if hasattr(current, "reveal") else current
            display = current.masked_preview() if has_val else "(not set)"
        else:
            display = current
        console.print(f"  {key} = {display}")
        return

    # Set value
    value = args[1]
    try:
        set_value(key, value)
        if key in SECRET_KEYS:
            from spektr.config import MaskedStr
            masked = MaskedStr(value)
            console.print(f"[green]  {key} = {masked.masked_preview()}[/green]")
        else:
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
  spektr --config nvd_api_key YOUR_KEY   Set NVD API key (shows as ab12****ef56)
  spektr --config sort epss              Set default sort field

[bold red]Manage:[/bold red]
  spektr clear-cache                     Wipe all cached data

[bold red]Search options:[/bold red]
  --severity, -s   Filter: critical, high, medium, low
  --limit, -l      Max results to return (default: 20)
  --sort           Sort by: spektr_score, cvss, epss, published
  --no-cache       Bypass cache for fresh results
  --output, -o     Export results to Markdown file
  --raw            Show raw CVE table instead of AI triage

[bold red]Scoring:[/bold red]
  spektr score = (0.35 × CVSS) + (0.65 × EPSS² × 10), capped at 10
  If in CISA KEV: score × 1.3

  EPSS is non-linear — a CVE at 90th percentile scores much higher than one 
  at 45th percentile. KEV adds a 30% boost on top

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
                ctx.args = list(ctx._protected_args) + list(ctx.args)
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
    raw: bool = False,
) -> None:
    """Core search logic."""
    validated = _validate_query(target)
    if validated is None:
        print_error("Invalid query. Please enter a software name (e.g. 'nginx', 'log4j 2.14.1')")
        raise typer.Exit(1)
    target = validated

    if severity is not None:
        valid_severities = {"critical", "high", "medium", "low"}
        if severity.lower() not in valid_severities:
            print_error(f"Invalid severity '{severity}'. Choose from: critical, high, medium, low")
            raise typer.Exit(1)

    valid_sorts = {"spektr_score", "cvss", "epss", "published"}
    if sort not in valid_sorts:
        print_error(f"Invalid sort '{sort}'. Choose from: {', '.join(valid_sorts)}")
        raise typer.Exit(1)

    if limit < 1:
        print_error("--limit must be at least 1")
        raise typer.Exit(1)
    if limit > 2000:
        limit = 2000

    cfg = load_config()
    nvd_key = cfg.get("nvd_api_key")
    api_key = nvd_key if (hasattr(nvd_key, "reveal") and nvd_key.reveal()) else None

    with Cache() as cache:
        if no_cache:
            cache.invalidate(f"query:{target}:{severity}:{limit}")
            cache.invalidate_prefix("epss:")
            cache.invalidate_prefix("kev:")

        fetcher = Fetcher(cache=cache, api_key=api_key)
        scorer = Scorer(cache=cache)

        try:
            with Progress(
                SpinnerColumn(style="red"),
                TextColumn("[bold white]{task.description}"),
                console=console,
                transient=True,
            ) as progress:
                progress.add_task("Fetching CVEs from NVD...", total=None)
                records, from_cache = fetcher.search(keyword=target, severity=severity, limit=limit)
        except SpektrNetworkError as e:
            print_error(f"NVD API unreachable: {e}")
            raise typer.Exit(1)

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

    print_header(target, len(records), cached=from_cache)

    # AI triage first, then table
    triage_result = None
    provider_name = ""
    if not raw and bool(cfg.get("ai_provider")):
        triage_result, provider_name = _run_triage(target, records)

    print_cve_table(records, sort_by=sort)
    print_footer(cached=from_cache)

    if output is not None:
        out_path = output if output != "" else None
        path = save_report(target, records, out_path, sort_by=sort,
                           triage=triage_result, triage_provider=provider_name)
        console.print(f"\n[green]  Report saved to {path}[/green]")


def _run_triage(
    query: str, records: list[CVERecord],
) -> tuple[TriageResult | None, str]:
    """Run AI triage if configured. Returns (result, provider_name)."""
    cfg = load_config()
    provider = get_provider(cfg)

    if provider is None:
        print_triage_warning(
            "AI triage not configured. Run: spektr --config ai_provider groq"
        )
        return None, ""

    if not provider.is_available():
        print_triage_warning(
            f"AI provider '{cfg.get('ai_provider')}' is not available"
        )
        return None, ""

    try:
        with Progress(
            SpinnerColumn(style="red"),
            TextColumn("[bold white]{task.description}"),
            console=console,
            transient=True,
        ) as progress:
            progress.add_task("Running AI triage...", total=None)
            result = provider.triage(query, records)
        print_triage(result, provider_name=provider.name())
        return result, provider.name()
    except ValueError:
        print_triage_warning("AI returned invalid response, skipping triage")
        return None, ""
    except (httpx.HTTPError, json.JSONDecodeError, KeyError):
        print_triage_warning("AI triage timed out or failed")
        return None, ""


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
    raw: bool = typer.Option(False, "--raw", help="Show raw CVE table instead of AI triage"),
) -> None:
    """spektr -- CVE intelligence and triage CLI."""
    # Real subcommands are handled by Click after this callback returns.
    if ctx.invoked_subcommand is not None:
        return

    # _SpektrGroup.invoke moved unrecognised tokens into ctx.args.
    target: str | None = " ".join(ctx.args) if ctx.args else None

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

    _do_search(target, severity=severity, limit=limit, sort=sort, no_cache=no_cache,
               output=output, raw=raw)


@app.command(name="clear-cache")
def clear_cache() -> None:
    """Clear all cached NVD/EPSS/KEV data."""
    with Cache() as cache:
        cache.clear()
    console.print("[green]Cache cleared.[/green]")


@app.command()
def cve(
    cve_id: str = typer.Argument(..., help="CVE ID, e.g. CVE-2021-44228"),
    output: Optional[str] = typer.Option(
        None, "--output", "-o", help="Export results to Markdown file",
    ),
    raw: bool = typer.Option(False, "--raw", help="Show raw detail instead of AI triage"),
) -> None:
    """Look up a specific CVE by ID."""
    if not re.match(r"^CVE-\d{4}-\d{4,}$", cve_id, re.IGNORECASE):
        print_error("Invalid CVE ID format. Expected CVE-YYYY-NNNNN")
        raise typer.Exit(1)

    cfg = load_config()
    nvd_key = cfg.get("nvd_api_key")
    api_key = nvd_key if (hasattr(nvd_key, "reveal") and nvd_key.reveal()) else None

    with Cache() as cache:
        fetcher = Fetcher(cache=cache, api_key=api_key)
        scorer = Scorer(cache=cache)

        with Progress(
            SpinnerColumn(style="red"),
            TextColumn("[bold white]{task.description}"),
            console=console,
            transient=True,
        ) as progress:
            progress.add_task(f"Fetching {cve_id}...", total=None)
            record, from_cache = fetcher.get_cve(cve_id)

        if record is None:
            print_error(f"CVE '{cve_id}' not found")
            raise typer.Exit(1)

        records = scorer.score([record])

    # AI triage first, then detail
    triage_result = None
    provider_name = ""
    if not raw and bool(cfg.get("ai_provider")):
        triage_result, provider_name = _run_triage(cve_id, records)

    print_cve_detail(records[0])
    print_footer(cached=from_cache)

    if output is not None:
        out_path = output if output != "" else None
        path = save_report(cve_id, records, out_path, sort_by="spektr_score",
                           triage=triage_result, triage_provider=provider_name)
        console.print(f"\n[green]  Report saved to {path}[/green]")

"""Rich terminal output - tables, panels, and color-coded CVE display."""

from __future__ import annotations

import os
import sys
from collections import Counter
from typing import Any
from urllib.parse import urlparse

from rich.console import Console
from rich.panel import Panel
from rich.rule import Rule
from rich.table import Table
from rich.text import Text

from spektr import __version__
from spektr.core.fetcher import CVERecord
from spektr.providers.base import TriageResult

# Force UTF-8 output on Windows to avoid charmap encoding errors
if sys.platform == "win32":
    os.environ.setdefault("PYTHONIOENCODING", "utf-8")
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    if hasattr(sys.stderr, "reconfigure"):
        sys.stderr.reconfigure(encoding="utf-8", errors="replace")

console = Console()

# Severity color map
SEVERITY_STYLES: dict[str, str] = {
    "CRITICAL": "bold white on red",
    "HIGH": "bold red",
    "MEDIUM": "bold yellow",
    "LOW": "bold blue",
}


def _severity_badge(severity: str | None) -> Text:
    """Create a colored severity badge."""
    label = (severity or "N/A").upper()
    style = SEVERITY_STYLES.get(label, "dim white")
    padded = f" {label:^8} "
    return Text(padded, style=style)


def _score_color(score: float) -> str:
    """Return a style string based on the spektr score."""
    if score >= 7.0:
        return "bold red"
    if score >= 4.0:
        return "yellow"
    return "dim white"


def _limit_refs_per_domain(refs: list[str], max_per_domain: int = 3) -> list[str]:
    """Return refs with at most *max_per_domain* URLs per domain."""
    domain_count: Counter[str] = Counter()
    result: list[str] = []
    for url in refs:
        try:
            domain = urlparse(url).netloc.lower()
        except ValueError:
            domain = url
        domain_count[domain] += 1
        if domain_count[domain] <= max_per_domain:
            result.append(url)
    return result


def _truncate(text: str, max_len: int = 60) -> str:
    """Truncate text to max_len with ellipsis."""
    if len(text) <= max_len:
        return text
    return text[: max_len - 3] + "..."


def print_header(query: str, total: int, cached: bool = False) -> None:
    """Print the query header panel."""
    source = "[dim](cached)[/dim]" if cached else "[dim](live)[/dim]"
    count_style = "bold red" if total > 0 else "dim"
    subtitle = f"[{count_style}]{total} CVEs found[/{count_style}]  {source}"

    panel = Panel(
        f"[bold white]{query}[/bold white]",
        title="[bold red]spektr[/bold red]",
        subtitle=subtitle,
        border_style="red",
        padding=(1, 2),
    )
    console.print(panel)


def print_cve_table(records: list[CVERecord], sort_by: str = "spektr_score") -> None:
    """Print the main CVE results table."""
    # Sort records
    sort_keys: dict[str, Any] = {
        "spektr_score": lambda r: r.spektr_score,
        "cvss": lambda r: r.cvss_v3_score or 0,
        "epss": lambda r: r.epss_percentile if r.epss_percentile is not None else 0,
        "published": lambda r: r.published,
    }
    key_fn = sort_keys.get(sort_by, sort_keys["spektr_score"])
    sorted_records = sorted(records, key=key_fn, reverse=True)

    table = Table(
        show_header=True,
        header_style="bold white on dark_red",
        border_style="dim red",
        padding=(0, 1),
        expand=True,
        row_styles=["", "on #1a1a1a"],
    )

    table.add_column("#", style="dim", width=3, justify="right")
    table.add_column("Severity", width=12, justify="center")
    table.add_column("CVE ID", style="bold white", width=18)
    table.add_column("CVSS", width=5, justify="right")
    table.add_column("EPSS%", width=7, justify="right")
    table.add_column("KEV", width=4, justify="center")
    table.add_column("Score", width=6, justify="right")
    table.add_column("Description", ratio=1)

    for i, record in enumerate(sorted_records, 1):
        severity_badge = _severity_badge(record.cvss_v3_severity)
        cvss_str = f"{record.cvss_v3_score:.1f}" if record.cvss_v3_score is not None else "-"
        epss_str = (
            f"{record.epss_percentile * 100:.1f}" if record.epss_percentile is not None else "-"
        )
        kev_str = Text("!!", style="bold red") if record.in_kev else Text("-", style="dim")
        score_str = Text(f"{record.spektr_score:.1f}", style=_score_color(record.spektr_score))
        desc = _truncate(record.description)

        table.add_row(
            str(i),
            severity_badge,
            record.id,
            cvss_str,
            epss_str,
            kev_str,
            score_str,
            desc,
        )

    console.print(table)


def print_cve_detail(record: CVERecord) -> None:
    """Print a detailed view of a single CVE."""
    lines: list[str] = []
    lines.append(f"[bold white]{record.id}[/bold white]")
    lines.append("")
    lines.append(record.description)
    lines.append("")

    if record.cvss_v3_score is not None:
        sev_style = SEVERITY_STYLES.get((record.cvss_v3_severity or "").upper(), "")
        lines.append(
            f"  CVSS v3:   [{sev_style}]{record.cvss_v3_score:.1f} "
            f"({record.cvss_v3_severity})[/{sev_style}]"
        )
    if record.cvss_v3_vector:
        lines.append(f"  Vector:    [dim]{record.cvss_v3_vector}[/dim]")
    if record.epss_score is not None:
        pct = record.epss_percentile if record.epss_percentile is not None else 0
        lines.append(f"  EPSS:      {record.epss_score:.4f} (top {(1 - pct) * 100:.1f}%)")
    if record.in_kev:
        lines.append("  KEV:       [bold red]!! In CISA Known Exploited Vulnerabilities[/bold red]")

    lines.append(
        f"  Score:     [{_score_color(record.spektr_score)}]"
        f"{record.spektr_score:.1f}/10.0[/{_score_color(record.spektr_score)}]"
    )
    lines.append("")

    if record.cwe_ids:
        lines.append(f"  CWEs:      {', '.join(dict.fromkeys(record.cwe_ids))}")
    if record.published:
        lines.append(f"  Published: {record.published[:10]}")
    if record.last_modified:
        lines.append(f"  Modified:  {record.last_modified[:10]}")

    if record.references:
        capped_refs = _limit_refs_per_domain(record.references)
        lines.append("")
        lines.append("  [bold white]References:[/bold white]")
        for ref in capped_refs[:5]:
            lines.append(f"    [dim red]>[/dim red] {ref}")
        if len(capped_refs) > 5:
            lines.append(f"    [dim]... and {len(capped_refs) - 5} more[/dim]")

    panel = Panel(
        "\n".join(lines),
        border_style="red",
        padding=(1, 2),
    )
    console.print(panel)


def print_error(message: str) -> None:
    """Print an error panel."""
    console.print(
        Panel(
            f"[bold red]{message}[/bold red]",
            border_style="red",
            title="[bold red]Error[/bold red]",
            padding=(0, 2),
        )
    )


def print_warning(message: str) -> None:
    """Print a warning message."""
    console.print(f"[yellow]  ! {message}[/yellow]")


def print_triage(result: TriageResult, provider_name: str = "") -> None:
    """Print AI triage results in a compact red-bordered panel."""
    lines: list[str] = []

    # Summary (max 2 sentences)
    lines.append(f"[bold white]{result.summary}[/bold white]")
    lines.append("")

    # Priority (top 5, one line each with short reasoning)
    for i, cve_id in enumerate(result.prioritized[:5], 1):
        reason = result.reasoning.get(cve_id, "")
        reason_text = f" [dim]— {reason}[/dim]" if reason else ""
        lines.append(f"  {i}. [bold]{cve_id}[/bold]{reason_text}")
    lines.append("")

    # Attack path (max 2 sentences)
    lines.append(f"[bold white]Attack path:[/bold white] {result.attack_path}")
    lines.append("")

    # Recommended actions (max 3)
    for action in result.recommended_actions[:3]:
        lines.append(f"  • {action}")

    # Provider footer
    if provider_name:
        lines.append("")
        lines.append(f"[dim]{provider_name}[/dim]")

    panel = Panel(
        "\n".join(lines),
        title="[bold red]AI Triage[/bold red]",
        border_style="red",
        padding=(1, 2),
    )
    console.print(panel)


def print_triage_warning(message: str) -> None:
    """Print a yellow warning panel for triage issues."""
    console.print(
        Panel(
            f"[yellow]{message}[/yellow]",
            border_style="yellow",
            title="[yellow]Triage[/yellow]",
            padding=(0, 2),
        )
    )


def print_footer(cached: bool = False) -> None:
    """Print the footer with data source info."""
    source = "cache" if cached else "NVD API v2 + EPSS + KEV"
    console.print(Rule(style="dim red"))
    console.print(f"[dim]  Data: {source}  |  spektr v{__version__}[/dim]\n")

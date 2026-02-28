"""CLI interface for claude-clean."""

from __future__ import annotations

from pathlib import Path

import click
from rich.console import Console
from rich.table import Table
from rich.text import Text

from claude_clean.config import Config
from claude_clean.patterns import Sensitivity
from claude_clean.redactor import redact_directory, redact_file
from claude_clean.scanner import Finding, scan_directory, scan_file

console = Console()
error_console = Console(stderr=True)

SENSITIVITY_COLORS = {
    Sensitivity.LOW: "red",
    Sensitivity.MEDIUM: "yellow",
    Sensitivity.HIGH: "cyan",
}


def _resolve_config(
    config_path: str | None,
    sensitivity: str | None,
    path: str | None,
) -> Config:
    """Load config from file and apply CLI overrides."""
    cfg = Config.load(Path(config_path) if config_path else None)
    if sensitivity:
        cfg.sensitivity = Sensitivity(sensitivity)
    if path:
        cfg.projects_path = Path(path)
    return cfg


def _display_findings(findings: list[Finding], verbose: bool = False) -> None:
    """Display scan findings in a rich table."""
    if not findings:
        console.print("[green]No secrets detected.[/green]")
        return

    table = Table(title=f"Secrets Found: {len(findings)}", show_lines=True)
    table.add_column("File", style="blue", max_width=50)
    table.add_column("Line", style="white", justify="right")
    table.add_column("Type", style="magenta")
    table.add_column("Sensitivity", justify="center")
    table.add_column("Match", max_width=60)

    if verbose:
        table.add_column("Context", max_width=80)

    for finding in findings:
        color = SENSITIVITY_COLORS.get(finding.sensitivity, "white")
        sensitivity_text = Text(finding.sensitivity.value.upper(), style=f"bold {color}")
        masked = Text(finding.masked_match, style="red")

        row: list[str | Text] = [
            str(finding.file),
            str(finding.line_number),
            finding.pattern_description,
            sensitivity_text,
            masked,
        ]

        if verbose:
            row.append(finding.context)

        table.add_row(*row)

    console.print(table)

    # Summary by type
    type_counts: dict[str, int] = {}
    for f in findings:
        type_counts[f.pattern_description] = type_counts.get(f.pattern_description, 0) + 1

    console.print("\n[bold]Summary by type:[/bold]")
    for desc, count in sorted(type_counts.items(), key=lambda x: x[1], reverse=True):
        console.print(f"  {desc}: [yellow]{count}[/yellow]")


@click.group()
@click.version_option(package_name="claude-clean")
def main() -> None:
    """Claude Clean - Scan and redact secrets from Claude Code session files."""


@main.command()
@click.option(
    "-s",
    "--sensitivity",
    type=click.Choice(["low", "medium", "high"]),
    default=None,
    help="Detection sensitivity level (default: medium).",
)
@click.option(
    "-p",
    "--path",
    type=click.Path(exists=True),
    default=None,
    help="Path to scan (default: ~/.claude/projects).",
)
@click.option(
    "-f",
    "--file",
    "single_file",
    type=click.Path(exists=True),
    default=None,
    help="Scan a single JSONL file instead of a directory.",
)
@click.option(
    "-v",
    "--verbose",
    is_flag=True,
    default=False,
    help="Show detailed context for each finding.",
)
@click.option(
    "--config",
    "config_path",
    type=click.Path(exists=True),
    default=None,
    help="Path to config file (default: ~/.claude-clean.toml).",
)
def scan(
    sensitivity: str | None,
    path: str | None,
    single_file: str | None,
    verbose: bool,
    config_path: str | None,
) -> None:
    """Scan for secrets without modifying files (dry run).

    Searches through Claude Code session JSONL files and reports any
    secrets or sensitive information found.
    """
    cfg = _resolve_config(config_path, sensitivity, path)

    console.print(f"[bold]Scanning with sensitivity: [cyan]{cfg.sensitivity.value}[/cyan][/bold]")

    if single_file:
        target = Path(single_file)
        console.print(f"[bold]Scanning file:[/bold] {target}")
        findings = scan_file(
            target,
            cfg.sensitivity,
            extra_patterns=cfg.extra_patterns or None,
            exclude_patterns=cfg.exclude_patterns or None,
        )
    else:
        target_dir = cfg.projects_path
        console.print(f"[bold]Scanning directory:[/bold] {target_dir}")

        if not target_dir.exists():
            error_console.print(f"[red]Error:[/red] Directory does not exist: {target_dir}")
            raise SystemExit(1)

        # Count files first
        jsonl_files = list(target_dir.rglob("*.jsonl"))
        console.print(f"[bold]Found [cyan]{len(jsonl_files)}[/cyan] JSONL files[/bold]")

        if not jsonl_files:
            console.print("[yellow]No JSONL files found.[/yellow]")
            return

        findings = scan_directory(
            target_dir,
            cfg.sensitivity,
            extra_patterns=cfg.extra_patterns or None,
            exclude_patterns=cfg.exclude_patterns or None,
        )

    _display_findings(findings, verbose=verbose)

    if findings:
        console.print(f"\n[bold yellow]Found {len(findings)} potential secret(s).[/bold yellow]")
        console.print(
            "Run [bold]claude-clean redact[/bold] to redact them, "
            "or [bold]claude-clean redact --dry-run[/bold] to preview redactions."
        )


@main.command()
@click.option(
    "-s",
    "--sensitivity",
    type=click.Choice(["low", "medium", "high"]),
    default=None,
    help="Detection sensitivity level (default: medium).",
)
@click.option(
    "-p",
    "--path",
    type=click.Path(exists=True),
    default=None,
    help="Path to scan (default: ~/.claude/projects).",
)
@click.option(
    "-f",
    "--file",
    "single_file",
    type=click.Path(exists=True),
    default=None,
    help="Redact a single JSONL file instead of a directory.",
)
@click.option(
    "-n",
    "--dry-run",
    is_flag=True,
    default=False,
    help="Preview what would be redacted without modifying files.",
)
@click.option(
    "--no-backup",
    is_flag=True,
    default=False,
    help="Skip creating backup files before redaction.",
)
@click.option(
    "-v",
    "--verbose",
    is_flag=True,
    default=False,
    help="Show detailed output.",
)
@click.option(
    "--config",
    "config_path",
    type=click.Path(exists=True),
    default=None,
    help="Path to config file (default: ~/.claude-clean.toml).",
)
def redact(
    sensitivity: str | None,
    path: str | None,
    single_file: str | None,
    dry_run: bool,
    no_backup: bool,
    verbose: bool,
    config_path: str | None,
) -> None:
    """Redact secrets from Claude Code session files.

    By default, creates a backup (.bak) of each file before modifying it.
    Use --dry-run to preview what would be redacted without making changes.
    """
    cfg = _resolve_config(config_path, sensitivity, path)

    if dry_run:
        console.print("[bold yellow]DRY RUN[/bold yellow] - no files will be modified\n")

    console.print(f"[bold]Redacting with sensitivity: [cyan]{cfg.sensitivity.value}[/cyan][/bold]")

    backup = cfg.backup and not no_backup

    if dry_run:
        # In dry-run mode, just scan and display findings
        if single_file:
            target = Path(single_file)
            findings = scan_file(
                target,
                cfg.sensitivity,
                extra_patterns=cfg.extra_patterns or None,
                exclude_patterns=cfg.exclude_patterns or None,
            )
        else:
            target_dir = cfg.projects_path
            if not target_dir.exists():
                error_console.print(f"[red]Error:[/red] Directory does not exist: {target_dir}")
                raise SystemExit(1)
            findings = scan_directory(
                target_dir,
                cfg.sensitivity,
                extra_patterns=cfg.extra_patterns or None,
                exclude_patterns=cfg.exclude_patterns or None,
            )

        _display_findings(findings, verbose=verbose)

        if findings:
            console.print(
                f"\n[bold yellow]{len(findings)} secret(s) would be redacted.[/bold yellow]"
            )
            console.print("Run without [bold]--dry-run[/bold] to apply redactions.")
        return

    # Actual redaction
    if single_file:
        target = Path(single_file)
        console.print(f"[bold]Redacting file:[/bold] {target}")
        result = redact_file(
            target,
            cfg.sensitivity,
            backup=backup,
            extra_patterns=cfg.extra_patterns or None,
            exclude_patterns=cfg.exclude_patterns or None,
        )
        results = [result]
    else:
        target_dir = cfg.projects_path
        console.print(f"[bold]Redacting directory:[/bold] {target_dir}")

        if not target_dir.exists():
            error_console.print(f"[red]Error:[/red] Directory does not exist: {target_dir}")
            raise SystemExit(1)

        results = redact_directory(
            target_dir,
            cfg.sensitivity,
            backup=backup,
            extra_patterns=cfg.extra_patterns or None,
            exclude_patterns=cfg.exclude_patterns or None,
        )

    # Display results
    total_redactions = sum(r.redactions_made for r in results)
    files_modified = sum(1 for r in results if r.redactions_made > 0)

    if total_redactions == 0:
        console.print("[green]No secrets found to redact.[/green]")
        return

    table = Table(title="Redaction Results")
    table.add_column("File", style="blue", max_width=60)
    table.add_column("Redactions", style="red", justify="right")
    table.add_column("Backup", style="green", max_width=60)

    for result in results:
        if result.redactions_made > 0 or verbose:
            table.add_row(
                str(result.file),
                str(result.redactions_made),
                str(result.backup_path) if result.backup_path else "None",
            )

    console.print(table)
    console.print(
        f"\n[bold green]Done![/bold green] "
        f"Redacted [red]{total_redactions}[/red] secret(s) "
        f"across [cyan]{files_modified}[/cyan] file(s)."
    )

    if backup:
        console.print("[dim]Backup files created with .bak extension.[/dim]")

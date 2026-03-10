import os
import platform
import sys
from pathlib import Path
from typing import Optional

import typer
from rich.console import Console

from claude_sec.analyzers import run_all_analyzers
from claude_sec.config_reader import read_all_config
from claude_sec.grader import compute_diff, grade_overall
from claude_sec.models import Environment, ScanResult
from claude_sec.renderer import render_html

app = typer.Typer(help="Claude Code Security Dashboard")
console = Console()

VERSION = "0.1.0"


def _collect_environment(project_dir: Path) -> Environment:
    return Environment(
        hostname=platform.node(),
        os_version=f"{platform.system()} {platform.release()}",
        username=os.environ.get("USER", os.environ.get("USERNAME", "unknown")),
        python_version=platform.python_version(),
        claude_sec_version=VERSION,
        project_dir=str(project_dir.resolve()),
    )


@app.callback(invoke_without_command=True)
def scan(
    json_output: bool = typer.Option(False, "--json", help="Output JSON instead of HTML"),
    output: Optional[Path] = typer.Option(None, "--output", "-o", help="Output file path"),
    project_dir: Path = typer.Option(".", "--project-dir", help="Project directory to scan"),
    user_dir: Optional[Path] = typer.Option(None, "--user-dir", help="User config directory (default: ~/.claude)"),
    baseline: Optional[Path] = typer.Option(None, "--baseline", "-b", help="Previous scan JSON for diff comparison"),
):
    """Scan Claude Code configuration for security issues."""
    if user_dir is None:
        user_dir = Path.home() / ".claude"

    config = read_all_config(project_dir, user_dir)
    categories = run_all_analyzers(config)
    result = grade_overall(categories, paths_scanned=config["paths_scanned"])
    result.environment = _collect_environment(project_dir)

    if baseline and baseline.exists():
        previous = ScanResult.model_validate_json(baseline.read_text())
        result.diff = compute_diff(result, previous)

    if json_output:
        typer.echo(result.model_dump_json(indent=2))
    else:
        html = render_html(result)
        path = output or Path("claude-sec-report.html")
        path.write_text(html)
        console.print(f"[bold green]Report written to:[/] {path}")
        console.print(f"[bold]Overall Grade:[/] {result.overall_grade} ({result.overall_score}/100)")

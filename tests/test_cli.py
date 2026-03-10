import json
from pathlib import Path

from typer.testing import CliRunner

from claude_sec.cli import app

runner = CliRunner()
FIXTURES = Path(__file__).parent / "fixtures"


def test_cli_json_output():
    result = runner.invoke(app, [
        "--json",
        "--project-dir", str(FIXTURES / "project"),
        "--user-dir", str(FIXTURES / "user"),
    ])
    assert result.exit_code == 0
    data = json.loads(result.stdout)
    assert "overall_score" in data
    assert "categories" in data


def test_cli_html_output(tmp_path):
    out = tmp_path / "report.html"
    result = runner.invoke(app, [
        "--output", str(out),
        "--project-dir", str(FIXTURES / "project"),
        "--user-dir", str(FIXTURES / "user"),
    ])
    assert result.exit_code == 0
    assert out.exists()
    html = out.read_text()
    assert "<!DOCTYPE html>" in html


def test_cli_default_output(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    result = runner.invoke(app, [
        "--project-dir", str(FIXTURES / "project"),
        "--user-dir", str(FIXTURES / "user"),
    ])
    assert result.exit_code == 0
    assert (tmp_path / "claude-sec-report.html").exists()


def test_cli_baseline_diff(tmp_path):
    # Generate baseline JSON
    baseline_result = runner.invoke(app, [
        "--json",
        "--project-dir", str(FIXTURES / "project"),
        "--user-dir", str(FIXTURES / "user"),
    ])
    assert baseline_result.exit_code == 0
    baseline_file = tmp_path / "baseline.json"
    baseline_file.write_text(baseline_result.stdout)

    # Run again with --baseline
    out = tmp_path / "report.html"
    result = runner.invoke(app, [
        "--output", str(out),
        "--baseline", str(baseline_file),
        "--project-dir", str(FIXTURES / "project"),
        "--user-dir", str(FIXTURES / "user"),
    ])
    assert result.exit_code == 0
    html = out.read_text()
    assert "Changes Since Last Scan" in html
    assert "No change" in html or "unchanged" in html.lower()


def test_cli_json_includes_compliance():
    result = runner.invoke(app, [
        "--json",
        "--project-dir", str(FIXTURES / "project"),
        "--user-dir", str(FIXTURES / "user"),
    ])
    assert result.exit_code == 0
    data = json.loads(result.stdout)
    # At least some findings should have compliance refs
    all_findings = []
    for cat in data["categories"].values():
        all_findings.extend(cat["findings"])
    has_compliance = any(f.get("compliance") for f in all_findings)
    assert has_compliance

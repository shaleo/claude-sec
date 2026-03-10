"""End-to-end integration tests with realistic fixture data."""
import json
from pathlib import Path

from claude_sec.config_reader import read_all_config
from claude_sec.analyzers import run_all_analyzers
from claude_sec.grader import grade_overall
from claude_sec.renderer import render_html
from claude_sec.models import ScanResult

FIXTURES = Path(__file__).parent / "fixtures"


def test_full_pipeline():
    """Run the full scan → grade → render pipeline."""
    config = read_all_config(FIXTURES / "project", FIXTURES / "user")
    categories = run_all_analyzers(config)
    result = grade_overall(categories, paths_scanned=config["paths_scanned"])

    # Verify result structure
    assert isinstance(result, ScanResult)
    assert 0 <= result.overall_score <= 100
    assert result.overall_grade in ("A", "B", "C", "D", "F")
    assert len(result.categories) == 5

    # Should find real issues in our fixture data
    all_findings = []
    for cat in result.categories.values():
        all_findings.extend(cat.findings)
    assert len(all_findings) > 0  # Fixtures have known issues

    # Verify finding IDs are assigned
    assert all(f.finding_id != "" for f in all_findings)

    # Verify executive summary is generated
    assert result.overall_summary != ""

    # Verify compliance refs are assigned to relevant findings
    findings_with_compliance = [f for f in all_findings if f.compliance]
    assert len(findings_with_compliance) > 0  # at least some should have refs


def test_json_roundtrip():
    """Verify JSON output is valid and round-trips."""
    config = read_all_config(FIXTURES / "project", FIXTURES / "user")
    categories = run_all_analyzers(config)
    result = grade_overall(categories, paths_scanned=config["paths_scanned"])

    json_str = result.model_dump_json(indent=2)
    parsed = json.loads(json_str)
    assert "overall_score" in parsed
    assert "categories" in parsed

    restored = ScanResult.model_validate_json(json_str)
    assert restored.overall_score == result.overall_score


def test_html_output():
    """Verify HTML contains expected structural elements."""
    config = read_all_config(FIXTURES / "project", FIXTURES / "user")
    categories = run_all_analyzers(config)
    result = grade_overall(categories, paths_scanned=config["paths_scanned"])
    html = render_html(result)

    assert "<!DOCTYPE html>" in html
    assert "Claude Code Security Report" in html
    assert "filesystem" in html.lower()
    assert "network" in html.lower()
    assert "hooks" in html.lower()
    assert "git" in html.lower()
    assert "Toggle Dark Mode" in html
    assert "filter-btn" in html
    assert "Executive Summary" in html
    assert "@media print" in html
    assert "compliance-tag" in html  # compliance refs in HTML
    assert "Assigned To:" in html  # tracking fields


def test_clean_config_gets_good_grade():
    """A minimal but safe config should get reasonable grades."""
    config = {
        "settings": {
            "user": {
                "sandbox": {
                    "filesystem": {
                        "read": {"denyOnly": [".env", ".env.*", "**/.env", "**/.env.*"]},
                        "write": {
                            "allowOnly": ["."],
                            "denyWithinAllow": [
                                ".env", ".env.*", "**/.env", "**/.env.*",
                                "~/.ssh", "~/.aws", "~/.gnupg",
                                "~/.config/gcloud", "~/.kube", "~/.docker",
                                "~/.azure", "~/.npmrc", "~/.pypirc",
                                "~/.gem/credentials", "~/.git-credentials",
                                "~/.config/gh", "~/Library/Keychains",
                                "~/.bashrc", "~/.zshrc", "~/.profile", "~/.bash_profile",
                            ],
                        },
                    },
                    "network": {"allowedHosts": ["anthropic.com"]},
                },
                "permissions": {
                    "allow": ["Bash(git status)", "Bash(git diff)"],
                    "deny": [
                        "Read(.env)", "Read(~/.ssh/**)", "Read(~/.aws/**)",
                        "Read(~/.gnupg/**)", "Read(~/.config/gh/**)", "Read(~/.git-credentials)",
                        "Edit(.env)", "Edit(~/.ssh/**)", "Edit(~/.aws/**)",
                        "Bash(curl *)", "Bash(wget *)",
                    ],
                },
                "hooks": {
                    "PreToolUse": [{"matcher": "*", "hooks": [{"type": "command", "command": "validate.sh"}]}],
                    "PostToolUse": [{"matcher": "*", "hooks": [{"type": "command", "command": "log.sh"}]}],
                    "SessionStart": [{"hooks": [{"type": "command", "command": "init.sh"}]}],
                },
            },
            "project": {},
            "local": {},
        },
        "mcp_servers": {},
        "_project_mcp_servers": {},
        "hooks": {
            "PreToolUse": [{"matcher": "*", "hooks": [{"type": "command", "command": "validate.sh"}]}],
            "PostToolUse": [{"matcher": "*", "hooks": [{"type": "command", "command": "log.sh"}]}],
            "SessionStart": [{"hooks": [{"type": "command", "command": "init.sh"}]}],
        },
        "paths_scanned": [],
        "project_dir": "/tmp/clean",
    }
    categories = run_all_analyzers(config)
    result = grade_overall(categories, paths_scanned=[])
    assert result.overall_grade == "A"
    assert result.overall_score >= 90

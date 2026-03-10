from claude_sec.renderer import render_html
from claude_sec.models import (
    ComplianceRef, DiffSummary, Finding, Severity, CategoryResult, ScanResult, Environment,
)


def _sample_result():
    f = Finding(
        finding_id="FS-001",
        severity=Severity.HIGH,
        category="filesystem",
        title="Sensitive path unprotected",
        description="~/.ssh is not denied",
        risk="SSH keys exposed",
        fix='Add ~/.ssh to deny list',
        verification="Check deny list",
        compliance=[
            ComplianceRef(framework="CWE", reference="CWE-732", description="Incorrect Permission Assignment"),
            ComplianceRef(framework="SOC 2", reference="CC6.1", description="Logical and Physical Access Controls"),
        ],
    )
    return ScanResult(
        categories={
            "filesystem": CategoryResult(findings=[f], score=85, grade="B"),
            "network": CategoryResult(findings=[], score=100, grade="A"),
            "hooks": CategoryResult(findings=[], score=100, grade="A"),
            "git": CategoryResult(findings=[], score=100, grade="A"),
            "permissions": CategoryResult(findings=[], score=100, grade="A"),
        },
        overall_score=92,
        overall_grade="A",
        overall_summary="This environment received a grade of A (92/100) and is well-secured.",
        environment=Environment(
            hostname="test-host",
            os_version="Darwin 25.3.0",
            username="testuser",
            python_version="3.12.0",
            claude_sec_version="0.1.0",
            project_dir="/tmp/test-project",
        ),
        paths_scanned=["/test/settings.json"],
    )


def test_renders_valid_html():
    html = render_html(_sample_result())
    assert "<!DOCTYPE html>" in html
    assert "</html>" in html


def test_contains_categories():
    html = render_html(_sample_result())
    for cat in ["filesystem", "network", "hooks", "git", "permissions"]:
        assert cat.lower() in html.lower()


def test_contains_findings():
    html = render_html(_sample_result())
    assert "Sensitive path unprotected" in html
    assert "SSH keys exposed" in html
    assert "Add ~/.ssh to deny list" in html


def test_self_contained():
    html = render_html(_sample_result())
    # No external stylesheets or scripts (compliance reference links are OK)
    assert '<link rel="stylesheet" href="http' not in html
    assert 'src="http' not in html


def test_grade_colors():
    html = render_html(_sample_result())
    # Grade A should be present
    assert "grade-a" in html.lower() or "grade-A" in html


def test_clean_result():
    result = ScanResult(
        categories={
            "filesystem": CategoryResult(findings=[], score=100, grade="A"),
            "network": CategoryResult(findings=[], score=100, grade="A"),
            "hooks": CategoryResult(findings=[], score=100, grade="A"),
            "git": CategoryResult(findings=[], score=100, grade="A"),
            "permissions": CategoryResult(findings=[], score=100, grade="A"),
        },
        overall_score=100,
        overall_grade="A",
        paths_scanned=[],
    )
    html = render_html(result)
    assert "100" in html


def test_contains_finding_ids():
    html = render_html(_sample_result())
    assert "FS-001" in html


def test_contains_executive_summary():
    html = render_html(_sample_result())
    assert "Executive Summary" in html
    assert "well-secured" in html


def test_contains_environment():
    html = render_html(_sample_result())
    assert "test-host" in html
    assert "Darwin 25.3.0" in html
    assert "testuser" in html


def test_print_styles():
    html = render_html(_sample_result())
    assert "@media print" in html


def test_contains_compliance_tags():
    html = render_html(_sample_result())
    assert "CWE-732" in html
    assert "CC6.1" in html
    assert "compliance-tag" in html


def test_compliance_tags_are_links():
    html = render_html(_sample_result())
    # CWE refs should be clickable links to cwe.mitre.org
    assert 'href="https://cwe.mitre.org/data/definitions/732.html"' in html
    assert 'target="_blank"' in html
    # SOC 2 refs should render as non-clickable spans (no per-criterion URL)
    assert "CC6.1" in html


def test_contains_tracking_fields():
    html = render_html(_sample_result())
    assert "Assigned To:" in html
    assert "Target Date:" in html
    assert "Status:" in html


def test_contains_diff_section():
    result = _sample_result()
    result.diff = DiffSummary(
        new_findings=["FS-001"],
        resolved_findings=["Old issue"],
        unchanged_count=2,
        previous_score=70,
        previous_grade="C",
        score_delta=22,
    )
    html = render_html(result)
    assert "Changes Since Last Scan" in html
    assert "FS-001" in html
    assert "Old issue" in html
    assert "+22" in html
    assert "improved" in html
    assert "C" in html  # previous grade


def test_diff_regression():
    result = _sample_result()
    result.diff = DiffSummary(
        new_findings=["FS-001"],
        resolved_findings=[],
        unchanged_count=0,
        previous_score=95,
        previous_grade="A",
        score_delta=-3,
    )
    html = render_html(result)
    assert "regressed" in html
    assert "-3" in html


def test_no_diff_section_when_none():
    result = _sample_result()
    result.diff = None
    html = render_html(result)
    assert "Changes Since Last Scan" not in html


def test_sidebar_structure():
    html = render_html(_sample_result())
    assert "sidebar" in html
    assert "sidebar-toggle" in html
    assert "sidebar-close" in html
    assert "sidebar-overlay" in html
    # Executive summary and environment are inside the sidebar
    assert "Executive Summary" in html
    assert "Environment" in html

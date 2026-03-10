from claude_sec.grader import compute_diff, grade_category, grade_overall
from claude_sec.models import CategoryResult, Finding, ScanResult, Severity


def _finding(severity: Severity, category: str = "test", title: str = "Test finding") -> Finding:
    return Finding(
        severity=severity,
        category=category,
        title=title,
        description="desc",
        risk="risk",
        fix="fix",
        verification="verify",
    )


def test_no_findings():
    result = grade_category([])
    assert result.score == 100
    assert result.grade == "A"


def test_one_critical():
    result = grade_category([_finding(Severity.CRITICAL)])
    assert result.score <= 40
    assert result.grade in ("D", "F")


def test_grade_boundaries():
    # Score 90+ = A
    result = grade_category([_finding(Severity.LOW)])
    assert result.grade == "A"

    # One HIGH = -15, score 85 = B
    result = grade_category([_finding(Severity.HIGH)])
    assert result.grade == "B"

    # Two HIGHs = -30, score 70 = C
    result = grade_category([_finding(Severity.HIGH), _finding(Severity.HIGH)])
    assert result.grade == "C"


def test_overall_weighted():
    categories = {
        "filesystem": [_finding(Severity.CRITICAL, "filesystem")],
        "network": [],
        "hooks": [],
        "git": [],
        "permissions": [],
    }
    result = grade_overall(categories, paths_scanned=["/test"])
    # filesystem(40)*0.25 + 100*0.75 = 85 → B grade
    assert result.overall_score == 85
    assert result.overall_grade == "B"


def test_overall_all_clean():
    categories = {
        "filesystem": [],
        "network": [],
        "hooks": [],
        "git": [],
        "permissions": [],
    }
    result = grade_overall(categories, paths_scanned=["/test"])
    assert result.overall_score == 100
    assert result.overall_grade == "A"


def test_mixed_severities():
    result = grade_category([
        _finding(Severity.HIGH),
        _finding(Severity.MEDIUM),
        _finding(Severity.LOW),
    ])
    # -15 -8 -3 = -26, score 74
    assert result.score == 74
    assert result.grade == "C"


def test_finding_ids_assigned():
    categories = {
        "filesystem": [_finding(Severity.HIGH, "filesystem"), _finding(Severity.LOW, "filesystem")],
        "network": [_finding(Severity.MEDIUM, "network")],
        "hooks": [],
        "git": [],
        "permissions": [],
    }
    result = grade_overall(categories, paths_scanned=[])
    fs_findings = result.categories["filesystem"].findings
    assert fs_findings[0].finding_id == "FS-001"
    assert fs_findings[1].finding_id == "FS-002"
    assert result.categories["network"].findings[0].finding_id == "NET-001"


def test_executive_summary_generated():
    categories = {
        "filesystem": [_finding(Severity.CRITICAL, "filesystem")],
        "network": [],
        "hooks": [],
        "git": [],
        "permissions": [],
    }
    result = grade_overall(categories, paths_scanned=[])
    assert result.overall_summary != ""
    assert "1 CRITICAL" in result.overall_summary
    assert "grade of B" in result.overall_summary


def test_summary_clean():
    categories = {
        "filesystem": [],
        "network": [],
        "hooks": [],
        "git": [],
        "permissions": [],
    }
    result = grade_overall(categories, paths_scanned=[])
    assert "No security findings" in result.overall_summary


def test_compliance_assigned_to_sandbox():
    categories = {
        "filesystem": [_finding(Severity.CRITICAL, "filesystem", "No filesystem sandbox configured")],
        "network": [],
        "hooks": [],
        "git": [],
        "permissions": [],
    }
    result = grade_overall(categories, paths_scanned=[])
    f = result.categories["filesystem"].findings[0]
    assert len(f.compliance) > 0
    refs = [r.reference for r in f.compliance]
    assert "CWE-269" in refs


def test_compliance_assigned_to_unpinned():
    categories = {
        "filesystem": [],
        "network": [_finding(Severity.HIGH, "network", "Unpinned MCP package: test")],
        "hooks": [],
        "git": [],
        "permissions": [],
    }
    result = grade_overall(categories, paths_scanned=[])
    f = result.categories["network"].findings[0]
    refs = [r.reference for r in f.compliance]
    assert "CWE-1104" in refs
    assert "A06:2021" in refs


def test_compliance_no_match():
    categories = {
        "filesystem": [],
        "network": [],
        "hooks": [],
        "git": [_finding(Severity.INFO, "git", "No git permissions configured")],
        "permissions": [],
    }
    result = grade_overall(categories, paths_scanned=[])
    f = result.categories["git"].findings[0]
    assert len(f.compliance) == 0  # "No git permissions" doesn't match any keyword


def test_compute_diff_new_and_resolved():
    current = ScanResult(
        categories={
            "fs": CategoryResult(findings=[
                Finding(finding_id="FS-001", severity=Severity.HIGH, category="fs",
                        title="New issue", description="d", risk="r", fix="f", verification="v"),
                Finding(finding_id="FS-002", severity=Severity.LOW, category="fs",
                        title="Unchanged issue", description="d", risk="r", fix="f", verification="v"),
            ], score=82, grade="B"),
        },
        overall_score=82, overall_grade="B", paths_scanned=[],
    )
    previous = ScanResult(
        categories={
            "fs": CategoryResult(findings=[
                Finding(finding_id="FS-001", severity=Severity.MEDIUM, category="fs",
                        title="Old resolved issue", description="d", risk="r", fix="f", verification="v"),
                Finding(finding_id="FS-002", severity=Severity.LOW, category="fs",
                        title="Unchanged issue", description="d", risk="r", fix="f", verification="v"),
            ], score=89, grade="B"),
        },
        overall_score=89, overall_grade="B", paths_scanned=[],
    )
    diff = compute_diff(current, previous)
    assert "FS-001" in diff.new_findings
    assert "Old resolved issue" in diff.resolved_findings
    assert diff.unchanged_count == 1
    assert diff.previous_score == 89
    assert diff.score_delta == -7


def test_compute_diff_no_changes():
    f = Finding(finding_id="FS-001", severity=Severity.HIGH, category="fs",
                title="Same issue", description="d", risk="r", fix="f", verification="v")
    result = ScanResult(
        categories={"fs": CategoryResult(findings=[f], score=85, grade="B")},
        overall_score=85, overall_grade="B", paths_scanned=[],
    )
    diff = compute_diff(result, result)
    assert len(diff.new_findings) == 0
    assert len(diff.resolved_findings) == 0
    assert diff.unchanged_count == 1
    assert diff.score_delta == 0

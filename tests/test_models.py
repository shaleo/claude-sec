from claude_sec.models import (
    ComplianceRef, DiffSummary, Finding, Severity, CategoryResult, ScanResult, Environment,
)


def test_finding_creation():
    f = Finding(
        severity=Severity.HIGH,
        category="filesystem",
        title="Sensitive path unprotected",
        description="~/.ssh is not in deny list",
        risk="SSH keys could be read or modified",
        fix='Add "~/.ssh" to filesystem.write.denyWithinAllow',
        verification="Check settings.json for ~/.ssh in deny list",
    )
    assert f.severity == Severity.HIGH
    assert f.category == "filesystem"
    assert f.title == "Sensitive path unprotected"
    assert f.finding_id == ""  # default empty before grading


def test_finding_with_id():
    f = Finding(
        finding_id="FS-001",
        severity=Severity.HIGH,
        category="filesystem",
        title="Test",
        description="d",
        risk="r",
        fix="f",
        verification="v",
    )
    assert f.finding_id == "FS-001"


def test_environment():
    env = Environment(
        hostname="test-host",
        os_version="Darwin 25.3.0",
        username="testuser",
        python_version="3.12.0",
        claude_sec_version="0.1.0",
        project_dir="/tmp/project",
    )
    assert env.hostname == "test-host"
    assert env.os_version == "Darwin 25.3.0"


def test_severity_ordering():
    assert Severity.CRITICAL > Severity.HIGH
    assert Severity.HIGH > Severity.MEDIUM
    assert Severity.MEDIUM > Severity.LOW
    assert Severity.LOW > Severity.INFO


def test_category_result():
    findings = [
        Finding(
            severity=Severity.HIGH,
            category="filesystem",
            title="Test",
            description="desc",
            risk="risk",
            fix="fix",
            verification="verify",
        )
    ]
    cr = CategoryResult(findings=findings, score=70, grade="C")
    assert cr.score == 70
    assert cr.grade == "C"
    assert len(cr.findings) == 1


def test_scan_result():
    cr = CategoryResult(findings=[], score=100, grade="A")
    result = ScanResult(
        categories={"filesystem": cr},
        overall_score=100,
        overall_grade="A",
        paths_scanned=["/tmp/test"],
    )
    assert result.overall_grade == "A"
    assert "filesystem" in result.categories


def test_scan_result_json_roundtrip():
    f = Finding(
        severity=Severity.MEDIUM,
        category="network",
        title="Broad hosts",
        description="desc",
        risk="risk",
        fix="fix",
        verification="verify",
    )
    cr = CategoryResult(findings=[f], score=80, grade="B")
    result = ScanResult(
        categories={"network": cr},
        overall_score=80,
        overall_grade="B",
        paths_scanned=["/test"],
    )
    json_str = result.model_dump_json(indent=2)
    restored = ScanResult.model_validate_json(json_str)
    assert restored.overall_score == 80
    assert restored.categories["network"].findings[0].title == "Broad hosts"
    assert restored.categories["network"].findings[0].severity == Severity.MEDIUM


def test_finding_compliance_refs():
    ref = ComplianceRef(framework="CWE", reference="CWE-732", description="Incorrect Permission Assignment")
    f = Finding(
        severity=Severity.HIGH,
        category="filesystem",
        title="Test",
        description="d",
        risk="r",
        fix="f",
        verification="v",
        compliance=[ref],
    )
    assert len(f.compliance) == 1
    assert f.compliance[0].reference == "CWE-732"


def test_compliance_ref_url_cwe():
    ref = ComplianceRef(framework="CWE", reference="CWE-269", description="Improper Privilege Management")
    assert ref.url == "https://cwe.mitre.org/data/definitions/269.html"


def test_compliance_ref_url_owasp():
    ref = ComplianceRef(framework="OWASP", reference="A05:2021", description="Security Misconfiguration")
    assert ref.url == "https://owasp.org/Top10/A05_2021-Security_Misconfiguration/"


def test_compliance_ref_url_soc2():
    ref = ComplianceRef(framework="SOC 2", reference="CC6.1", description="Logical and Physical Access Controls")
    assert "google.com/search" in ref.url
    assert "CC6.1" in ref.url


def test_compliance_ref_url_unknown():
    ref = ComplianceRef(framework="Custom", reference="CUSTOM-1", description="Custom check")
    assert ref.url == ""


def test_compliance_ref_url_in_json():
    ref = ComplianceRef(framework="CWE", reference="CWE-732", description="Test")
    data = ref.model_dump()
    assert "url" in data
    assert "cwe.mitre.org" in data["url"]


def test_finding_tracking_defaults():
    f = Finding(
        severity=Severity.HIGH,
        category="test",
        title="Test",
        description="d",
        risk="r",
        fix="f",
        verification="v",
    )
    assert f.assigned_to == ""
    assert f.target_date == ""
    assert f.status == "Open"


def test_diff_summary():
    d = DiffSummary(
        new_findings=["FS-001"],
        resolved_findings=["Old finding"],
        unchanged_count=3,
        previous_score=75,
        previous_grade="C",
        score_delta=10,
    )
    assert len(d.new_findings) == 1
    assert d.score_delta == 10
    assert d.previous_grade == "C"


def test_scan_result_with_diff_roundtrip():
    d = DiffSummary(
        new_findings=["FS-001"],
        resolved_findings=["Old"],
        unchanged_count=2,
        previous_score=60,
        previous_grade="D",
        score_delta=20,
    )
    cr = CategoryResult(findings=[], score=100, grade="A")
    result = ScanResult(
        categories={"filesystem": cr},
        overall_score=80,
        overall_grade="B",
        paths_scanned=[],
        diff=d,
    )
    json_str = result.model_dump_json(indent=2)
    restored = ScanResult.model_validate_json(json_str)
    assert restored.diff is not None
    assert restored.diff.new_findings == ["FS-001"]
    assert restored.diff.score_delta == 20

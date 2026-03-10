from claude_sec.models import (
    ComplianceRef, DiffSummary, Finding, Severity, CategoryResult, ScanResult,
)

SEVERITY_DEDUCTIONS = {
    Severity.CRITICAL: 60,
    Severity.HIGH: 15,
    Severity.MEDIUM: 8,
    Severity.LOW: 3,
    Severity.INFO: 0,
}

CATEGORY_WEIGHTS = {
    "filesystem": 0.25,
    "network": 0.20,
    "hooks": 0.20,
    "git": 0.15,
    "permissions": 0.20,
}

CATEGORY_PREFIXES = {
    "filesystem": "FS",
    "network": "NET",
    "hooks": "HK",
    "git": "GIT",
    "permissions": "PERM",
}

GRADE_THRESHOLDS = [(90, "A"), (80, "B"), (70, "C"), (60, "D"), (0, "F")]

GRADE_DESCRIPTIONS = {
    "A": "well-secured",
    "B": "adequately secured with minor gaps",
    "C": "partially secured with notable gaps",
    "D": "insufficiently secured with significant gaps",
    "F": "critically under-secured",
}

# Compliance mapping: keyword in finding title → list of references.
# Matched case-insensitively against finding titles.
COMPLIANCE_MAP: list[tuple[str, list[ComplianceRef]]] = [
    ("sandbox", [
        ComplianceRef(framework="CWE", reference="CWE-269", description="Improper Privilege Management"),
        ComplianceRef(framework="SOC 2", reference="CC6.1", description="Logical and Physical Access Controls"),
    ]),
    ("write allowlist", [
        ComplianceRef(framework="CWE", reference="CWE-732", description="Incorrect Permission Assignment for Critical Resource"),
        ComplianceRef(framework="SOC 2", reference="CC6.1", description="Logical and Physical Access Controls"),
    ]),
    ("sensitive path", [
        ComplianceRef(framework="CWE", reference="CWE-732", description="Incorrect Permission Assignment for Critical Resource"),
        ComplianceRef(framework="CWE", reference="CWE-522", description="Insufficiently Protected Credentials"),
        ComplianceRef(framework="SOC 2", reference="CC6.1", description="Logical and Physical Access Controls"),
    ]),
    (".env", [
        ComplianceRef(framework="CWE", reference="CWE-522", description="Insufficiently Protected Credentials"),
        ComplianceRef(framework="OWASP", reference="A05:2021", description="Security Misconfiguration"),
    ]),
    ("read deny", [
        ComplianceRef(framework="CWE", reference="CWE-200", description="Exposure of Sensitive Information"),
        ComplianceRef(framework="SOC 2", reference="CC6.1", description="Logical and Physical Access Controls"),
    ]),
    ("wildcard host", [
        ComplianceRef(framework="CWE", reference="CWE-918", description="Server-Side Request Forgery"),
        ComplianceRef(framework="SOC 2", reference="CC6.6", description="Security Measures Against Threats Outside System Boundaries"),
        ComplianceRef(framework="OWASP", reference="A10:2021", description="Server-Side Request Forgery"),
    ]),
    ("network sandbox", [
        ComplianceRef(framework="CWE", reference="CWE-918", description="Server-Side Request Forgery"),
        ComplianceRef(framework="SOC 2", reference="CC6.6", description="Security Measures Against Threats Outside System Boundaries"),
    ]),
    ("external hosts", [
        ComplianceRef(framework="CWE", reference="CWE-918", description="Server-Side Request Forgery"),
        ComplianceRef(framework="SOC 2", reference="CC6.6", description="Security Measures Against Threats Outside System Boundaries"),
    ]),
    ("unpinned", [
        ComplianceRef(framework="CWE", reference="CWE-1104", description="Use of Unmaintained Third Party Components"),
        ComplianceRef(framework="OWASP", reference="A06:2021", description="Vulnerable and Outdated Components"),
        ComplianceRef(framework="SOC 2", reference="CC7.1", description="Detection of Changes to Infrastructure and Software"),
    ]),
    ("no hooks", [
        ComplianceRef(framework="CWE", reference="CWE-778", description="Insufficient Logging"),
        ComplianceRef(framework="SOC 2", reference="CC7.2", description="Monitoring of System Components for Anomalies"),
        ComplianceRef(framework="OWASP", reference="A09:2021", description="Security Logging and Monitoring Failures"),
    ]),
    ("missing", [  # missing hooks
        ComplianceRef(framework="CWE", reference="CWE-778", description="Insufficient Logging"),
        ComplianceRef(framework="SOC 2", reference="CC7.2", description="Monitoring of System Components for Anomalies"),
    ]),
    ("fail-open", [
        ComplianceRef(framework="CWE", reference="CWE-636", description="Not Failing Securely"),
        ComplianceRef(framework="OWASP", reference="A05:2021", description="Security Misconfiguration"),
    ]),
    ("wildcard git", [
        ComplianceRef(framework="CWE", reference="CWE-269", description="Improper Privilege Management"),
        ComplianceRef(framework="SOC 2", reference="CC6.1", description="Logical and Physical Access Controls"),
    ]),
    ("destructive git", [
        ComplianceRef(framework="CWE", reference="CWE-269", description="Improper Privilege Management"),
        ComplianceRef(framework="SOC 2", reference="CC8.1", description="Changes to Infrastructure and Software"),
    ]),
    ("bypass permissions", [
        ComplianceRef(framework="CWE", reference="CWE-269", description="Improper Privilege Management"),
        ComplianceRef(framework="CWE", reference="CWE-284", description="Improper Access Control"),
        ComplianceRef(framework="SOC 2", reference="CC6.1", description="Logical and Physical Access Controls"),
    ]),
    ("anthropic_base_url", [
        ComplianceRef(framework="CWE", reference="CWE-522", description="Insufficiently Protected Credentials"),
        ComplianceRef(framework="CWE", reference="CWE-200", description="Exposure of Sensitive Information"),
        ComplianceRef(framework="SOC 2", reference="CC6.6", description="Security Measures Against Threats Outside System Boundaries"),
    ]),
    ("overly broad permission", [
        ComplianceRef(framework="CWE", reference="CWE-250", description="Execution with Unnecessary Privileges"),
        ComplianceRef(framework="CWE", reference="CWE-269", description="Improper Privilege Management"),
        ComplianceRef(framework="SOC 2", reference="CC6.1", description="Logical and Physical Access Controls"),
    ]),
    ("credential files not denied", [
        ComplianceRef(framework="CWE", reference="CWE-522", description="Insufficiently Protected Credentials"),
        ComplianceRef(framework="CWE", reference="CWE-200", description="Exposure of Sensitive Information"),
        ComplianceRef(framework="SOC 2", reference="CC6.1", description="Logical and Physical Access Controls"),
    ]),
    ("deny mismatch", [
        ComplianceRef(framework="CWE", reference="CWE-732", description="Incorrect Permission Assignment for Critical Resource"),
        ComplianceRef(framework="OWASP", reference="A01:2021", description="Broken Access Control"),
    ]),
    ("network tools not denied", [
        ComplianceRef(framework="CWE", reference="CWE-918", description="Server-Side Request Forgery"),
        ComplianceRef(framework="SOC 2", reference="CC6.6", description="Security Measures Against Threats Outside System Boundaries"),
    ]),
    ("docker socket", [
        ComplianceRef(framework="CWE", reference="CWE-269", description="Improper Privilege Management"),
        ComplianceRef(framework="CWE", reference="CWE-250", description="Execution with Unnecessary Privileges"),
        ComplianceRef(framework="SOC 2", reference="CC6.1", description="Logical and Physical Access Controls"),
    ]),
    ("unix sockets", [
        ComplianceRef(framework="CWE", reference="CWE-269", description="Improper Privilege Management"),
        ComplianceRef(framework="SOC 2", reference="CC6.1", description="Logical and Physical Access Controls"),
    ]),
    ("shell config", [
        ComplianceRef(framework="CWE", reference="CWE-426", description="Untrusted Search Path"),
        ComplianceRef(framework="CWE", reference="CWE-732", description="Incorrect Permission Assignment for Critical Resource"),
        ComplianceRef(framework="SOC 2", reference="CC6.1", description="Logical and Physical Access Controls"),
    ]),
    ("weaker nested sandbox", [
        ComplianceRef(framework="CWE", reference="CWE-269", description="Improper Privilege Management"),
        ComplianceRef(framework="OWASP", reference="A05:2021", description="Security Misconfiguration"),
    ]),
    ("unsandboxed commands", [
        ComplianceRef(framework="CWE", reference="CWE-269", description="Improper Privilege Management"),
        ComplianceRef(framework="CWE", reference="CWE-284", description="Improper Access Control"),
        ComplianceRef(framework="SOC 2", reference="CC6.1", description="Logical and Physical Access Controls"),
    ]),
    ("supply chain", [
        ComplianceRef(framework="CWE", reference="CWE-494", description="Download of Code Without Integrity Check"),
        ComplianceRef(framework="CWE", reference="CWE-829", description="Inclusion of Functionality from Untrusted Control Sphere"),
        ComplianceRef(framework="OWASP", reference="A08:2021", description="Software and Data Integrity Failures"),
    ]),
    ("all project mcp", [
        ComplianceRef(framework="CWE", reference="CWE-829", description="Inclusion of Functionality from Untrusted Control Sphere"),
        ComplianceRef(framework="CWE", reference="CWE-269", description="Improper Privilege Management"),
        ComplianceRef(framework="OWASP", reference="A08:2021", description="Software and Data Integrity Failures"),
    ]),
    ("weaker network isolation", [
        ComplianceRef(framework="CWE", reference="CWE-918", description="Server-Side Request Forgery"),
        ComplianceRef(framework="SOC 2", reference="CC6.6", description="Security Measures Against Threats Outside System Boundaries"),
    ]),
    ("mcp servers in project", [
        ComplianceRef(framework="CWE", reference="CWE-829", description="Inclusion of Functionality from Untrusted Control Sphere"),
        ComplianceRef(framework="OWASP", reference="A08:2021", description="Software and Data Integrity Failures"),
    ]),
]


def _score_to_grade(score: int) -> str:
    for threshold, grade in GRADE_THRESHOLDS:
        if score >= threshold:
            return grade
    return "F"


def _assign_finding_ids(categories: dict[str, list[Finding]]) -> None:
    """Assign stable IDs (e.g. FS-001, NET-002) to all findings in-place."""
    for cat_name, findings in categories.items():
        prefix = CATEGORY_PREFIXES.get(cat_name, cat_name[:3].upper())
        for i, f in enumerate(findings, 1):
            f.finding_id = f"{prefix}-{i:03d}"


def _assign_compliance(categories: dict[str, list[Finding]]) -> None:
    """Map compliance references to findings based on title keywords."""
    for findings in categories.values():
        for f in findings:
            title_lower = f.title.lower()
            for keyword, refs in COMPLIANCE_MAP:
                if keyword in title_lower:
                    f.compliance = refs
                    break  # first match wins


def compute_diff(current: ScanResult, previous: ScanResult) -> DiffSummary:
    """Compare two scan results and produce a diff summary."""
    current_keys = set()
    current_id_map = {}
    for cat in current.categories.values():
        for f in cat.findings:
            key = (f.category, f.title)
            current_keys.add(key)
            current_id_map[key] = f.finding_id

    previous_keys = set()
    previous_title_map = {}
    for cat in previous.categories.values():
        for f in cat.findings:
            key = (f.category, f.title)
            previous_keys.add(key)
            previous_title_map[key] = f.title

    new_keys = current_keys - previous_keys
    resolved_keys = previous_keys - current_keys
    unchanged = current_keys & previous_keys

    return DiffSummary(
        new_findings=[current_id_map[k] for k in sorted(new_keys)],
        resolved_findings=[previous_title_map[k] for k in sorted(resolved_keys)],
        unchanged_count=len(unchanged),
        previous_score=previous.overall_score,
        previous_grade=previous.overall_grade,
        score_delta=current.overall_score - previous.overall_score,
    )


def _generate_summary(
    graded: dict[str, CategoryResult],
    overall_grade: str,
    overall_score: int,
) -> str:
    """Generate a plain-English executive summary for auditors."""
    total_findings = sum(len(c.findings) for c in graded.values())
    by_sev = {}
    for cat in graded.values():
        for f in cat.findings:
            by_sev[f.severity.name] = by_sev.get(f.severity.name, 0) + 1

    desc = GRADE_DESCRIPTIONS.get(overall_grade, "assessed")
    summary = (
        f"This Claude Code environment received an overall grade of "
        f"{overall_grade} ({overall_score}/100) and is {desc}. "
    )

    if total_findings == 0:
        summary += "No security findings were identified across any category."
        return summary

    summary += f"The scan identified {total_findings} finding(s): "
    parts = []
    for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]:
        count = by_sev.get(sev, 0)
        if count > 0:
            parts.append(f"{count} {sev}")
    summary += ", ".join(parts) + ". "

    # Note weakest categories
    weak = sorted(graded.items(), key=lambda x: x[1].score)
    if weak[0][1].score < 90:
        weakest = [f"{name} ({cr.grade})" for name, cr in weak if cr.score < 90]
        summary += f"Categories requiring attention: {', '.join(weakest)}. "

    summary += "See detailed findings below for specific remediation steps."
    return summary


def grade_category(findings: list[Finding]) -> CategoryResult:
    deduction = sum(SEVERITY_DEDUCTIONS[f.severity] for f in findings)
    score = max(0, 100 - deduction)
    return CategoryResult(findings=findings, score=score, grade=_score_to_grade(score))


def grade_overall(
    categories: dict[str, list[Finding]],
    paths_scanned: list[str],
) -> ScanResult:
    _assign_finding_ids(categories)
    _assign_compliance(categories)

    graded = {}
    for name, findings in categories.items():
        graded[name] = grade_category(findings)

    total = sum(
        graded[cat].score * CATEGORY_WEIGHTS.get(cat, 0.25)
        for cat in graded
    )
    overall_score = round(total)
    overall_grade = _score_to_grade(overall_score)

    return ScanResult(
        categories=graded,
        overall_score=overall_score,
        overall_grade=overall_grade,
        overall_summary=_generate_summary(graded, overall_grade, overall_score),
        paths_scanned=paths_scanned,
    )

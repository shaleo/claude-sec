import re
from enum import IntEnum
from datetime import datetime, timezone

from pydantic import BaseModel, Field, computed_field

# OWASP Top 10 2021 reference → URL slug mapping
_OWASP_SLUGS = {
    "A01:2021": "A01_2021-Broken_Access_Control",
    "A02:2021": "A02_2021-Cryptographic_Failures",
    "A03:2021": "A03_2021-Injection",
    "A04:2021": "A04_2021-Insecure_Design",
    "A05:2021": "A05_2021-Security_Misconfiguration",
    "A06:2021": "A06_2021-Vulnerable_and_Outdated_Components",
    "A07:2021": "A07_2021-Identification_and_Authentication_Failures",
    "A08:2021": "A08_2021-Software_and_Data_Integrity_Failures",
    "A09:2021": "A09_2021-Security_Logging_and_Monitoring_Failures",
    "A10:2021": "A10_2021-Server-Side_Request_Forgery_(SSRF)",
}


class Severity(IntEnum):
    INFO = 0
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4


class ComplianceRef(BaseModel):
    framework: str  # e.g. "CWE", "SOC 2", "OWASP"
    reference: str  # e.g. "CWE-732", "CC6.1"
    description: str  # e.g. "Incorrect Permission Assignment"

    @computed_field  # type: ignore[prop-decorator]
    @property
    def url(self) -> str:
        """Derive a reference URL from framework and reference ID."""
        if self.framework == "CWE":
            m = re.match(r"CWE-(\d+)", self.reference)
            if m:
                return f"https://cwe.mitre.org/data/definitions/{m.group(1)}.html"
        elif self.framework == "OWASP":
            slug = _OWASP_SLUGS.get(self.reference)
            if slug:
                return f"https://owasp.org/Top10/{slug}/"
        elif self.framework == "SOC 2":
            q = f"{self.reference} {self.description}".replace(" ", "+")
            return f"https://www.google.com/search?q=SOC+2+{q}"
        return ""


class Finding(BaseModel):
    finding_id: str = ""
    severity: Severity
    category: str
    title: str
    description: str
    risk: str
    fix: str
    verification: str
    compliance: list[ComplianceRef] = Field(default_factory=list)
    assigned_to: str = ""
    target_date: str = ""
    status: str = "Open"


class Environment(BaseModel):
    hostname: str = ""
    os_version: str = ""
    username: str = ""
    python_version: str = ""
    claude_sec_version: str = ""
    project_dir: str = ""


class CategoryResult(BaseModel):
    findings: list[Finding]
    score: int
    grade: str


class DiffSummary(BaseModel):
    new_findings: list[str] = Field(default_factory=list)  # finding_ids
    resolved_findings: list[str] = Field(default_factory=list)  # titles from previous
    unchanged_count: int = 0
    previous_score: int | None = None
    previous_grade: str = ""
    score_delta: int = 0


class ScanResult(BaseModel):
    categories: dict[str, CategoryResult]
    overall_score: int
    overall_grade: str
    overall_summary: str = ""
    environment: Environment = Field(default_factory=Environment)
    paths_scanned: list[str]
    diff: DiffSummary | None = None
    timestamp: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

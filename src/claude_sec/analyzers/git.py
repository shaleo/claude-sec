import re

from claude_sec.models import Finding, Severity

CATEGORY = "git"

DESTRUCTIVE_PATTERNS = [
    ("push --force", "Force push can overwrite remote history"),
    ("push -f", "Force push can overwrite remote history"),
    ("reset --hard", "Hard reset discards uncommitted changes"),
    ("clean -f", "Clean -f permanently deletes untracked files"),
    ("branch -D", "Force-deletes branch without merge check"),
    ("checkout -- .", "Discards all uncommitted changes"),
]


def _collect_permissions(config: dict) -> list[str]:
    """Collect all permission allow lists across settings layers."""
    perms = []
    for layer in ["user", "project", "local"]:
        settings = config["settings"].get(layer, {})
        perms.extend(settings.get("permissions", {}).get("allow", []))
    return perms


def analyze_git(config: dict) -> list[Finding]:
    findings = []
    perms = _collect_permissions(config)

    git_perms = [p for p in perms if "git" in p.lower()]

    if not git_perms:
        findings.append(Finding(
            severity=Severity.INFO,
            category=CATEGORY,
            title="No git permissions configured",
            description="No explicit git command permissions found in allow lists.",
            risk="Git operations may require manual approval each time.",
            fix="Add specific safe git commands to permissions.allow if needed",
            verification="Review permissions.allow for git entries",
        ))
        return findings

    # Check for wildcard git access
    for perm in git_perms:
        if re.search(r"git[:\s]*\*", perm) or perm == "Bash(git)":
            findings.append(Finding(
                severity=Severity.HIGH,
                category=CATEGORY,
                title="Wildcard git permission",
                description=f'Permission "{perm}" grants access to all git commands including destructive ones.',
                risk="Claude Code can run git push --force, git reset --hard, and other destructive git operations.",
                fix='Replace with specific commands: "Bash(git status)", "Bash(git diff)", "Bash(git log)"',
                verification="Verify no wildcard git permissions in allow list",
            ))

    # Check for destructive git commands
    for perm in git_perms:
        for pattern, desc in DESTRUCTIVE_PATTERNS:
            if pattern in perm:
                findings.append(Finding(
                    severity=Severity.HIGH,
                    category=CATEGORY,
                    title=f"Destructive git command allowed",
                    description=f'Permission "{perm}" allows a destructive operation. {desc}.',
                    risk="Data loss or repository corruption from destructive git operations.",
                    fix=f'Remove "{perm}" from permissions.allow',
                    verification=f'Verify "{pattern}" is not in any allow list',
                ))

    return findings

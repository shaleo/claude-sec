from claude_sec.analyzers.git import analyze_git
from claude_sec.models import Severity


def _config_with_permissions(allow_list):
    return {
        "settings": {
            "user": {"permissions": {"allow": allow_list}},
            "project": {},
            "local": {},
        },
        "mcp_servers": {},
        "hooks": {},
        "paths_scanned": [],
        "project_dir": "/tmp/test",
    }


def test_git_wildcard():
    config = _config_with_permissions(["Bash(git:*)"])
    findings = analyze_git(config)
    high = [f for f in findings if f.severity >= Severity.HIGH]
    assert any("wildcard" in f.title.lower() or "git:*" in f.description.lower() for f in high)


def test_destructive_git_commands():
    config = _config_with_permissions(["Bash(git push --force)", "Bash(git reset --hard)"])
    findings = analyze_git(config)
    assert any("destructive" in f.title.lower() or "force" in f.description.lower() for f in findings)


def test_safe_git_commands():
    config = _config_with_permissions(["Bash(git status)", "Bash(git diff)", "Bash(git log)"])
    findings = analyze_git(config)
    high = [f for f in findings if f.severity >= Severity.HIGH and "git" in f.category]
    assert len(high) == 0


def test_no_git_permissions():
    config = _config_with_permissions([])
    findings = analyze_git(config)
    # Should note no git permissions found (INFO level)
    assert any("git" in f.title.lower() for f in findings)

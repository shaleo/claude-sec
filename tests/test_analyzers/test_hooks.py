from claude_sec.analyzers.hooks import analyze_hooks
from claude_sec.models import Severity


def _config_with_hooks(hooks, project_settings=None):
    return {
        "settings": {"user": {}, "project": project_settings or {}, "local": {}},
        "mcp_servers": {},
        "hooks": hooks,
        "paths_scanned": [],
        "project_dir": "/tmp/test",
    }


def test_no_hooks(empty_config):
    findings = analyze_hooks(empty_config)
    critical = [f for f in findings if f.severity == Severity.CRITICAL]
    assert any("no hooks" in f.title.lower() for f in critical)


def test_has_pretooluse_hook():
    config = _config_with_hooks({
        "PreToolUse": [
            {"matcher": "Bash", "hooks": [{"type": "command", "command": "validate.sh"}]}
        ]
    })
    findings = analyze_hooks(config)
    missing_pre = [f for f in findings if "pretooluse" in f.title.lower() and "missing" in f.title.lower()]
    assert len(missing_pre) == 0


def test_missing_pretooluse():
    config = _config_with_hooks({
        "PostToolUse": [
            {"matcher": "Bash", "hooks": [{"type": "command", "command": "log.sh"}]}
        ]
    })
    findings = analyze_hooks(config)
    assert any("pretooluse" in f.title.lower() for f in findings)


def test_fail_open_hook():
    config = _config_with_hooks({
        "PreToolUse": [
            {
                "matcher": "Bash",
                "hooks": [{"type": "command", "command": "validate.sh || exit 0"}]
            }
        ]
    })
    findings = analyze_hooks(config)
    fail_open = [f for f in findings if "fail" in f.title.lower() and "open" in f.title.lower()]
    assert len(fail_open) > 0


def test_fail_open_bare_except():
    config = _config_with_hooks({
        "PreToolUse": [
            {
                "matcher": "Bash",
                "hooks": [{"type": "command", "command": "python -c 'try: check()\nexcept: pass'"}]
            }
        ]
    })
    findings = analyze_hooks(config)
    fail_open = [f for f in findings if "fail" in f.title.lower()]
    assert len(fail_open) > 0


def test_key_events_covered():
    config = _config_with_hooks({
        "PreToolUse": [{"matcher": "*", "hooks": [{"type": "command", "command": "check.sh"}]}],
        "PostToolUse": [{"matcher": "*", "hooks": [{"type": "command", "command": "log.sh"}]}],
        "SessionStart": [{"hooks": [{"type": "command", "command": "init.sh"}]}],
    })
    findings = analyze_hooks(config)
    missing = [f for f in findings if "missing" in f.title.lower() and f.severity >= Severity.HIGH]
    assert len(missing) == 0


def test_hooks_in_project_settings():
    """Hooks defined in project settings are a supply chain risk (CVE-2025-59536)."""
    config = _config_with_hooks(
        hooks={"PreToolUse": [{"matcher": "Bash", "hooks": [{"type": "command", "command": "check.sh"}]}]},
        project_settings={
            "hooks": {
                "SessionStart": [{"hooks": [{"type": "command", "command": "evil.sh"}]}]
            }
        },
    )
    findings = analyze_hooks(config)
    supply_chain = [f for f in findings if "supply chain" in f.title.lower() or "project settings" in f.title.lower()]
    assert len(supply_chain) > 0
    assert supply_chain[0].severity >= Severity.HIGH
